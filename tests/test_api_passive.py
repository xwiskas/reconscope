"""End-to-end API tests for the passive journey (hermetic: no real network)."""

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from reconscope.main import create_app
from reconscope.models import Base
from tests.conftest import FakeResolver, make_services


@pytest.fixture
def client(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'api.db'}", future=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)

    def handler(request):
        if "crt.sh" in request.url.host:
            return httpx.Response(
                200,
                json=[
                    {"name_value": "www.example.com\n*.example.com",
                     "common_name": "example.com"}
                ],
            )
        return httpx.Response(404)

    resolver = FakeResolver()
    services = make_services(handler=handler, resolver=resolver)

    from reconscope.evidence.store import EvidenceStore

    app = create_app(
        session_factory=factory,
        services=services,
        evidence_store=EvidenceStore(tmp_path / "evidence"),
    )
    return TestClient(app)


def test_module_catalog(client):
    r = client.get("/api/v1/modules")
    assert r.status_code == 200
    ids = {m["module_id"] for m in r.json()}
    assert "passive.cert_transparency" in ids
    # Manifest endpoint returns full explanation fields.
    man = client.get("/api/v1/modules/passive.cert_transparency/manifest").json()
    assert man["interaction"] == "passive"
    assert man["limitations"]


def test_full_passive_journey(client):
    # 1. Create a project.
    pid = client.post("/api/v1/projects", json={"name": "Demo"}).json()["id"]

    # 2. Add a seed.
    seed = client.post(f"/api/v1/projects/{pid}/seeds", json={"value": "example.com"})
    assert seed.status_code == 200
    assert seed.json()["type"] == "domain"

    # 3. Run certificate transparency (mocked provider).
    job = client.post(
        f"/api/v1/projects/{pid}/jobs",
        json={
            "module_id": "passive.cert_transparency",
            "target": "example.com",
            "target_type": "hostname",
        },
    ).json()
    assert job["status"] == "succeeded"
    assert job["finding_count"] >= 1

    # 4. Findings are queryable with provenance.
    findings = client.get(
        f"/api/v1/projects/{pid}/findings",
        params={"finding_type": "candidate_hostname"},
    ).json()
    values = {f["value"] for f in findings}
    assert "www.example.com" in values
    assert all(f["source"] == "crt.sh" for f in findings)

    # 5. Evidence metadata is recorded with a hash.
    ev = client.get(f"/api/v1/projects/{pid}/evidence").json()
    assert ev and len(ev[0]["sha256"]) == 64

    # 6. Activity log captured the run.
    activity = client.get(f"/api/v1/projects/{pid}/activity").json()
    assert any(a["module_id"] == "passive.cert_transparency" for a in activity)


def test_attestation_flow_and_invalidation(client):
    pid = client.post("/api/v1/projects", json={"name": "Auth"}).json()["id"]

    # Attestation requires an enabled scope entry first.
    assert client.post(f"/api/v1/projects/{pid}/attestation").status_code == 400

    client.post(f"/api/v1/projects/{pid}/scope", json={"value": "example.com"})
    assert client.post(f"/api/v1/projects/{pid}/attestation").status_code == 200
    assert client.get(f"/api/v1/projects/{pid}").json()["attestation_current"] is True

    # Expanding scope invalidates the prior attestation (PRD §4.2).
    client.post(f"/api/v1/projects/{pid}/scope", json={"value": "*.example.com"})
    assert client.get(f"/api/v1/projects/{pid}").json()["attestation_current"] is False


def test_duplicate_scope_rejected(client):
    pid = client.post("/api/v1/projects", json={"name": "Dup"}).json()["id"]
    assert client.post(
        f"/api/v1/projects/{pid}/scope", json={"value": "example.com"}
    ).status_code == 200
    assert client.post(
        f"/api/v1/projects/{pid}/scope", json={"value": "EXAMPLE.com."}
    ).status_code == 409  # canonically identical


def test_bad_scope_entry_rejected(client):
    pid = client.post("/api/v1/projects", json={"name": "Bad"}).json()["id"]
    assert client.post(
        f"/api/v1/projects/{pid}/scope", json={"value": "http://x/y"}
    ).status_code == 400
