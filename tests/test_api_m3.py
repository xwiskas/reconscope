"""End-to-end API tests for M3: recommendations, worksheet, reports, command."""

import io
import zipfile

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from reconscope.evidence.store import EvidenceStore
from reconscope.main import create_app
from reconscope.models import Base
from reconscope.providers.dns import DnsAnswer, DnsStatus
from tests.conftest import (
    SAMPLE_NMAP_XML,
    FakeProcessRunner,
    FakeResolver,
    available_nmap,
    make_services,
)


@pytest.fixture
def client(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'api.db'}", future=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)

    def handler(request):
        if "crt.sh" in request.url.host:
            return httpx.Response(
                200,
                json=[{"name_value": "www.example.com", "common_name": "example.com"}],
            )
        return httpx.Response(404)

    resolver = FakeResolver(
        answers={
            ("example.com", "A"): DnsAnswer(
                "example.com", "A", DnsStatus.OK, ("203.0.113.10",), 300, "fake"
            )
        }
    )
    services = make_services(
        handler=handler, resolver=resolver,
        process_runner=FakeProcessRunner(stdout=SAMPLE_NMAP_XML), nmap=available_nmap(),
    )
    app = create_app(
        session_factory=factory, services=services,
        evidence_store=EvidenceStore(tmp_path / "evidence"),
    )
    return TestClient(app)


def _project(client):
    return client.post("/api/v1/projects", json={"name": "M3"}).json()["id"]


def test_recommendations_after_ct(client):
    pid = _project(client)
    client.post(
        f"/api/v1/projects/{pid}/jobs",
        json={"module_id": "passive.cert_transparency", "target": "example.com",
              "target_type": "hostname"},
    )
    recs = client.get(f"/api/v1/projects/{pid}/recommendations").json()
    assert any(r["action"] == "add_scope" for r in recs)


def test_worksheet_roundtrip(client):
    pid = _project(client)
    client.put(
        f"/api/v1/projects/{pid}/worksheet",
        json={"hypothesis": "the site exposes a dev host", "conclusion": "TBD"},
    )
    w = client.get(f"/api/v1/projects/{pid}/worksheet").json()
    assert w["hypothesis"] == "the site exposes a dev host"
    assert w["conclusion"] == "TBD"


def test_report_markdown(client):
    pid = _project(client)
    client.post(
        f"/api/v1/projects/{pid}/jobs",
        json={"module_id": "passive.cert_transparency", "target": "example.com",
              "target_type": "hostname"},
    )
    r = client.get(f"/api/v1/projects/{pid}/report.md")
    assert r.status_code == 200
    assert "text/markdown" in r.headers["content-type"]
    assert "www.example.com" in r.text


def test_report_zip_downloads_with_manifest(client):
    pid = _project(client)
    client.post(
        f"/api/v1/projects/{pid}/jobs",
        json={"module_id": "passive.cert_transparency", "target": "example.com",
              "target_type": "hostname"},
    )
    r = client.get(f"/api/v1/projects/{pid}/report.zip")
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/zip"
    with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
        assert "report.md" in zf.namelist()
        assert "manifest.json" in zf.namelist()


def test_explain_every_argument(client):
    pid = _project(client)
    client.post(f"/api/v1/projects/{pid}/scope", json={"value": "example.com"})
    client.post(f"/api/v1/projects/{pid}/attestation")
    client.post(
        f"/api/v1/projects/{pid}/active-jobs",
        json={"module_id": "active.tcp_scan", "target": "example.com",
              "target_type": "hostname", "config": {"preset": "quick"}},
    )
    jobs = client.get(f"/api/v1/projects/{pid}/jobs").json()
    scan = next(j for j in jobs if j["module_id"] == "active.tcp_scan")
    cmd = client.get(f"/api/v1/projects/{pid}/jobs/{scan['id']}/command").json()
    assert cmd["argv"][0] == "nmap"
    assert any(e["kind"] == "target" and e["user_derived"] for e in cmd["explanation"])
