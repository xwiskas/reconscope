"""End-to-end API tests for active jobs and capabilities (hermetic)."""

import httpx
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from reconscope.evidence.store import EvidenceStore
from reconscope.main import create_app
from reconscope.models import Base
from reconscope.providers.dns import DnsAnswer, DnsStatus
from tests.conftest import SAMPLE_NMAP_XML, FakeProcessRunner, FakeResolver, available_nmap


@pytest.fixture
def client(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'api.db'}", future=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)

    resolver = FakeResolver(
        answers={
            ("example.com", "A"): DnsAnswer(
                "example.com", "A", DnsStatus.OK, ("203.0.113.10",), 300, "fake"
            )
        }
    )

    from tests.conftest import make_services

    services = make_services(
        handler=lambda r: httpx.Response(404),
        resolver=resolver,
        process_runner=FakeProcessRunner(stdout=SAMPLE_NMAP_XML),
        nmap=available_nmap(),
    )
    app = create_app(
        session_factory=factory,
        services=services,
        evidence_store=EvidenceStore(tmp_path / "evidence"),
    )
    return TestClient(app)


def _project_with_scope(client, attest=True):
    pid = client.post("/api/v1/projects", json={"name": "Active"}).json()["id"]
    client.post(f"/api/v1/projects/{pid}/scope", json={"value": "example.com"})
    if attest:
        client.post(f"/api/v1/projects/{pid}/attestation")
    return pid


def test_capabilities(client):
    r = client.get("/api/v1/capabilities").json()
    assert r["nmap"]["available"] is True
    assert r["nmap"]["version"] == "7.94"


def test_active_job_rejects_out_of_scope(client):
    pid = _project_with_scope(client, attest=True)
    r = client.post(
        f"/api/v1/projects/{pid}/active-jobs",
        json={
            "module_id": "active.tcp_scan",
            "target": "not-in-scope.test",
            "target_type": "hostname",
            "config": {"preset": "quick"},
        },
    ).json()
    assert r["status"] == "failed"
    assert r["error_code"] == "target_out_of_scope"


def test_active_job_rejects_without_attestation(client):
    pid = _project_with_scope(client, attest=False)
    r = client.post(
        f"/api/v1/projects/{pid}/active-jobs",
        json={
            "module_id": "active.tcp_scan",
            "target": "example.com",
            "target_type": "hostname",
            "config": {"preset": "quick"},
        },
    ).json()
    assert r["status"] == "failed"
    assert r["error_code"] == "authorization_missing"


def test_active_job_happy_path(client):
    pid = _project_with_scope(client, attest=True)
    r = client.post(
        f"/api/v1/projects/{pid}/active-jobs",
        json={
            "module_id": "active.tcp_scan",
            "target": "example.com",
            "target_type": "hostname",
            "config": {"preset": "quick"},
        },
    ).json()
    assert r["status"] == "succeeded"
    assert r["pinned_ips"] == ["203.0.113.10"]
    findings = client.get(
        f"/api/v1/projects/{pid}/findings", params={"finding_type": "tcp_port"}
    ).json()
    assert any(f["value"] == "22/tcp" for f in findings)


def test_start_and_stream_events_to_completion(client):
    pid = _project_with_scope(client, attest=True)
    start = client.post(
        f"/api/v1/projects/{pid}/active-jobs/start",
        json={"module_id": "active.tcp_scan", "target": "example.com",
              "target_type": "hostname", "config": {"preset": "quick"}},
    ).json()
    job_id = start["job_id"]
    # The SSE stream replays retained events and ends at the terminal one.
    r = client.get(f"/api/v1/projects/{pid}/active-jobs/{job_id}/events")
    assert r.status_code == 200
    assert "text/event-stream" in r.headers["content-type"]
    assert '"type": "running"' in r.text
    assert '"status": "succeeded"' in r.text


def test_cancel_unknown_job_404(client):
    pid = _project_with_scope(client, attest=True)
    r = client.post(f"/api/v1/projects/{pid}/active-jobs/deadbeef/cancel")
    assert r.status_code == 404


def test_passive_module_rejected_at_active_endpoint(client):
    pid = _project_with_scope(client, attest=True)
    r = client.post(
        f"/api/v1/projects/{pid}/active-jobs",
        json={
            "module_id": "passive.rdap",
            "target": "example.com",
            "target_type": "hostname",
        },
    )
    assert r.status_code == 400
