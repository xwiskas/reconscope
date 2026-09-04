"""API smoke tests for the M0 safety-spine endpoints and security headers."""

from fastapi.testclient import TestClient

from reconscope.main import create_app

client = TestClient(create_app())


def test_health():
    r = client.get("/api/v1/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_security_headers_present():
    r = client.get("/api/v1/health")
    assert "Content-Security-Policy" in r.headers
    assert r.headers["X-Frame-Options"] == "DENY"
    assert r.headers["X-Content-Type-Options"] == "nosniff"


def test_glossary_non_empty():
    r = client.get("/api/v1/glossary")
    assert r.status_code == 200
    slugs = {t["slug"] for t in r.json()}
    assert {"active-recon", "passive-recon", "scope"} <= slugs


def test_scope_preview_wildcard():
    r = client.post("/api/v1/scope/preview", json={"value": "*.Example.com"})
    body = r.json()
    assert body["ok"] is True
    assert body["type"] == "wildcard_domain"
    assert body["canonical"] == "example.com"


def test_scope_preview_rejects_bad_entry():
    r = client.post("/api/v1/scope/preview", json={"value": "http://x/y"})
    assert r.json()["ok"] is False


def test_scope_evaluate_denies_subdomain_of_exact_entry():
    r = client.post(
        "/api/v1/scope/evaluate",
        json={
            "target": "sub.example.com",
            "target_type": "hostname",
            "entries": ["example.com"],
        },
    )
    assert r.json()["allowed"] is False


def test_scope_evaluate_allows_in_scope():
    r = client.post(
        "/api/v1/scope/evaluate",
        json={
            "target": "example.com",
            "target_type": "hostname",
            "entries": ["example.com"],
        },
    )
    body = r.json()
    assert body["allowed"] is True
    assert body["matched_entry"] == "example.com"


def test_gate_check_blocks_without_attestation():
    r = client.post(
        "/api/v1/gate/check",
        json={
            "target": "example.com",
            "target_type": "hostname",
            "entries": ["example.com"],
            "attestation_current": False,
        },
    )
    body = r.json()
    assert body["allowed"] is False
    assert body["reason"] == "authorization_missing"


def test_gate_check_allows_when_attested_and_in_scope():
    r = client.post(
        "/api/v1/gate/check",
        json={
            "target": "example.com",
            "target_type": "hostname",
            "entries": ["example.com"],
            "attestation_current": True,
        },
    )
    assert r.json()["allowed"] is True
