"""Tests for recommendations, argument explanation, and report generation."""

import hashlib
import io
import zipfile

import httpx

from reconscope.jobs.runner import PassiveJobRunner
from reconscope.modules.gate import ProjectAuthorization
from reconscope.modules.passive import CertTransparency
from reconscope.reporting.argv_explain import explain_argv
from reconscope.reporting.builder import build_markdown_report, build_report_zip
from reconscope.reporting.recommendations import recommend_next_steps
from reconscope.scope.canonical import TargetType
from tests.conftest import make_services

_NO_AUTHZ = ProjectAuthorization.build(False, [])


class TestRecommendations:
    def test_empty_starts_with_rdap(self):
        recs = recommend_next_steps([])
        assert recs[0].module_id == "passive.rdap"

    def test_open_443_recommends_tls_and_https(self):
        findings = [{"finding_type": "tcp_port", "value": "443/tcp",
                     "data": {"state": "open"}}]
        recs = recommend_next_steps(findings)
        modules = {r.module_id for r in recs}
        assert "active.tls_review" in modules
        assert "active.http_overview" in modules

    def test_candidate_hostname_recommends_scope(self):
        findings = [{"finding_type": "candidate_hostname", "value": "a.example.com",
                     "data": {}}]
        recs = recommend_next_steps(findings)
        assert any(r.action == "add_scope" for r in recs)

    def test_open_ports_without_services_recommends_detection(self):
        findings = [{"finding_type": "tcp_port", "value": "22/tcp",
                     "data": {"state": "open"}}]
        recs = recommend_next_steps(findings)
        det = [r for r in recs if r.module_id == "active.service_detection"]
        assert det and det[0].config["ports"] == "22"


class TestArgvExplain:
    def test_annotates_nmap(self):
        argv = ["nmap", "-sT", "-Pn", "--max-rate", "100", "--top-ports", "100",
                "-oX", "-", "203.0.113.10"]
        ann = explain_argv(argv)
        assert ann[0].kind == "executable"
        target = [a for a in ann if a.kind == "target"][0]
        assert target.token == "203.0.113.10" and target.user_derived is True
        topports_val = [a for a in ann if a.kind == "value"
                        and a.token == "100" and a.user_derived]
        assert topports_val  # --top-ports value is user-derived
        oxval = [a for a in ann if a.token == "-" and a.kind == "value"][0]
        assert oxval.user_derived is False


def _populate(db_session, project, evidence_store):
    def handler(request):
        return httpx.Response(
            200,
            json=[{"name_value": "www.example.com", "common_name": "example.com"}],
        )

    services = make_services(handler=handler)
    PassiveJobRunner(db_session, evidence_store, services).run(
        project_id=project.id, module=CertTransparency(), target="example.com",
        target_type=TargetType.HOSTNAME, authz=_NO_AUTHZ,
    )


class TestReport:
    def test_markdown_is_traceable_and_labeled(self, db_session, project, evidence_store):
        _populate(db_session, project, evidence_store)
        md = build_markdown_report(db_session, project.id)
        # A finding appears with its source and its evidence file (traceable).
        assert "www.example.com" in md
        assert "crt.sh" in md
        assert "crtsh.json" in md
        # Interpretation and Guidance are explicitly labeled sections.
        assert "Interpretation (derived, labeled)" in md
        assert "Defensive guidance" in md
        assert "Evidence manifest" in md

    def test_zip_manifest_hashes_match_files(self, db_session, project, evidence_store):
        _populate(db_session, project, evidence_store)
        data, manifest_hash = build_report_zip(db_session, project.id, evidence_store)
        assert len(manifest_hash) == 64

        with zipfile.ZipFile(io.BytesIO(data)) as zf:
            names = zf.namelist()
            assert "report.md" in names and "manifest.json" in names
            import json

            manifest = json.loads(zf.read("manifest.json"))
            assert manifest["files"], "expected at least one evidence file"
            for entry in manifest["files"]:
                raw = zf.read(entry["path"])
                assert hashlib.sha256(raw).hexdigest() == entry["sha256"]
