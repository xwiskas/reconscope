"""Active-runner safety tests (PRD §4.4, §16.2)."""

import httpx
from sqlalchemy import select

from reconscope.jobs.active_runner import ActiveJobRunner
from reconscope.models import Job
from reconscope.modules.active.http_overview import HttpOverview
from reconscope.modules.active.tcp_scan import TcpScan
from reconscope.modules.gate import ProjectAuthorization
from reconscope.providers.dns import DnsAnswer, DnsStatus
from reconscope.scope.canonical import TargetType, canonicalize_scope_entry
from tests.conftest import (
    SAMPLE_NMAP_XML,
    FakeProcessRunner,
    FakeResolver,
    available_nmap,
    make_services,
)


def _entries(*vals):
    return [canonicalize_scope_entry(v) for v in vals]


def _runner(db_session, evidence_store, services):
    return ActiveJobRunner(db_session, evidence_store, services)


def test_out_of_scope_target_blocked_before_running(db_session, project, evidence_store):
    runner = FakeProcessRunner(stdout=SAMPLE_NMAP_XML)
    services = make_services(
        process_runner=runner, nmap=available_nmap(),
        resolver=FakeResolver(),
    )
    entries = _entries("example.com")
    authz = ProjectAuthorization.build(True, entries)
    outcome = _runner(db_session, evidence_store, services).run(
        project_id=project.id, module=TcpScan(), target="evil.test",
        target_type=TargetType.HOSTNAME, authz=authz, enabled_entries=entries,
        config={"preset": "quick"},
    )
    assert outcome.status == "failed"
    assert outcome.error_code == "target_out_of_scope"
    assert runner.calls == []  # nmap never launched


def test_missing_attestation_blocked(db_session, project, evidence_store):
    runner = FakeProcessRunner(stdout=SAMPLE_NMAP_XML)
    services = make_services(
        process_runner=runner, nmap=available_nmap(), resolver=FakeResolver()
    )
    entries = _entries("example.com")
    authz = ProjectAuthorization.build(False, entries)  # not attested
    outcome = _runner(db_session, evidence_store, services).run(
        project_id=project.id, module=TcpScan(), target="example.com",
        target_type=TargetType.HOSTNAME, authz=authz, enabled_entries=entries,
        config={"preset": "quick"},
    )
    assert outcome.status == "failed"
    assert outcome.error_code == "authorization_missing"
    assert runner.calls == []


def test_in_scope_run_pins_and_scans_pinned_ip(db_session, project, evidence_store):
    resolver = FakeResolver(
        answers={
            ("example.com", "A"): DnsAnswer(
                "example.com", "A", DnsStatus.OK, ("203.0.113.10",), 300, "fake"
            )
        }
    )
    runner = FakeProcessRunner(stdout=SAMPLE_NMAP_XML)
    services = make_services(
        process_runner=runner, nmap=available_nmap(), resolver=resolver
    )
    entries = _entries("example.com")
    authz = ProjectAuthorization.build(True, entries)
    outcome = _runner(db_session, evidence_store, services).run(
        project_id=project.id, module=TcpScan(), target="example.com",
        target_type=TargetType.HOSTNAME, authz=authz, enabled_entries=entries,
        config={"preset": "quick"},
    )
    assert outcome.status == "succeeded"
    assert outcome.pinned_ips == ("203.0.113.10",)
    # Nmap scanned the pinned IP, not the hostname (no re-resolution).
    assert runner.calls[0][-1] == "203.0.113.10"


def test_unresolvable_hostname_fails_without_scanning(db_session, project, evidence_store):
    resolver = FakeResolver()  # everything NODATA
    runner = FakeProcessRunner(stdout=SAMPLE_NMAP_XML)
    services = make_services(
        process_runner=runner, nmap=available_nmap(), resolver=resolver
    )
    entries = _entries("example.com")
    authz = ProjectAuthorization.build(True, entries)
    outcome = _runner(db_session, evidence_store, services).run(
        project_id=project.id, module=TcpScan(), target="example.com",
        target_type=TargetType.HOSTNAME, authz=authz, enabled_entries=entries,
        config={"preset": "quick"},
    )
    assert outcome.status == "failed"
    assert outcome.error_code == "resolution_failed"
    assert runner.calls == []


def test_http_out_of_scope_redirect_blocked_via_runner(db_session, project, evidence_store):
    contacted = []

    def handler(request):
        contacted.append(request.url.host)
        if request.url.host == "example.com":
            return httpx.Response(302, headers={"location": "http://evil.test/"})
        return httpx.Response(200, text="SHOULD NOT BE REACHED")

    resolver = FakeResolver(
        answers={
            ("example.com", "A"): DnsAnswer(
                "example.com", "A", DnsStatus.OK, ("203.0.113.10",), 300, "fake"
            )
        }
    )
    services = make_services(handler=handler, resolver=resolver)
    entries = _entries("example.com")
    authz = ProjectAuthorization.build(True, entries)
    outcome = _runner(db_session, evidence_store, services).run(
        project_id=project.id, module=HttpOverview(), target="example.com",
        target_type=TargetType.HOSTNAME, authz=authz, enabled_entries=entries,
        config={"scheme": "http", "port": 80},
    )
    assert "evil.test" not in contacted
    assert outcome.status == "succeeded"
    jobs = db_session.scalars(select(Job)).all()
    assert jobs[0].status == "succeeded"
