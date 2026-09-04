"""Passive job-runner tests, including the M1 exit criterion."""

import httpx
from sqlalchemy import select

from reconscope.jobs.runner import PassiveJobRunner
from reconscope.models import ActivityLog, Evidence, Finding, Job
from reconscope.modules.echo import ConnectivityEcho
from reconscope.modules.gate import ProjectAuthorization
from reconscope.modules.passive import CertTransparency, DnsRecords, Rdap
from reconscope.providers.dns import DnsAnswer, DnsStatus
from reconscope.scope.canonical import TargetType
from tests.conftest import FakeResolver, make_services

_NO_AUTHZ = ProjectAuthorization.build(False, [])


def _runner(db_session, evidence_store, services):
    return PassiveJobRunner(db_session, evidence_store, services)


def test_dns_run_persists_findings_and_evidence(db_session, project, evidence_store):
    resolver = FakeResolver(
        answers={
            ("example.com", "A"): DnsAnswer(
                "example.com", "A", DnsStatus.OK, ("192.0.2.1",), 300, "fake-resolver"
            )
        }
    )
    services = make_services(resolver=resolver)
    outcome = _runner(db_session, evidence_store, services).run(
        project_id=project.id,
        module=DnsRecords(),
        target="example.com",
        target_type=TargetType.HOSTNAME,
        authz=_NO_AUTHZ,
    )
    assert outcome.status == "succeeded"
    assert outcome.finding_count >= 1

    findings = db_session.scalars(select(Finding)).all()
    assert any(f.value == "192.0.2.1" for f in findings)

    ev = db_session.scalars(select(Evidence)).all()
    assert len(ev) == 1
    assert len(ev[0].sha256) == 64
    assert ev[0].provider == "fake-resolver"
    # The evidence file physically exists.
    assert (evidence_store._root / ev[0].relative_path).exists()


def test_one_provider_failure_preserves_other_evidence(db_session, project, evidence_store):
    """M1 exit criterion: passive journey works when one provider fails and
    preserves source-specific evidence."""

    def handler(request):
        if "crt.sh" in request.url.host:
            return httpx.Response(
                200,
                json=[{"name_value": "www.example.com", "common_name": "example.com"}],
            )
        if "rdap.org" in request.url.host:
            return httpx.Response(503, text="registry down")
        return httpx.Response(404)

    services = make_services(handler=handler)
    runner = _runner(db_session, evidence_store, services)

    ct = runner.run(
        project_id=project.id, module=CertTransparency(), target="example.com",
        target_type=TargetType.HOSTNAME, authz=_NO_AUTHZ,
    )
    rdap = runner.run(
        project_id=project.id, module=Rdap(), target="example.com",
        target_type=TargetType.HOSTNAME, authz=_NO_AUTHZ,
    )

    # The good provider succeeded with source-specific evidence...
    assert ct.status == "succeeded"
    ct_ev = db_session.scalars(
        select(Evidence).where(Evidence.provider == "crt.sh")
    ).all()
    assert len(ct_ev) == 1

    # ...and the failing provider failed on its own without erasing anything.
    assert rdap.status == "failed"
    assert rdap.error_code == "provider_unavailable"

    findings = db_session.scalars(select(Finding)).all()
    assert any(f.finding_type == "candidate_hostname" for f in findings)

    jobs = {j.module_id: j.status for j in db_session.scalars(select(Job)).all()}
    assert jobs["passive.cert_transparency"] == "succeeded"
    assert jobs["passive.rdap"] == "failed"


def test_rerun_updates_last_seen_without_duplicating(db_session, project, evidence_store):
    resolver = FakeResolver(
        answers={
            ("example.com", "A"): DnsAnswer(
                "example.com", "A", DnsStatus.OK, ("192.0.2.1",), 300, "fake-resolver"
            )
        }
    )
    services = make_services(resolver=resolver)
    runner = _runner(db_session, evidence_store, services)
    kwargs = dict(
        project_id=project.id, module=DnsRecords(), target="example.com",
        target_type=TargetType.HOSTNAME, authz=_NO_AUTHZ,
    )
    runner.run(**kwargs)
    first = db_session.scalars(
        select(Finding).where(Finding.value == "192.0.2.1")
    ).one()
    first_seen = first.first_seen

    runner.run(**kwargs)
    rows = db_session.scalars(
        select(Finding).where(Finding.value == "192.0.2.1")
    ).all()
    assert len(rows) == 1  # not duplicated
    assert rows[0].first_seen == first_seen
    assert rows[0].last_seen >= first_seen


def test_active_module_blocked_by_runner(db_session, project, evidence_store):
    services = make_services()
    outcome = _runner(db_session, evidence_store, services).run(
        project_id=project.id,
        module=ConnectivityEcho(),  # active, and no attestation
        target="example.com",
        target_type=TargetType.HOSTNAME,
        authz=_NO_AUTHZ,
    )
    assert outcome.status == "failed"
    assert outcome.error_code == "authorization_missing"
    assert db_session.scalars(select(Evidence)).all() == []
    logs = db_session.scalars(select(ActivityLog)).all()
    assert any(log.action == "module.blocked" for log in logs)
