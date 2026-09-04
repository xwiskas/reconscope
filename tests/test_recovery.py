"""Restart-recovery tests (PRD §9.2, §14.3, §16.2)."""

from sqlalchemy import select

from reconscope.jobs.recovery import recover_interrupted_jobs
from reconscope.models import Evidence, Job


def test_running_job_without_evidence_becomes_interrupted(db_session, project):
    job = Job(
        project_id=project.id, module_id="active.tcp_scan", module_version="0.1.0",
        target="example.com", target_type="hostname", status="running",
    )
    db_session.add(job)
    db_session.flush()

    changed = recover_interrupted_jobs(db_session)
    assert changed == 1
    refreshed = db_session.get(Job, job.id)
    assert refreshed.status == "interrupted"
    assert refreshed.error_code == "app_restart"


def test_running_job_with_evidence_becomes_partial(db_session, project):
    job = Job(
        project_id=project.id, module_id="active.tcp_scan", module_version="0.1.0",
        target="example.com", target_type="hostname", status="running",
    )
    db_session.add(job)
    db_session.flush()
    db_session.add(
        Evidence(
            job_id=job.id, name="nmap.xml", relative_path="e/nmap.xml",
            media_type="application/xml", size_bytes=10, sha256="0" * 64,
        )
    )
    db_session.flush()

    recover_interrupted_jobs(db_session)
    assert db_session.get(Job, job.id).status == "partial"


def test_finished_jobs_untouched(db_session, project):
    job = Job(
        project_id=project.id, module_id="active.tcp_scan", module_version="0.1.0",
        target="example.com", target_type="hostname", status="succeeded",
    )
    db_session.add(job)
    db_session.flush()

    changed = recover_interrupted_jobs(db_session)
    assert changed == 0
    assert db_session.get(Job, job.id).status == "succeeded"
    assert db_session.scalars(select(Job)).all()  # still present
