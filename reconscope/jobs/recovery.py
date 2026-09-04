"""Startup recovery for jobs interrupted by an app restart (PRD §9.2, §14.3).

On startup any job still marked ``queued`` or ``running`` is reconciled to a
terminal state: ``partial`` if it already produced evidence, otherwise
``interrupted``. A restart never marks an unfinished job successful.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.orm import Session

from reconscope.models import Evidence, Job


def recover_interrupted_jobs(session: Session) -> int:
    """Reconcile unfinished jobs. Returns how many were changed."""
    unfinished = session.scalars(
        select(Job).where(Job.status.in_(("queued", "running")))
    ).all()
    now = dt.datetime.now(dt.UTC).replace(tzinfo=None)
    changed = 0
    for job in unfinished:
        has_evidence = (
            session.scalars(
                select(Evidence.id).where(Evidence.job_id == job.id).limit(1)
            ).first()
            is not None
        )
        job.status = "partial" if has_evidence else "interrupted"
        job.error_code = "app_restart"
        if job.finished_at is None:
            job.finished_at = now
        changed += 1
    session.commit()
    return changed
