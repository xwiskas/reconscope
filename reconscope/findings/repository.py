"""Persistence for normalized findings (PRD §8.1).

Re-running a module updates a finding's ``last_seen`` without destroying earlier
evidence: findings are upserted by ``(project_id, finding_type, value)``.
"""

from __future__ import annotations

import datetime as dt

from sqlalchemy import select
from sqlalchemy.orm import Session

from reconscope.findings.types import NormalizedFinding
from reconscope.models import Finding


def _now() -> dt.datetime:
    # Naive UTC to match the storage convention (see models._now).
    return dt.datetime.now(dt.UTC).replace(tzinfo=None)


def upsert_findings(
    session: Session,
    *,
    project_id: str,
    job_id: str,
    module_id: str,
    findings: list[NormalizedFinding],
    evidence_id_by_name: dict[str, str],
    target_requested: str | None = None,
    target_contacted: str | None = None,
) -> int:
    """Insert or update findings; return the number processed."""
    now = _now()
    for f in findings:
        evidence_id = (
            evidence_id_by_name.get(f.evidence_name) if f.evidence_name else None
        )
        existing = session.scalars(
            select(Finding).where(
                Finding.project_id == project_id,
                Finding.finding_type == f.finding_type,
                Finding.value == f.value,
            )
        ).one_or_none()

        if existing is None:
            session.add(
                Finding(
                    project_id=project_id,
                    job_id=job_id,
                    evidence_id=evidence_id,
                    module_id=module_id,
                    finding_type=f.finding_type,
                    value=f.value,
                    data=f.data,
                    confidence=f.confidence.value,
                    source=f.source,
                    target_requested=target_requested,
                    target_contacted=target_contacted,
                    first_seen=now,
                    last_seen=now,
                )
            )
        else:
            existing.last_seen = now
            existing.data = f.data
            existing.source = f.source
            existing.job_id = job_id
            if evidence_id:
                existing.evidence_id = evidence_id
    return len(findings)
