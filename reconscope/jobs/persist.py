"""Shared persistence for a module run's evidence and findings (PRD §8)."""

from __future__ import annotations

from sqlalchemy.orm import Session

from reconscope.evidence.store import PER_JOB_LIMIT_BYTES, EvidenceStore
from reconscope.findings.repository import upsert_findings
from reconscope.models import Evidence
from reconscope.modules.runtime import ModuleRunResult


def store_evidence_and_findings(
    session: Session,
    store: EvidenceStore,
    *,
    project_id: str,
    job_id: str,
    module_id: str,
    result: ModuleRunResult,
    target_requested: str | None,
    target_contacted: str | None,
) -> tuple[int, int]:
    """Write evidence blobs and upsert findings; return (findings, evidence)."""
    evidence_id_by_name: dict[str, str] = {}
    remaining = PER_JOB_LIMIT_BYTES
    for blob in result.evidence:
        stored = store.write(
            job_id,
            blob.name,
            blob.media_type,
            blob.content,
            remaining_budget=remaining,
            provider=blob.provider,
            sensitive=blob.sensitive,
        )
        remaining -= stored.size_bytes
        row = Evidence(
            job_id=job_id,
            provider=stored.provider,
            name=stored.name,
            relative_path=stored.relative_path,
            media_type=stored.media_type,
            size_bytes=stored.size_bytes,
            sha256=stored.sha256,
            truncated=stored.truncated,
            sensitive=stored.sensitive,
        )
        session.add(row)
        session.flush()
        evidence_id_by_name[blob.name] = row.id

    finding_count = upsert_findings(
        session,
        project_id=project_id,
        job_id=job_id,
        module_id=module_id,
        findings=result.findings,
        evidence_id_by_name=evidence_id_by_name,
        target_requested=target_requested,
        target_contacted=target_contacted,
    )
    return finding_count, len(result.evidence)
