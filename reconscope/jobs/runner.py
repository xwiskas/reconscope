"""Passive job runner (PRD §5.4, §8, §14.2).

Ties a module run to its side effects: gate check, evidence persistence,
normalized-finding upserts, job state, and an activity-log entry. A single
module failing (e.g. a provider outage) is recorded as a failed job and does not
raise — the project and its other findings are preserved (M1 exit criterion).
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

from sqlalchemy import select
from sqlalchemy.orm import Session

from reconscope.evidence.store import PER_JOB_LIMIT_BYTES, EvidenceStore
from reconscope.findings.repository import upsert_findings
from reconscope.models import ActivityLog, Evidence, Finding, Job
from reconscope.modules.contract import ModuleContext
from reconscope.modules.gate import ProjectAuthorization, authorize_job
from reconscope.modules.runtime import ModuleRunResult, RunContext
from reconscope.providers.http import ProviderError
from reconscope.providers.services import ProviderServices
from reconscope.scope.canonical import TargetType


def _now() -> dt.datetime:
    # Naive UTC to match the storage convention (see models._now).
    return dt.datetime.now(dt.UTC).replace(tzinfo=None)


@dataclass(frozen=True)
class JobOutcome:
    job_id: str
    module_id: str
    status: str
    summary: str
    provider: str | None
    error_code: str | None
    finding_count: int
    evidence_count: int


class PassiveJobRunner:
    def __init__(
        self,
        session: Session,
        evidence_store: EvidenceStore,
        services: ProviderServices,
    ):
        self._session = session
        self._store = evidence_store
        self._services = services

    def run(
        self,
        *,
        project_id: str,
        module,
        target: str,
        target_type: TargetType,
        authz: ProjectAuthorization,
        config: dict | None = None,
    ) -> JobOutcome:
        config = dict(config or {})
        mod_ctx = ModuleContext(target=target, target_type=target_type, config=config)

        # 1. Gate. Passive modules pass; an active module here would be blocked.
        decision = authorize_job(module, mod_ctx, authz)

        job = Job(
            project_id=project_id,
            module_id=module.module_id,
            module_version=module.module_version,
            target=target,
            target_type=target_type.value,
            status="running",
            started_at=_now(),
        )
        self._session.add(job)
        self._session.flush()  # assign job.id

        if not decision.allowed:
            job.status = "failed"
            job.error_code = decision.reason
            job.finished_at = _now()
            self._log(project_id, job, decision.reason, None, 0, 0, blocked=True)
            self._session.flush()
            return JobOutcome(
                job.id, module.module_id, "failed", "Blocked by gate.",
                None, decision.reason, 0, 0,
            )

        # 2. Auto-populate candidate hostnames for the local asset-hint module.
        if module.module_id == "passive.asset_hints" and "candidates" not in config:
            config["candidates"] = self._known_candidates(project_id)

        # 3. Run the module (pure; never touches the DB).
        run_ctx = RunContext(
            target=target,
            target_type=target_type,
            services=self._services,
            config=config,
        )
        try:
            result = module.run(run_ctx)
        except ProviderError as exc:
            result = ModuleRunResult.failed(
                f"{exc.provider} failed ({exc.code}).",
                error_code=exc.code,
                detail=exc.detail,
                provider=exc.provider,
            )
        except Exception as exc:  # defensive: a module bug must not crash the app
            result = ModuleRunResult.failed(
                "Module raised an unexpected error.",
                error_code="module_error",
                detail=repr(exc),
            )

        # 4. Persist evidence, tracking the per-job byte budget.
        evidence_id_by_name: dict[str, str] = {}
        remaining = PER_JOB_LIMIT_BYTES
        for blob in result.evidence:
            stored = self._store.write(
                job.id,
                blob.name,
                blob.media_type,
                blob.content,
                remaining_budget=remaining,
                provider=blob.provider,
                sensitive=blob.sensitive,
            )
            remaining -= stored.size_bytes
            row = Evidence(
                job_id=job.id,
                provider=stored.provider,
                name=stored.name,
                relative_path=stored.relative_path,
                media_type=stored.media_type,
                size_bytes=stored.size_bytes,
                sha256=stored.sha256,
                truncated=stored.truncated,
                sensitive=stored.sensitive,
            )
            self._session.add(row)
            self._session.flush()
            evidence_id_by_name[blob.name] = row.id

        # 5. Upsert findings.
        finding_count = upsert_findings(
            self._session,
            project_id=project_id,
            job_id=job.id,
            module_id=module.module_id,
            findings=result.findings,
            evidence_id_by_name=evidence_id_by_name,
            target_requested=target,
            target_contacted=result.provider,
        )

        # 6. Finalize job + activity log.
        job.status = result.status
        job.error_code = result.error_code
        job.finished_at = _now()
        self._log(
            project_id, job, result.status, result.provider,
            finding_count, len(result.evidence), detail=result.summary,
        )
        self._session.flush()

        return JobOutcome(
            job_id=job.id,
            module_id=module.module_id,
            status=result.status,
            summary=result.summary,
            provider=result.provider,
            error_code=result.error_code,
            finding_count=finding_count,
            evidence_count=len(result.evidence),
        )

    def _known_candidates(self, project_id: str) -> list[str]:
        rows = self._session.scalars(
            select(Finding.value).where(
                Finding.project_id == project_id,
                Finding.finding_type.in_(("candidate_hostname", "ptr_name")),
            )
        ).all()
        return sorted(set(rows))

    def _log(
        self, project_id, job, decision, provider, findings, evidence,
        detail=None, blocked=False,
    ) -> None:
        self._session.add(
            ActivityLog(
                project_id=project_id,
                action="module.blocked" if blocked else "module.run",
                module_id=job.module_id,
                target=job.target,
                scope_decision=decision,
                matched_entry=provider,
                detail=(
                    f"{detail or ''} "
                    f"[findings={findings}, evidence={evidence}, provider={provider}]"
                ).strip(),
            )
        )
