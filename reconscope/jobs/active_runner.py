"""Active job runner (PRD §4.4, §7, §16.2) — the active safety orchestrator.

Before any active module runs, the runner:

1. Checks the gate (current attestation + target in scope). Blocked → failed job.
2. Resolves a hostname target at job start and **pins** the addresses, recording
   them; the module then contacts the pinned IP (or the requested host for HTTP,
   where vhost/SNI matters, with the pinned IPs still recorded).
3. Serializes active jobs (one at a time) so a single Nmap job runs at once.

A single module failing never raises; it is recorded as a failed/partial job.
"""

from __future__ import annotations

import datetime as dt
import threading
from dataclasses import dataclass

from sqlalchemy.orm import Session

from reconscope.evidence.store import EvidenceStore
from reconscope.jobs.persist import store_evidence_and_findings
from reconscope.models import ActivityLog, Job
from reconscope.modules.contract import ModuleContext
from reconscope.modules.gate import ProjectAuthorization, authorize_job
from reconscope.modules.runtime import ModuleRunResult, RunContext
from reconscope.providers.dns import DnsStatus
from reconscope.providers.services import ProviderServices
from reconscope.scope.canonical import CanonicalScopeEntry, TargetType

# Only one active job runs at a time across the local session (PRD §12.5).
_ACTIVE_LOCK = threading.Lock()


def _now() -> dt.datetime:
    return dt.datetime.now(dt.UTC).replace(tzinfo=None)


@dataclass(frozen=True)
class ActiveJobOutcome:
    job_id: str
    module_id: str
    status: str
    summary: str
    error_code: str | None
    pinned_ips: tuple[str, ...]
    finding_count: int
    evidence_count: int


class ActiveJobRunner:
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
        enabled_entries: list[CanonicalScopeEntry],
        config: dict | None = None,
        job_id: str | None = None,
        on_event=None,
    ) -> ActiveJobOutcome:
        config = dict(config or {})
        mod_ctx = ModuleContext(target=target, target_type=target_type, config=config)

        def emit(event_type: str, message: str, data: dict | None = None) -> None:
            if on_event:
                on_event(event_type, message, data)

        job = Job(
            project_id=project_id,
            module_id=module.module_id,
            module_version=module.module_version,
            target=target,
            target_type=target_type.value,
            status="running",
            started_at=_now(),
        )
        if job_id:
            job.id = job_id
        self._session.add(job)
        self._session.flush()

        # 1. Gate: attestation + scope. This is the hard safety boundary.
        emit("gate", "Checking authorization and scope.")
        decision = authorize_job(module, mod_ctx, authz)
        if not decision.allowed:
            emit("blocked", f"Blocked: {decision.reason}.")
            return self._finish(
                job, project_id, "failed", "Blocked by gate.",
                decision.reason, (), 0, 0, scope_decision=decision.reason,
            )

        # 2. Resolve + pin.
        emit("resolving", "In scope. Resolving and pinning the target address.")
        pinned, resolution_note, resolve_ok = self._resolve_and_pin(target, target_type)
        if not resolve_ok:
            emit("resolve_failed", resolution_note)
            return self._finish(
                job, project_id, "failed",
                f"Could not resolve target: {resolution_note}",
                "resolution_failed", (), 0, 0, scope_decision=decision.reason,
            )
        emit("pinned", resolution_note, {"pinned_ips": list(pinned)})

        # 3. Choose the contact target and assemble the run context.
        contact = target if getattr(module, "contact_target", "ip") == "host" else pinned[0]
        run_config = {
            **config,
            "requested_host": target,
            "pinned_ips": list(pinned),
            "scope_entries": enabled_entries,
        }
        run_ctx = RunContext(
            target=contact,
            target_type=target_type,
            services=self._services,
            config=run_config,
        )

        # 4. Execute (serialized). Never let a module crash the app.
        emit("contacting", f"Running {module.display_name} against {contact}.")
        with _ACTIVE_LOCK:
            try:
                result = module.run(run_ctx)
            except Exception as exc:  # defensive
                result = ModuleRunResult.failed(
                    "Module raised an unexpected error.", "module_error", repr(exc)
                )

        findings, evidence = store_evidence_and_findings(
            self._session,
            self._store,
            project_id=project_id,
            job_id=job.id,
            module_id=module.module_id,
            result=result,
            target_requested=target,
            target_contacted=contact,
        )
        return self._finish(
            job, project_id, result.status, result.summary, result.error_code,
            pinned, findings, evidence, scope_decision=decision.reason,
            resolution=resolution_note,
        )

    # ------------------------------------------------------------------ #
    def _resolve_and_pin(
        self, target: str, target_type: TargetType
    ) -> tuple[tuple[str, ...], str, bool]:
        if target_type is TargetType.IP:
            return (target,), f"target is a literal IP ({target})", True
        resolver = self._services.resolver
        if resolver is None:
            return (), "no resolver configured", False
        addresses: list[str] = []
        for rtype in ("A", "AAAA"):
            ans = resolver.query(target, rtype)
            if ans.status is DnsStatus.OK:
                addresses.extend(ans.records)
        if not addresses:
            return (), f"{target} did not resolve to any address", False
        return tuple(addresses), f"{target} -> {', '.join(addresses)}", True

    def _finish(
        self, job, project_id, status, summary, error_code, pinned,
        findings, evidence, *, scope_decision, resolution=None,
    ) -> ActiveJobOutcome:
        job.status = status
        job.error_code = error_code
        job.finished_at = _now()
        self._session.add(
            ActivityLog(
                project_id=project_id,
                action="active.run",
                module_id=job.module_id,
                target=job.target,
                scope_decision=scope_decision,
                matched_entry=", ".join(pinned) if pinned else None,
                detail=(
                    f"{summary} [status={status}, findings={findings}, "
                    f"evidence={evidence}, resolution={resolution or 'n/a'}]"
                ),
            )
        )
        self._session.flush()
        return ActiveJobOutcome(
            job_id=job.id,
            module_id=job.module_id,
            status=status,
            summary=summary,
            error_code=error_code,
            pinned_ips=tuple(pinned),
            finding_count=findings,
            evidence_count=evidence,
        )
