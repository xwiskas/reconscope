"""In-process manager for background active jobs with progress + cancellation.

An active job runs in a worker thread with its own DB session. Lifecycle and
progress events are appended to a per-job handle; the SSE endpoint replays them
(with monotonic sequence numbers, so a reconnect can resume). Cancellation sets
a threading.Event that the subprocess supervisor already honors, terminating
the process tree (PRD §10.4, §12.5).
"""

from __future__ import annotations

import datetime as dt
import threading
import uuid
from dataclasses import dataclass, field

from sqlalchemy import select

from reconscope.jobs.active_runner import ActiveJobRunner
from reconscope.models import AuthorizationRecord, ScopeEntry
from reconscope.modules.gate import ProjectAuthorization
from reconscope.modules.registry import get_module
from reconscope.scope.canonical import CanonicalizationError, canonicalize_scope_entry

_TERMINAL = {"succeeded", "failed", "partial", "cancelled", "interrupted"}


def _now_iso() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat()


@dataclass
class JobEvent:
    seq: int
    type: str
    message: str
    status: str | None
    ts: str
    data: dict = field(default_factory=dict)

    def as_dict(self) -> dict:
        return {
            "seq": self.seq,
            "type": self.type,
            "message": self.message,
            "status": self.status,
            "ts": self.ts,
            "data": self.data,
        }


class JobHandle:
    def __init__(self, job_id: str):
        self.job_id = job_id
        self.cancel = threading.Event()
        self._events: list[JobEvent] = []
        self._terminal = False
        self._lock = threading.Lock()

    def emit(self, type: str, message: str, status: str | None = None,
             data: dict | None = None) -> None:
        with self._lock:
            self._events.append(
                JobEvent(len(self._events), type, message, status, _now_iso(),
                         data or {})
            )
            if status in _TERMINAL:
                self._terminal = True

    def snapshot(self, from_seq: int) -> tuple[list[JobEvent], bool]:
        with self._lock:
            return [e for e in self._events if e.seq >= from_seq], self._terminal

    @property
    def terminal(self) -> bool:
        with self._lock:
            return self._terminal


class ActiveJobManager:
    def __init__(self, session_factory, evidence_store, services_getter):
        self._session_factory = session_factory
        self._evidence_store = evidence_store
        self._services_getter = services_getter
        self._handles: dict[str, JobHandle] = {}
        self._lock = threading.Lock()

    def handle(self, job_id: str) -> JobHandle | None:
        with self._lock:
            return self._handles.get(job_id)

    def submit(self, *, project_id: str, module_id: str, target: str,
               target_type, config: dict | None = None) -> str:
        job_id = uuid.uuid4().hex
        handle = JobHandle(job_id)
        with self._lock:
            self._handles[job_id] = handle
        thread = threading.Thread(
            target=self._run,
            args=(job_id, project_id, module_id, target, target_type, config or {}),
            daemon=True,
        )
        thread.start()
        return job_id

    def cancel(self, job_id: str) -> bool:
        handle = self.handle(job_id)
        if handle is None:
            return False
        handle.cancel.set()
        handle.emit("cancelling", "Cancellation requested.")
        return True

    def _run(self, job_id, project_id, module_id, target, target_type, config):
        handle = self._handles[job_id]
        session = self._session_factory()
        try:
            module = get_module(module_id)
            if module is None:
                handle.emit("error", "Unknown module.", "failed")
                return
            entries = self._enabled_entries(session, project_id)
            authz = ProjectAuthorization.build(
                attestation_current=self._attested(session, project_id),
                enabled_entries=entries,
            )
            handle.emit("running", "Job started.", None)
            runner = ActiveJobRunner(
                session, self._evidence_store, self._services_getter()
            )
            outcome = runner.run(
                project_id=project_id,
                module=module,
                target=target,
                target_type=target_type,
                authz=authz,
                enabled_entries=entries,
                job_id=job_id,
                config={**config, "cancel": handle.cancel},
                on_event=lambda t, m, d=None: handle.emit(t, m, None, d),
            )
            session.commit()
            handle.emit(
                outcome.status,
                outcome.summary,
                outcome.status,
                {
                    "error_code": outcome.error_code,
                    "pinned_ips": list(outcome.pinned_ips),
                    "finding_count": outcome.finding_count,
                    "evidence_count": outcome.evidence_count,
                },
            )
        except Exception as exc:  # pragma: no cover - defensive
            session.rollback()
            handle.emit("error", f"Job crashed: {exc}", "failed")
        finally:
            session.close()

    def _enabled_entries(self, session, project_id):
        rows = session.scalars(
            select(ScopeEntry).where(
                ScopeEntry.project_id == project_id, ScopeEntry.enabled.is_(True)
            )
        ).all()
        out = []
        for r in rows:
            try:
                out.append(canonicalize_scope_entry(r.entered_value))
            except CanonicalizationError:
                continue
        return out

    def _attested(self, session, project_id) -> bool:
        return (
            session.scalars(
                select(AuthorizationRecord).where(
                    AuthorizationRecord.project_id == project_id,
                    AuthorizationRecord.invalidated_at.is_(None),
                )
            ).first()
            is not None
        )
