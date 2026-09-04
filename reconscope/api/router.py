"""Project / passive-recon API (PRD §5, §12.4).

Milestone 1 runs passive modules synchronously (they are quick and quiet). The
async job supervisor with SSE progress is introduced with active modules in M2.
Session and provider services are read from ``request.app.state`` so tests can
inject fakes.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterator

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from reconscope.education.manifest import LearningManifest
from reconscope.evidence.store import EvidenceStore
from reconscope.jobs.active_runner import ActiveJobRunner
from reconscope.jobs.runner import PassiveJobRunner
from reconscope.models import (
    ActivityLog,
    AssignmentWorksheet,
    AuthorizationRecord,
    Evidence,
    Finding,
    Job,
    Project,
    ReportSnapshot,
    ScopeEntry,
    SeedTarget,
)
from reconscope.modules.contract import InteractionType
from reconscope.modules.gate import ProjectAuthorization
from reconscope.modules.registry import get_module, list_modules
from reconscope.reporting import (
    build_markdown_report,
    build_report_zip,
    explain_argv,
    recommend_next_steps,
)
from reconscope.scope.canonical import (
    CanonicalizationError,
    EntryType,
    TargetType,
    canonicalize_scope_entry,
)

api_router = APIRouter(prefix="/api/v1")

ATTESTATION_TEXT = (
    "I confirm that I own these targets or have explicit authorization to test "
    "them, and that the selected action is permitted by that authorization."
)
NOTICE_VERSION = "2026-09-04.1"


# --------------------------------------------------------------------------- #
# Dependencies
# --------------------------------------------------------------------------- #
def get_session(request: Request) -> Iterator[Session]:
    factory = request.app.state.session_factory
    session = factory()
    try:
        yield session
        session.commit()
    except Exception:
        session.rollback()
        raise
    finally:
        session.close()


def get_services(request: Request):
    return request.app.state.get_services()


def get_evidence_store(request: Request) -> EvidenceStore:
    return request.app.state.evidence_store


# --------------------------------------------------------------------------- #
# Schemas
# --------------------------------------------------------------------------- #
class ProjectIn(BaseModel):
    name: str
    description: str | None = None
    notes: str | None = None


class ProjectOut(BaseModel):
    id: str
    name: str
    description: str | None
    notes: str | None
    attestation_current: bool
    scope_count: int


class ValueIn(BaseModel):
    value: str


class ScopeEntryOut(BaseModel):
    id: str
    entry_type: str
    normalized_value: str
    entered_value: str
    enabled: bool


class JobIn(BaseModel):
    module_id: str
    target: str
    target_type: TargetType
    config: dict = Field(default_factory=dict)


class JobOut(BaseModel):
    job_id: str
    module_id: str
    status: str
    summary: str
    provider: str | None
    error_code: str | None
    finding_count: int
    evidence_count: int


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _get_project(session: Session, project_id: str) -> Project:
    project = session.get(Project, project_id)
    if project is None:
        raise HTTPException(status_code=404, detail="project_not_found")
    return project


def _attestation_current(session: Session, project_id: str) -> bool:
    row = session.scalars(
        select(AuthorizationRecord).where(
            AuthorizationRecord.project_id == project_id,
            AuthorizationRecord.invalidated_at.is_(None),
        )
    ).first()
    return row is not None


def _enabled_canonical_entries(session: Session, project_id: str):
    entries = session.scalars(
        select(ScopeEntry).where(
            ScopeEntry.project_id == project_id, ScopeEntry.enabled.is_(True)
        )
    ).all()
    canonical = []
    for e in entries:
        try:
            canonical.append(canonicalize_scope_entry(e.entered_value))
        except CanonicalizationError:
            continue
    return canonical


def _project_out(session: Session, project: Project) -> ProjectOut:
    scope_count = len(
        session.scalars(
            select(ScopeEntry.id).where(ScopeEntry.project_id == project.id)
        ).all()
    )
    return ProjectOut(
        id=project.id,
        name=project.name,
        description=project.description,
        notes=project.notes,
        attestation_current=_attestation_current(session, project.id),
        scope_count=scope_count,
    )


# --------------------------------------------------------------------------- #
# Projects
# --------------------------------------------------------------------------- #
@api_router.post("/projects", response_model=ProjectOut)
def create_project(body: ProjectIn, session: Session = Depends(get_session)):
    project = Project(name=body.name, description=body.description, notes=body.notes)
    session.add(project)
    session.flush()
    return _project_out(session, project)


@api_router.get("/projects", response_model=list[ProjectOut])
def list_projects(session: Session = Depends(get_session)):
    projects = session.scalars(select(Project).order_by(Project.created_at)).all()
    return [_project_out(session, p) for p in projects]


@api_router.get("/projects/{project_id}", response_model=ProjectOut)
def get_project(project_id: str, session: Session = Depends(get_session)):
    return _project_out(session, _get_project(session, project_id))


# --------------------------------------------------------------------------- #
# Seeds, scope, attestation
# --------------------------------------------------------------------------- #
@api_router.post("/projects/{project_id}/seeds")
def add_seed(project_id: str, body: ValueIn, session: Session = Depends(get_session)):
    _get_project(session, project_id)
    try:
        entry = canonicalize_scope_entry(body.value)
    except CanonicalizationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if entry.type not in (EntryType.DOMAIN, EntryType.IP):
        raise HTTPException(status_code=400, detail="seed must be a domain or IP")
    seed = SeedTarget(
        project_id=project_id,
        target_type="ip" if entry.type is EntryType.IP else "domain",
        normalized_value=entry.value,
        entered_value=entry.display,
    )
    session.add(seed)
    session.flush()
    return {"id": seed.id, "type": seed.target_type, "value": seed.normalized_value}


@api_router.post("/projects/{project_id}/scope", response_model=ScopeEntryOut)
def add_scope(project_id: str, body: ValueIn, session: Session = Depends(get_session)):
    _get_project(session, project_id)
    try:
        entry = canonicalize_scope_entry(body.value)
    except CanonicalizationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    existing = session.scalars(
        select(ScopeEntry).where(
            ScopeEntry.project_id == project_id,
            ScopeEntry.entry_type == entry.type.value,
            ScopeEntry.normalized_value == entry.value,
        )
    ).first()
    if existing is not None:
        raise HTTPException(status_code=409, detail="duplicate scope entry")

    row = ScopeEntry(
        project_id=project_id,
        entry_type=entry.type.value,
        normalized_value=entry.value,
        entered_value=entry.display,
        enabled=True,
    )
    session.add(row)
    # Adding/expanding scope invalidates any current attestation (PRD §4.2).
    _invalidate_attestation(session, project_id, "scope expanded")
    session.flush()
    return ScopeEntryOut(
        id=row.id,
        entry_type=row.entry_type,
        normalized_value=row.normalized_value,
        entered_value=row.entered_value,
        enabled=row.enabled,
    )


@api_router.get("/projects/{project_id}/scope", response_model=list[ScopeEntryOut])
def list_scope(project_id: str, session: Session = Depends(get_session)):
    _get_project(session, project_id)
    rows = session.scalars(
        select(ScopeEntry).where(ScopeEntry.project_id == project_id)
    ).all()
    return [
        ScopeEntryOut(
            id=r.id,
            entry_type=r.entry_type,
            normalized_value=r.normalized_value,
            entered_value=r.entered_value,
            enabled=r.enabled,
        )
        for r in rows
    ]


def _invalidate_attestation(session: Session, project_id: str, reason: str) -> None:
    import datetime as dt

    rows = session.scalars(
        select(AuthorizationRecord).where(
            AuthorizationRecord.project_id == project_id,
            AuthorizationRecord.invalidated_at.is_(None),
        )
    ).all()
    for row in rows:
        row.invalidated_at = dt.datetime.now(dt.UTC).replace(tzinfo=None)
        row.invalidated_reason = reason


@api_router.post("/projects/{project_id}/attestation")
def attest(project_id: str, session: Session = Depends(get_session)):
    _get_project(session, project_id)
    if not _enabled_canonical_entries(session, project_id):
        raise HTTPException(
            status_code=400, detail="add at least one enabled scope entry first"
        )
    record = AuthorizationRecord(
        project_id=project_id,
        attestation_text=ATTESTATION_TEXT,
        notice_version=NOTICE_VERSION,
    )
    session.add(record)
    session.flush()
    return {"attestation_current": True, "notice_version": NOTICE_VERSION}


# --------------------------------------------------------------------------- #
# Module catalog
# --------------------------------------------------------------------------- #
def _manifest_dict(m: LearningManifest) -> dict:
    return {
        "module_id": m.module_id,
        "version": m.version,
        "what": m.what,
        "methodology_position": m.methodology_position,
        "interaction": m.interaction,
        "intensity": m.intensity,
        "data_leaves_machine": m.data_leaves_machine,
        "observers": m.observers,
        "budget": m.budget,
        "tool": m.tool,
        "options_explained": m.options_explained,
        "result_states": m.result_states,
        "attacker_relevance": m.attacker_relevance,
        "defender_relevance": m.defender_relevance,
        "false_positives": m.false_positives,
        "limitations": m.limitations,
        "safe_next_steps": m.safe_next_steps,
        "prohibited_next_steps": m.prohibited_next_steps,
        "glossary_terms": list(m.glossary_terms),
    }


@api_router.get("/modules")
def modules_catalog():
    out = []
    for m in list_modules():
        out.append(
            {
                "module_id": m.module_id,
                "display_name": m.display_name,
                "description": m.description,
                "interaction": m.interaction.value,
                "intensity": m.intensity.value,
                "accepted_target_types": [t.value for t in m.accepted_target_types],
            }
        )
    return out


@api_router.get("/modules/{module_id}/manifest")
def module_manifest(module_id: str):
    module = get_module(module_id)
    if module is None:
        raise HTTPException(status_code=404, detail="module_not_found")
    return _manifest_dict(module.manifest)


# --------------------------------------------------------------------------- #
# Jobs (synchronous passive runs in M1)
# --------------------------------------------------------------------------- #
@api_router.post("/projects/{project_id}/jobs", response_model=JobOut)
def run_job(
    project_id: str,
    body: JobIn,
    session: Session = Depends(get_session),
    services=Depends(get_services),
    evidence_store: EvidenceStore = Depends(get_evidence_store),
):
    _get_project(session, project_id)
    module = get_module(body.module_id)
    if module is None:
        raise HTTPException(status_code=404, detail="module_not_found")

    authz = ProjectAuthorization.build(
        attestation_current=_attestation_current(session, project_id),
        enabled_entries=_enabled_canonical_entries(session, project_id),
    )
    runner = PassiveJobRunner(session, evidence_store, services)
    outcome = runner.run(
        project_id=project_id,
        module=module,
        target=body.target,
        target_type=body.target_type,
        authz=authz,
        config=body.config,
    )
    return JobOut(**outcome.__dict__)


class ActiveJobOut(BaseModel):
    job_id: str
    module_id: str
    status: str
    summary: str
    error_code: str | None
    pinned_ips: list[str]
    finding_count: int
    evidence_count: int


@api_router.get("/capabilities")
def capabilities(services=Depends(get_services)):
    nmap = getattr(services, "nmap", None)
    if nmap is None:
        return {"nmap": {"available": False, "error": "not detected"}}
    return {
        "nmap": {
            "available": nmap.available,
            "version": nmap.version,
            "path": nmap.path,
            "error": nmap.error,
            "install_hint": nmap.install_hint,
        }
    }


@api_router.post("/projects/{project_id}/active-jobs", response_model=ActiveJobOut)
def run_active_job(
    project_id: str,
    body: JobIn,
    session: Session = Depends(get_session),
    services=Depends(get_services),
    evidence_store: EvidenceStore = Depends(get_evidence_store),
):
    _get_project(session, project_id)
    module = get_module(body.module_id)
    if module is None:
        raise HTTPException(status_code=404, detail="module_not_found")
    if module.interaction is not InteractionType.ACTIVE:
        raise HTTPException(status_code=400, detail="not an active module")

    entries = _enabled_canonical_entries(session, project_id)
    authz = ProjectAuthorization.build(
        attestation_current=_attestation_current(session, project_id),
        enabled_entries=entries,
    )
    runner = ActiveJobRunner(session, evidence_store, services)
    outcome = runner.run(
        project_id=project_id,
        module=module,
        target=body.target,
        target_type=body.target_type,
        authz=authz,
        enabled_entries=entries,
        config=body.config,
    )
    return ActiveJobOut(
        job_id=outcome.job_id,
        module_id=outcome.module_id,
        status=outcome.status,
        summary=outcome.summary,
        error_code=outcome.error_code,
        pinned_ips=list(outcome.pinned_ips),
        finding_count=outcome.finding_count,
        evidence_count=outcome.evidence_count,
    )


def get_manager(request: Request):
    return request.app.state.active_manager


@api_router.post("/projects/{project_id}/active-jobs/start")
def start_active_job(
    project_id: str,
    body: JobIn,
    session: Session = Depends(get_session),
    manager=Depends(get_manager),
):
    """Start an active job in the background; returns its id for SSE + cancel."""
    _get_project(session, project_id)
    module = get_module(body.module_id)
    if module is None:
        raise HTTPException(status_code=404, detail="module_not_found")
    if module.interaction is not InteractionType.ACTIVE:
        raise HTTPException(status_code=400, detail="not an active module")
    job_id = manager.submit(
        project_id=project_id,
        module_id=body.module_id,
        target=body.target,
        target_type=body.target_type,
        config=body.config,
    )
    return {"job_id": job_id}


@api_router.get("/projects/{project_id}/active-jobs/{job_id}/events")
async def active_job_events(
    project_id: str, job_id: str, request: Request, manager=Depends(get_manager)
):
    handle = manager.handle(job_id)
    if handle is None:
        raise HTTPException(status_code=404, detail="job_not_found")

    last = request.headers.get("last-event-id")
    start = int(last) + 1 if last and last.isdigit() else 0

    async def gen():
        cursor = start
        while True:
            events, terminal = handle.snapshot(cursor)
            if events:
                for ev in events:
                    cursor = ev.seq + 1
                    # No `event:` line, so the browser's default `onmessage`
                    # fires for every event; the type is inside the JSON.
                    yield f"id: {ev.seq}\ndata: {json.dumps(ev.as_dict())}\n\n"
                continue
            if terminal:
                break
            if await request.is_disconnected():
                break
            await asyncio.sleep(0.15)

    return StreamingResponse(
        gen(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@api_router.post("/projects/{project_id}/active-jobs/{job_id}/cancel")
def cancel_active_job(project_id: str, job_id: str, manager=Depends(get_manager)):
    if not manager.cancel(job_id):
        raise HTTPException(status_code=404, detail="job_not_found")
    return {"cancelling": True}


@api_router.get("/projects/{project_id}/jobs")
def list_jobs(project_id: str, session: Session = Depends(get_session)):
    _get_project(session, project_id)
    rows = session.scalars(
        select(Job).where(Job.project_id == project_id).order_by(Job.created_at)
    ).all()
    return [
        {
            "id": j.id,
            "module_id": j.module_id,
            "target": j.target,
            "status": j.status,
            "error_code": j.error_code,
        }
        for j in rows
    ]


# --------------------------------------------------------------------------- #
# Findings, evidence, activity
# --------------------------------------------------------------------------- #
@api_router.get("/projects/{project_id}/findings")
def list_findings(
    project_id: str,
    finding_type: str | None = None,
    session: Session = Depends(get_session),
):
    _get_project(session, project_id)
    stmt = select(Finding).where(Finding.project_id == project_id)
    if finding_type:
        stmt = stmt.where(Finding.finding_type == finding_type)
    rows = session.scalars(stmt.order_by(Finding.finding_type, Finding.value)).all()
    ev_names = {
        e.id: e.name
        for e in session.scalars(
            select(Evidence).where(
                Evidence.id.in_([f.evidence_id for f in rows if f.evidence_id])
            )
        ).all()
    }
    return [
        {
            "id": f.id,
            "finding_type": f.finding_type,
            "value": f.value,
            "confidence": f.confidence,
            "source": f.source,
            "data": f.data,
            "evidence": ev_names.get(f.evidence_id) if f.evidence_id else None,
            "target": f.target_requested,
            "first_seen": f.first_seen.isoformat(),
            "last_seen": f.last_seen.isoformat(),
        }
        for f in rows
    ]


@api_router.get("/projects/{project_id}/evidence")
def list_evidence(project_id: str, session: Session = Depends(get_session)):
    _get_project(session, project_id)
    job_ids = session.scalars(
        select(Job.id).where(Job.project_id == project_id)
    ).all()
    if not job_ids:
        return []
    rows = session.scalars(
        select(Evidence).where(Evidence.job_id.in_(job_ids))
    ).all()
    return [
        {
            "id": e.id,
            "provider": e.provider,
            "name": e.name,
            "media_type": e.media_type,
            "size_bytes": e.size_bytes,
            "sha256": e.sha256,
            "truncated": e.truncated,
            "sensitive": e.sensitive,
        }
        for e in rows
    ]


@api_router.get("/projects/{project_id}/activity")
def list_activity(project_id: str, session: Session = Depends(get_session)):
    _get_project(session, project_id)
    rows = session.scalars(
        select(ActivityLog)
        .where(ActivityLog.project_id == project_id)
        .order_by(ActivityLog.id)
    ).all()
    return [
        {
            "timestamp": a.timestamp.isoformat(),
            "action": a.action,
            "module_id": a.module_id,
            "target": a.target,
            "scope_decision": a.scope_decision,
            "detail": a.detail,
        }
        for a in rows
    ]


# --------------------------------------------------------------------------- #
# Recommendations (PRD §8.4)
# --------------------------------------------------------------------------- #
@api_router.get("/projects/{project_id}/recommendations")
def recommendations(project_id: str, session: Session = Depends(get_session)):
    _get_project(session, project_id)
    findings = session.scalars(
        select(Finding).where(Finding.project_id == project_id)
    ).all()
    finding_dicts = [
        {"finding_type": f.finding_type, "value": f.value, "data": f.data}
        for f in findings
    ]
    return [
        {
            "reason": r.reason,
            "action": r.action,
            "module_id": r.module_id,
            "config": r.config,
        }
        for r in recommend_next_steps(finding_dicts)
    ]


# --------------------------------------------------------------------------- #
# Assignment worksheet (PRD §8.5)
# --------------------------------------------------------------------------- #
_WORKSHEET_FIELDS = (
    "title", "prompt", "hypothesis", "method", "predicted_traffic",
    "interpretation", "false_positive_considerations", "defender_interpretation",
    "conclusion", "remaining_unknowns",
)


class WorksheetIn(BaseModel):
    title: str | None = None
    prompt: str | None = None
    hypothesis: str | None = None
    method: str | None = None
    predicted_traffic: str | None = None
    interpretation: str | None = None
    false_positive_considerations: str | None = None
    defender_interpretation: str | None = None
    conclusion: str | None = None
    remaining_unknowns: str | None = None


def _worksheet_dict(w: AssignmentWorksheet | None) -> dict:
    if w is None:
        return {f: None for f in _WORKSHEET_FIELDS}
    return {f: getattr(w, f) for f in _WORKSHEET_FIELDS}


@api_router.get("/projects/{project_id}/worksheet")
def get_worksheet(project_id: str, session: Session = Depends(get_session)):
    _get_project(session, project_id)
    w = session.scalars(
        select(AssignmentWorksheet).where(
            AssignmentWorksheet.project_id == project_id
        )
    ).first()
    return _worksheet_dict(w)


@api_router.put("/projects/{project_id}/worksheet")
def put_worksheet(
    project_id: str, body: WorksheetIn, session: Session = Depends(get_session)
):
    _get_project(session, project_id)
    w = session.scalars(
        select(AssignmentWorksheet).where(
            AssignmentWorksheet.project_id == project_id
        )
    ).first()
    if w is None:
        w = AssignmentWorksheet(project_id=project_id)
        session.add(w)
    for field in _WORKSHEET_FIELDS:
        setattr(w, field, getattr(body, field))
    session.flush()
    return _worksheet_dict(w)


# --------------------------------------------------------------------------- #
# Reports (PRD §11)
# --------------------------------------------------------------------------- #
def _record_snapshot(session, project_id, fmt, manifest_hash):
    jobs = session.scalars(
        select(Job.id).where(Job.project_id == project_id)
    ).all()
    findings = session.scalars(
        select(Finding.id).where(Finding.project_id == project_id)
    ).all()
    session.add(
        ReportSnapshot(
            project_id=project_id,
            fmt=fmt,
            manifest_hash=manifest_hash,
            job_count=len(jobs),
            finding_count=len(findings),
        )
    )


@api_router.get("/projects/{project_id}/report.md")
def report_markdown(project_id: str, session: Session = Depends(get_session)):
    _get_project(session, project_id)
    md = build_markdown_report(session, project_id)
    import hashlib

    _record_snapshot(session, project_id, "markdown", hashlib.sha256(md.encode()).hexdigest())
    return Response(content=md, media_type="text/markdown; charset=utf-8")


@api_router.get("/projects/{project_id}/report.zip")
def report_zip(
    project_id: str,
    session: Session = Depends(get_session),
    evidence_store: EvidenceStore = Depends(get_evidence_store),
):
    _get_project(session, project_id)
    data, manifest_hash = build_report_zip(session, project_id, evidence_store)
    _record_snapshot(session, project_id, "zip", manifest_hash)
    return Response(
        content=data,
        media_type="application/zip",
        headers={
            "Content-Disposition": 'attachment; filename="reconscope-report.zip"'
        },
    )


# --------------------------------------------------------------------------- #
# Explain every argument (PRD §8.3)
# --------------------------------------------------------------------------- #
@api_router.get("/projects/{project_id}/jobs/{job_id}/command")
def job_command(
    project_id: str,
    job_id: str,
    session: Session = Depends(get_session),
    evidence_store: EvidenceStore = Depends(get_evidence_store),
):
    _get_project(session, project_id)
    cmd_evidence = session.scalars(
        select(Evidence).where(
            Evidence.job_id == job_id, Evidence.name.like("%command%")
        )
    ).first()
    if cmd_evidence is None:
        raise HTTPException(status_code=404, detail="no recorded command for this job")
    try:
        text = (evidence_store._root / cmd_evidence.relative_path).read_text(
            encoding="utf-8", errors="replace"
        )
    except OSError as exc:
        raise HTTPException(status_code=404, detail="command evidence missing") from exc
    argv = text.splitlines()[0].split(" ") if text.strip() else []
    return {
        "argv": argv,
        "explanation": [
            {
                "token": a.token,
                "meaning": a.meaning,
                "kind": a.kind,
                "user_derived": a.user_derived,
            }
            for a in explain_argv(argv)
        ],
    }
