"""FastAPI application factory (PRD §12.2, §13).

Milestone 0 exposes the safety spine over the API so the eventual GUI (and the
tests) can exercise it: canonicalize a scope entry, evaluate a target against a
scope, and run the gate for the test module. Full project/job CRUD arrives with
later milestones.
"""

from __future__ import annotations

import sys
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from reconscope import __version__
from reconscope.api import api_router
from reconscope.config import Settings, get_settings
from reconscope.db import get_session_factory, init_db
from reconscope.education.glossary import GLOSSARY
from reconscope.evidence.store import EvidenceStore
from reconscope.modules.contract import ModuleContext
from reconscope.modules.echo import ConnectivityEcho
from reconscope.modules.gate import ProjectAuthorization, authorize_job
from reconscope.scope.canonical import (
    CanonicalizationError,
    TargetType,
    canonicalize_scope_entry,
)
from reconscope.scope.service import evaluate

_CSP = (
    "default-src 'none'; "
    "script-src 'self'; "
    "style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; "
    "connect-src 'self'; "
    "font-src 'self'; "
    "base-uri 'none'; "
    "form-action 'none'; "
    "frame-ancestors 'none'"
)


class _SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Attach a restrictive CSP and deny framing on every response (PRD §13.3)."""

    async def dispatch(self, request: Request, call_next):
        response: Response = await call_next(request)
        response.headers.setdefault("Content-Security-Policy", _CSP)
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "no-referrer")
        return response


# --------------------------------------------------------------------------- #
# Request/response models
# --------------------------------------------------------------------------- #
class ScopeEntryIn(BaseModel):
    value: str = Field(..., description="A domain, *.domain, IP, or CIDR.")


class ScopePreviewOut(BaseModel):
    ok: bool
    type: str | None = None
    canonical: str | None = None
    display: str | None = None
    error: str | None = None


class EvaluateIn(BaseModel):
    target: str
    target_type: TargetType
    entries: list[str] = Field(default_factory=list)


class EvaluateOut(BaseModel):
    allowed: bool
    reason: str
    matched_entry: str | None = None
    target: str | None = None
    invalid_entries: list[str] = Field(default_factory=list)


class GateCheckIn(BaseModel):
    target: str
    target_type: TargetType
    entries: list[str] = Field(default_factory=list)
    attestation_current: bool = False


class GateCheckOut(BaseModel):
    allowed: bool
    reason: str
    matched_entry: str | None = None


def frontend_dist_dir() -> Path | None:
    """Locate the built SPA in both development and a PyInstaller bundle.

    In a frozen build the ``frontend/dist`` tree is bundled as ``frontend_dist``
    next to the app (``sys._MEIPASS``); in development it is the repo's
    ``frontend/dist``. Returns ``None`` if no build is present.
    """
    if getattr(sys, "frozen", False):
        base = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
        candidate = base / "frontend_dist"
        return candidate if candidate.is_dir() else None
    candidate = Path(__file__).resolve().parents[2] / "frontend" / "dist"
    return candidate if candidate.is_dir() else None


def create_app(
    settings: Settings | None = None,
    *,
    session_factory=None,
    services=None,
    evidence_store: EvidenceStore | None = None,
) -> FastAPI:
    settings = settings or get_settings()
    app = FastAPI(
        title="ReconScope",
        version=__version__,
        docs_url="/docs" if settings.enable_docs else None,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    app.add_middleware(_SecurityHeadersMiddleware)
    # No permissive CORS: the app is same-origin loopback only (PRD §13.1).
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[],
        allow_credentials=False,
        allow_methods=[],
        allow_headers=[],
    )

    @app.get("/api/v1/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.get("/api/v1/version")
    def version() -> dict:
        return {"version": __version__}

    @app.get("/api/v1/glossary")
    def glossary() -> list[dict]:
        return [
            {"slug": t.slug, "term": t.term, "definition": t.definition}
            for t in GLOSSARY.values()
        ]

    @app.post("/api/v1/scope/preview", response_model=ScopePreviewOut)
    def scope_preview(body: ScopeEntryIn) -> ScopePreviewOut:
        try:
            entry = canonicalize_scope_entry(body.value)
        except CanonicalizationError as exc:
            return ScopePreviewOut(ok=False, error=str(exc))
        return ScopePreviewOut(
            ok=True,
            type=entry.type.value,
            canonical=entry.value,
            display=entry.display,
        )

    @app.post("/api/v1/scope/evaluate", response_model=EvaluateOut)
    def scope_evaluate(body: EvaluateIn) -> EvaluateOut:
        canonical_entries = []
        invalid: list[str] = []
        for raw in body.entries:
            try:
                canonical_entries.append(canonicalize_scope_entry(raw))
            except CanonicalizationError:
                invalid.append(raw)
        decision = evaluate(body.target, body.target_type, canonical_entries)
        return EvaluateOut(
            allowed=decision.allowed,
            reason=decision.reason,
            matched_entry=decision.matched_entry,
            target=decision.target,
            invalid_entries=invalid,
        )

    @app.post("/api/v1/gate/check", response_model=GateCheckOut)
    def gate_check(body: GateCheckIn) -> GateCheckOut:
        canonical_entries = []
        for raw in body.entries:
            try:
                canonical_entries.append(canonicalize_scope_entry(raw))
            except CanonicalizationError:
                continue
        authz = ProjectAuthorization.build(
            attestation_current=body.attestation_current,
            enabled_entries=canonical_entries,
        )
        ctx = ModuleContext(target=body.target, target_type=body.target_type)
        decision = authorize_job(ConnectivityEcho(), ctx, authz)
        return GateCheckOut(
            allowed=decision.allowed,
            reason=decision.reason,
            matched_entry=decision.matched_entry,
        )

    # --- Wire application state for the project/passive API -------------- #
    if session_factory is None:
        init_db(settings)
        session_factory = get_session_factory(settings)
    app.state.session_factory = session_factory
    app.state.evidence_store = evidence_store or EvidenceStore(settings.evidence_dir)

    # Restart recovery: reconcile any jobs left running by a previous run.
    from reconscope.jobs.recovery import recover_interrupted_jobs

    _recovery_session = session_factory()
    try:
        recover_interrupted_jobs(_recovery_session)
    except Exception:  # pragma: no cover - never block startup on recovery
        pass
    finally:
        _recovery_session.close()

    if services is not None:
        app.state.get_services = lambda: services
    else:
        _cache: dict = {}

        def _lazy_services():
            if "svc" not in _cache:
                from reconscope.providers.services import build_default_services

                _cache["svc"] = build_default_services()
            return _cache["svc"]

        app.state.get_services = _lazy_services

    # Background manager for active jobs (SSE progress + cancellation).
    from reconscope.jobs.manager import ActiveJobManager

    app.state.active_manager = ActiveJobManager(
        session_factory=app.state.session_factory,
        evidence_store=app.state.evidence_store,
        services_getter=app.state.get_services,
    )

    app.include_router(api_router)

    # Serve the built React SPA when present (production/local use). API routes
    # are registered above and take precedence over this catch-all mount.
    frontend_dist = frontend_dist_dir()
    if frontend_dist is not None:
        app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="spa")

    return app


app = create_app()
