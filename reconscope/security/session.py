"""Local session guard (PRD §13.1, §13.2).

ReconScope intentionally sends requests to user-selected systems, so its local
control plane must not be drivable by an arbitrary web page the user happens to
visit. The guard implements:

* A one-time **bootstrap token** minted by the launcher and handed to the
  browser in the URL fragment. Exchanging it yields an ``HttpOnly``,
  ``SameSite=Strict`` session cookie. The token is single-use and expires.
* A **session cookie** validated on every API/SSE request.
* A **CSRF header** requirement for state-changing requests.
* **Host / Origin** validation against the active loopback origin.

M0 provides the mechanism and unit-testable logic. Wiring into every route and
the SSE transport is completed alongside the job layer in M2.
"""

from __future__ import annotations

import secrets
import time
from dataclasses import dataclass, field

_TOKEN_BYTES = 32  # 256 bits (PRD §13.2)
_BOOTSTRAP_TTL_SECONDS = 300  # five minutes
CSRF_HEADER = "x-reconscope-csrf"
SESSION_COOKIE = "reconscope_session"


@dataclass
class _Bootstrap:
    token: str
    created_at: float
    used: bool = False


@dataclass
class SessionManager:
    """In-memory, single-process session state for the local app."""

    _bootstrap: _Bootstrap | None = None
    _sessions: dict[str, float] = field(default_factory=dict)
    _csrf_tokens: dict[str, str] = field(default_factory=dict)

    # -- bootstrap ---------------------------------------------------------- #
    def mint_bootstrap(self) -> str:
        """Create a fresh single-use bootstrap token (invalidates any prior)."""
        token = secrets.token_urlsafe(_TOKEN_BYTES)
        self._bootstrap = _Bootstrap(token=token, created_at=time.monotonic())
        return token

    def _bootstrap_valid(self, token: str) -> bool:
        bs = self._bootstrap
        if bs is None or bs.used:
            return False
        if time.monotonic() - bs.created_at > _BOOTSTRAP_TTL_SECONDS:
            return False
        return secrets.compare_digest(bs.token, token)

    def exchange_bootstrap(self, token: str) -> tuple[str, str] | None:
        """Exchange a valid bootstrap token for ``(session_id, csrf_token)``.

        Returns ``None`` if the token is missing, expired, or already used.
        """
        if not token or not self._bootstrap_valid(token):
            return None
        assert self._bootstrap is not None
        self._bootstrap.used = True
        session_id = secrets.token_urlsafe(_TOKEN_BYTES)
        csrf = secrets.token_urlsafe(_TOKEN_BYTES)
        self._sessions[session_id] = time.monotonic()
        self._csrf_tokens[session_id] = csrf
        return session_id, csrf

    # -- validation --------------------------------------------------------- #
    def session_valid(self, session_id: str | None) -> bool:
        return bool(session_id) and session_id in self._sessions

    def csrf_valid(self, session_id: str | None, csrf: str | None) -> bool:
        if not self.session_valid(session_id) or not csrf:
            return False
        expected = self._csrf_tokens.get(session_id or "")
        return bool(expected) and secrets.compare_digest(expected, csrf)

    def end_session(self, session_id: str) -> None:
        self._sessions.pop(session_id, None)
        self._csrf_tokens.pop(session_id, None)

    def clear(self) -> None:
        self._bootstrap = None
        self._sessions.clear()
        self._csrf_tokens.clear()


def origin_allowed(origin: str | None, allowed_origins: set[str]) -> bool:
    """Validate an ``Origin`` header against the active loopback origin(s).

    A missing Origin is allowed (same-origin navigations and some GETs omit it);
    a present Origin must exactly match an allowed loopback origin.
    """
    if origin is None:
        return True
    return origin in allowed_origins


_MANAGER: SessionManager | None = None


def get_session_manager() -> SessionManager:
    global _MANAGER
    if _MANAGER is None:
        _MANAGER = SessionManager()
    return _MANAGER
