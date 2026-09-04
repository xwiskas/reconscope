"""Local control-plane security: session guard and request-origin checks."""

from reconscope.security.session import (
    SessionManager,
    get_session_manager,
)

__all__ = ["SessionManager", "get_session_manager"]
