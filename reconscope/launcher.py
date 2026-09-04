"""Local launcher (PRD §5.1, §12.2).

Binds the backend to a free loopback port, mints a one-time bootstrap token, and
opens the default browser at the bootstrap URL. In M0 the launcher runs the API
and prints the bootstrap URL; the browser-side exchange and the served frontend
are wired up in later milestones.
"""

from __future__ import annotations

import socket
import webbrowser

import uvicorn

from reconscope.config import get_settings
from reconscope.main import create_app
from reconscope.security import get_session_manager


def _pick_free_port(host: str) -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((host, 0))
        return sock.getsockname()[1]


def main() -> None:
    settings = get_settings()
    settings.ensure_dirs()

    host = settings.host
    port = settings.port or _pick_free_port(host)

    token = get_session_manager().mint_bootstrap()
    bootstrap_url = f"http://{host}:{port}/#bootstrap={token}"

    print("ReconScope is starting.")
    print(f"  API/base URL:  http://{host}:{port}")
    print("  Open in your browser (one-time bootstrap):")
    print(f"    {bootstrap_url}")
    print("  This backend is bound to loopback only. Press Ctrl+C to stop.")

    try:
        webbrowser.open(bootstrap_url, new=1)
    except Exception:  # pragma: no cover - headless / no browser available
        pass

    app = create_app(settings)
    uvicorn.run(app, host=host, port=port, log_level="info")


if __name__ == "__main__":
    main()
