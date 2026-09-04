"""Detect the Nmap installation and report diagnostics (PRD §5.1, §16.3).

Missing Nmap disables only Nmap-dependent actions and provides installation
guidance; passive features keep working. Detection is injectable so tests do not
require Nmap to be installed.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

_VERSION_RE = re.compile(r"Nmap version ([\d.]+)")

WINDOWS_INSTALL_HINT = (
    "Nmap was not found. Install it from https://nmap.org/download.html "
    "(the Windows installer includes Npcap, needed for some scan types), then "
    "restart ReconScope."
)


@dataclass(frozen=True)
class NmapCapability:
    available: bool
    path: str | None = None
    version: str | None = None
    error: str | None = None
    install_hint: str = WINDOWS_INSTALL_HINT


def _default_which(name: str) -> str | None:
    return shutil.which(name)


def _default_version(path: str) -> str:
    out = subprocess.run(
        [path, "--version"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    return out.stdout or out.stderr or ""


def detect_nmap(
    which: Callable[[str], str | None] = _default_which,
    version_probe: Callable[[str], str] = _default_version,
) -> NmapCapability:
    """Locate Nmap and read its version. Never raises."""
    try:
        path = which("nmap")
    except Exception as exc:  # pragma: no cover - defensive
        return NmapCapability(available=False, error=f"which failed: {exc}")

    if not path:
        return NmapCapability(available=False, error="nmap not found on PATH")

    try:
        text = version_probe(path)
    except Exception as exc:
        return NmapCapability(
            available=False, path=path, error=f"could not run nmap: {exc}"
        )

    match = _VERSION_RE.search(text or "")
    version = match.group(1) if match else None
    if version is None:
        return NmapCapability(
            available=False, path=path, error="could not parse nmap version"
        )
    return NmapCapability(available=True, path=path, version=version)
