"""Module registry (PRD §12.2).

The single place that knows which modules exist. The API catalog, the runner,
and the manifest contract test all read from here.
"""

from __future__ import annotations

from reconscope.modules.active import (
    HttpOverview,
    ServiceDetection,
    TcpScan,
    TlsReview,
)
from reconscope.modules.passive import (
    AssetHints,
    CertTransparency,
    DnsRecords,
    Rdap,
    ReverseDns,
    SocialFootprint,
)

# Order is the recommended guided passive order (PRD §5.4).
_PASSIVE_MODULES = [
    Rdap(),
    DnsRecords(),
    ReverseDns(),
    CertTransparency(),
    AssetHints(),
    SocialFootprint(),
]

# Recommended guided active order (PRD §5.5).
_ACTIVE_MODULES = [
    TcpScan(),
    ServiceDetection(),
    HttpOverview(),
    TlsReview(),
]

_REGISTRY = {m.module_id: m for m in (*_PASSIVE_MODULES, *_ACTIVE_MODULES)}


def list_modules() -> list:
    """Return all registered modules in recommended order."""
    return list(_REGISTRY.values())


def get_module(module_id: str):
    """Return the module with ``module_id`` or ``None``."""
    return _REGISTRY.get(module_id)
