"""The container of provider services injected into modules (PRD §12.3)."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from reconscope.providers.cache import Cache, MemoryTTLCache
from reconscope.providers.dns import DnsResolver
from reconscope.providers.http import HttpClient

if TYPE_CHECKING:
    from reconscope.jobs.process import SubprocessRunner
    from reconscope.tools.capability import NmapCapability


@dataclass
class ProviderServices:
    """Shared, injectable services a module may use.

    Passive modules use ``http``/``cache``/``resolver``; active modules also use
    ``process_runner`` (for Nmap), ``nmap`` (capability), and ``tls_fetcher``.
    All optional fields default to ``None`` so tests build only what they need.
    """

    http: HttpClient
    cache: Cache
    resolver: DnsResolver | None = None
    process_runner: SubprocessRunner | None = None
    nmap: NmapCapability | None = None
    tls_fetcher: Any = None


def build_default_services() -> ProviderServices:
    """Build the real services for running the app (network + tool enabled)."""
    from reconscope.jobs.process import SubprocessRunner
    from reconscope.providers.dns import DnspythonResolver
    from reconscope.providers.tls import default_tls_fetch
    from reconscope.tools.capability import detect_nmap

    return ProviderServices(
        http=HttpClient(),
        cache=MemoryTTLCache(),
        resolver=DnspythonResolver(),
        process_runner=SubprocessRunner(),
        nmap=detect_nmap(),
        tls_fetcher=default_tls_fetch,
    )
