"""Shared fixtures for passive-engine tests (no real network)."""

from __future__ import annotations

import httpx
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from reconscope.evidence.store import EvidenceStore
from reconscope.models import Base, Project
from reconscope.providers.cache import MemoryTTLCache
from reconscope.providers.dns import DnsAnswer, DnsStatus
from reconscope.providers.http import HttpClient
from reconscope.providers.services import ProviderServices


@pytest.fixture
def db_session(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'test.db'}", future=True)
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, expire_on_commit=False, future=True)
    session = factory()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def project(db_session):
    p = Project(name="Test Project")
    db_session.add(p)
    db_session.flush()
    return p


@pytest.fixture
def evidence_store(tmp_path):
    return EvidenceStore(tmp_path / "data")


class FakeResolver:
    """A deterministic DNS resolver for tests."""

    resolver_id = "fake-resolver"

    def __init__(self, answers=None, reverse=None):
        self._answers = answers or {}
        self._reverse = reverse or {}

    def query(self, name, rtype):
        return self._answers.get(
            (name, rtype),
            DnsAnswer(name, rtype, DnsStatus.NODATA, resolver=self.resolver_id),
        )

    def reverse(self, ip):
        return self._reverse.get(
            ip, DnsAnswer(ip, "PTR", DnsStatus.NODATA, resolver=self.resolver_id)
        )


def make_services(
    handler=None,
    resolver=None,
    cache=None,
    process_runner=None,
    nmap=None,
    tls_fetcher=None,
) -> ProviderServices:
    """Build ProviderServices whose HTTP client uses a MockTransport."""
    if handler is None:
        def handler(request):  # noqa: ANN001
            return httpx.Response(404)

    transport = httpx.MockTransport(handler)
    client = httpx.Client(transport=transport, follow_redirects=True)
    http = HttpClient(client=client, sleep=lambda _s: None)
    return ProviderServices(
        http=http,
        cache=cache or MemoryTTLCache(),
        resolver=resolver,
        process_runner=process_runner,
        nmap=nmap,
        tls_fetcher=tls_fetcher,
    )


# --- Active-module test doubles ------------------------------------------- #
from reconscope.jobs.process import ProcessResult  # noqa: E402
from reconscope.tools.capability import NmapCapability  # noqa: E402

SAMPLE_NMAP_XML = b"""<?xml version="1.0"?>
<nmaprun version="7.94">
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="203.0.113.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.6"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open" reason="syn-ack"/>
        <service name="http" product="nginx" version="1.25.4"/>
      </port>
      <port protocol="tcp" portid="443">
        <state state="filtered" reason="no-response"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


class FakeProcessRunner:
    """Records argv and returns a canned ProcessResult (no real subprocess)."""

    def __init__(self, stdout=b"", stderr=b"", timed_out=False, cancelled=False,
                 returncode=0):
        self.calls: list[list[str]] = []
        self._stdout = stdout
        self._stderr = stderr
        self._timed_out = timed_out
        self._cancelled = cancelled
        self._returncode = returncode

    def run(self, argv, *, timeout_s, output_limit=0, cancel=None, poll_interval=0.05):
        self.calls.append(list(argv))
        return ProcessResult(
            returncode=self._returncode,
            stdout=self._stdout,
            stderr=self._stderr,
            timed_out=self._timed_out,
            cancelled=self._cancelled,
            truncated=False,
            duration_s=0.01,
            argv=list(argv),
        )


def available_nmap() -> NmapCapability:
    return NmapCapability(available=True, path="nmap", version="7.94")
