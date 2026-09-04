"""DNS resolver abstraction (PRD P2, P3).

The :class:`DnsResolver` protocol lets modules query records without depending
on a concrete library, and lets tests inject deterministic answers. The
:class:`DnspythonResolver` is the real implementation.

Every lookup returns a :class:`DnsAnswer` that distinguishes the outcomes the
PRD requires modules to tell apart: an answer, NXDOMAIN, no-data, timeout,
refused, and error.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol


class DnsStatus(str, Enum):
    OK = "ok"
    NXDOMAIN = "nxdomain"
    NODATA = "nodata"
    TIMEOUT = "timeout"
    REFUSED = "refused"
    ERROR = "error"


@dataclass(frozen=True)
class DnsAnswer:
    """The result of one (name, rtype) query."""

    name: str
    rtype: str
    status: DnsStatus
    records: tuple[str, ...] = field(default_factory=tuple)
    ttl: int | None = None
    resolver: str | None = None
    detail: str | None = None


class DnsResolver(Protocol):
    def query(self, name: str, rtype: str) -> DnsAnswer: ...
    def reverse(self, ip: str) -> DnsAnswer: ...

    @property
    def resolver_id(self) -> str: ...


class DnspythonResolver:
    """Real resolver backed by dnspython using the system resolver config."""

    def __init__(self, timeout: float = 5.0):
        import dns.resolver

        self._resolver = dns.resolver.Resolver()
        self._resolver.timeout = timeout
        self._resolver.lifetime = timeout
        servers = self._resolver.nameservers
        self._resolver_id = ",".join(servers) if servers else "system"

    @property
    def resolver_id(self) -> str:
        return self._resolver_id

    def query(self, name: str, rtype: str) -> DnsAnswer:
        import dns.resolver

        try:
            answer = self._resolver.resolve(name, rtype)
        except dns.resolver.NXDOMAIN:
            return DnsAnswer(name, rtype, DnsStatus.NXDOMAIN, resolver=self._resolver_id)
        except dns.resolver.NoAnswer:
            return DnsAnswer(name, rtype, DnsStatus.NODATA, resolver=self._resolver_id)
        except dns.resolver.LifetimeTimeout as exc:
            return DnsAnswer(
                name, rtype, DnsStatus.TIMEOUT, resolver=self._resolver_id,
                detail=str(exc),
            )
        except dns.resolver.NoNameservers as exc:
            return DnsAnswer(
                name, rtype, DnsStatus.REFUSED, resolver=self._resolver_id,
                detail=str(exc),
            )
        except Exception as exc:  # dnspython raises several leaf types
            return DnsAnswer(
                name, rtype, DnsStatus.ERROR, resolver=self._resolver_id,
                detail=str(exc),
            )
        records = tuple(sorted(r.to_text() for r in answer))
        return DnsAnswer(
            name,
            rtype,
            DnsStatus.OK,
            records=records,
            ttl=answer.rrset.ttl if answer.rrset is not None else None,
            resolver=self._resolver_id,
        )

    def reverse(self, ip: str) -> DnsAnswer:
        import dns.resolver
        import dns.reversename

        try:
            rev = dns.reversename.from_address(ip)
        except Exception as exc:
            return DnsAnswer(ip, "PTR", DnsStatus.ERROR, detail=str(exc))
        return self.query(rev.to_text(), "PTR")
