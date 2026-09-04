"""Canonicalization of scope entries and job targets (PRD §4.3, §4.4, §16.2).

This module is **safety-critical**. Every value that will be compared for scope
must pass through here so that equivalent notations collapse to one canonical
form and cannot be used to bypass a scope check.

Design rules:

* Canonicalization is *strict*: ambiguous or unusual encodings are rejected
  rather than guessed at. A rejected value is treated by the scope service as
  "not in scope" (fail closed), so strictness never widens access.
* The same functions canonicalize both stored scope entries and the live job
  target, so alternate notations on either side collapse identically.
* No network access happens here. DNS resolution/pinning is a separate,
  logged step performed by the job layer (PRD §4.4).
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum

import idna

# PRD §4.3 rule 5: reject CIDRs broader than these prefixes to limit accidental
# breadth. A *smaller* prefix number means a *larger* range, so we reject any
# prefix length below the floor.
MIN_IPV4_PREFIX = 16
MIN_IPV6_PREFIX = 112

# Characters that must never appear in a domain/host value we accept. These are
# common vectors for smuggling a different destination past a naive check.
_FORBIDDEN_HOST_SUBSTRINGS = ("/", "\\", "@", "?", "#", " ", "\t", "%")

_MAX_DOMAIN_LENGTH = 253


class EntryType(str, Enum):
    """The kind of authorization a scope entry grants."""

    DOMAIN = "domain"  # exact hostname only
    WILDCARD_DOMAIN = "wildcard_domain"  # subdomains, not the apex
    IP = "ip"
    CIDR = "cidr"


class TargetType(str, Enum):
    """The kind of thing an active job wants to contact."""

    HOSTNAME = "hostname"
    IP = "ip"


class CanonicalizationError(ValueError):
    """Raised when a value cannot be turned into a safe canonical form."""


@dataclass(frozen=True)
class CanonicalScopeEntry:
    """A scope entry reduced to its canonical, comparable form.

    ``value`` is the canonical string (ASCII/IDNA domain, or compressed IP/CIDR).
    ``network`` / ``address`` hold parsed objects for IP-family entries so the
    scope service can do containment checks without re-parsing.
    """

    type: EntryType
    value: str
    display: str  # the value as the user originally entered it (for the UI)
    address: ipaddress._BaseAddress | None = None
    network: ipaddress._BaseNetwork | None = None


@dataclass(frozen=True)
class CanonicalTarget:
    """A job target reduced to its canonical, comparable form."""

    type: TargetType
    value: str
    display: str
    address: ipaddress._BaseAddress | None = None


# --------------------------------------------------------------------------- #
# Primitive canonicalizers
# --------------------------------------------------------------------------- #
def canonical_domain(raw: str) -> str:
    """Return the canonical ASCII (IDNA) form of a domain/hostname.

    Lowercases, strips a single trailing dot, applies UTS-46/IDNA mapping so
    internationalized domains and mixed-case forms collapse, and validates the
    label structure. Raises :class:`CanonicalizationError` for anything unsafe
    or ambiguous.
    """
    if raw is None:
        raise CanonicalizationError("domain is empty")

    value = raw.strip()
    if not value:
        raise CanonicalizationError("domain is empty")

    # Reject control characters outright.
    if any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in value):
        raise CanonicalizationError("domain contains control characters")

    # Reject anything that smells like a URL, userinfo, port, or path. A scope
    # domain is a bare hostname only (PRD §4.3 rule 6).
    lowered = value.lower()
    for bad in _FORBIDDEN_HOST_SUBSTRINGS:
        if bad in lowered:
            raise CanonicalizationError(
                f"domain must be a bare hostname (found {bad!r})"
            )
    if ":" in lowered:
        # A colon means a port or an IPv6 literal, neither of which is a domain.
        raise CanonicalizationError("domain must not contain ':' (no port/IPv6)")

    # Strip exactly one trailing dot (the DNS root); reject doubled dots.
    if lowered.endswith("."):
        lowered = lowered[:-1]
    if ".." in lowered or lowered.startswith(".") or not lowered:
        raise CanonicalizationError("domain has empty labels")

    if len(lowered) > _MAX_DOMAIN_LENGTH:
        raise CanonicalizationError("domain is too long")

    try:
        # uts46=True performs case-folding and NFC/compatibility mapping so that
        # e.g. "BÜCHER.example" and "bücher.example" map to the same ASCII form.
        ascii_bytes = idna.encode(lowered, uts46=True, std3_rules=True)
    except idna.IDNAError as exc:  # pragma: no cover - message varies by input
        raise CanonicalizationError(f"invalid domain: {exc}") from exc

    canonical = ascii_bytes.decode("ascii").lower()

    labels = canonical.split(".")
    if len(labels) < 2:
        raise CanonicalizationError("domain must have at least two labels")
    if any(not label for label in labels):
        raise CanonicalizationError("domain has empty labels")

    return canonical


def canonical_ip(raw: str) -> ipaddress._BaseAddress:
    """Return a canonical IP address object.

    Rejects ambiguous forms (leading zeros, integer/hex encodings) by relying on
    the strict parser in the stdlib. Folds IPv4-mapped IPv6 (``::ffff:a.b.c.d``)
    down to the IPv4 address so a v4 scope entry consistently governs it.
    """
    if raw is None:
        raise CanonicalizationError("IP is empty")

    value = raw.strip()
    if not value:
        raise CanonicalizationError("IP is empty")

    # Allow (and strip) a single pair of brackets around an IPv6 literal.
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]

    if "/" in value:
        raise CanonicalizationError("expected a single IP, not a CIDR range")
    if "%" in value:
        raise CanonicalizationError("IPv6 zone identifiers are not accepted")

    try:
        addr = ipaddress.ip_address(value)
    except ValueError as exc:
        # The stdlib rejects leading-zero IPv4 and non-dotted integer forms,
        # which is exactly the ambiguity we want to refuse.
        raise CanonicalizationError(f"invalid IP address: {exc}") from exc

    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    return addr


def canonical_cidr(raw: str) -> ipaddress._BaseNetwork:
    """Return a canonical IP network, enforcing the breadth floor (PRD §4.3.5)."""
    if raw is None or not raw.strip():
        raise CanonicalizationError("CIDR is empty")

    value = raw.strip()
    if "/" not in value:
        raise CanonicalizationError("expected a CIDR (missing '/')")
    if "%" in value:
        raise CanonicalizationError("IPv6 zone identifiers are not accepted")

    try:
        # strict=False lets a user write 192.168.1.5/24; we normalize to the
        # network address for storage/comparison.
        network = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        raise CanonicalizationError(f"invalid CIDR: {exc}") from exc

    if network.version == 4 and network.prefixlen < MIN_IPV4_PREFIX:
        raise CanonicalizationError(
            f"IPv4 CIDR is too broad; /{MIN_IPV4_PREFIX} is the widest allowed"
        )
    if network.version == 6 and network.prefixlen < MIN_IPV6_PREFIX:
        raise CanonicalizationError(
            f"IPv6 CIDR is too broad; /{MIN_IPV6_PREFIX} is the widest allowed"
        )

    return network


# --------------------------------------------------------------------------- #
# High-level canonicalizers
# --------------------------------------------------------------------------- #
def canonicalize_scope_entry(raw: str) -> CanonicalScopeEntry:
    """Detect the entry type from ``raw`` and canonicalize it.

    Accepted forms (PRD §4.3): ``example.com``, ``*.example.com``, an IPv4/IPv6
    address, or an IPv4/IPv6 CIDR.
    """
    if raw is None:
        raise CanonicalizationError("scope entry is empty")
    display = raw.strip()
    if not display:
        raise CanonicalizationError("scope entry is empty")

    if display.startswith("*."):
        base = canonical_domain(display[2:])
        return CanonicalScopeEntry(
            type=EntryType.WILDCARD_DOMAIN, value=base, display=display
        )

    if "/" in display:
        network = canonical_cidr(display)
        return CanonicalScopeEntry(
            type=EntryType.CIDR,
            value=str(network),
            display=display,
            network=network,
        )

    # Try IP before domain: an IP literal is never a valid domain and vice versa.
    try:
        addr = canonical_ip(display)
    except CanonicalizationError:
        addr = None
    if addr is not None:
        return CanonicalScopeEntry(
            type=EntryType.IP, value=str(addr), display=display, address=addr
        )

    base = canonical_domain(display)
    return CanonicalScopeEntry(type=EntryType.DOMAIN, value=base, display=display)


def canonicalize_target(raw: str, target_type: TargetType) -> CanonicalTarget:
    """Canonicalize a live job target of the given type."""
    display = (raw or "").strip()
    if target_type is TargetType.IP:
        addr = canonical_ip(display)
        return CanonicalTarget(
            type=TargetType.IP, value=str(addr), display=display, address=addr
        )
    if target_type is TargetType.HOSTNAME:
        value = canonical_domain(display)
        return CanonicalTarget(type=TargetType.HOSTNAME, value=value, display=display)
    raise CanonicalizationError(f"unknown target type: {target_type!r}")
