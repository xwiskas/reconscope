"""Scope evaluation — the single authority for active-contact decisions.

Given a canonical target and the project's *enabled* scope entries, decide
whether an active job may contact the target. Fails closed: any error, unknown
type, or non-match results in ``allowed=False``.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from reconscope.scope.canonical import (
    CanonicalizationError,
    CanonicalScopeEntry,
    CanonicalTarget,
    EntryType,
    TargetType,
    canonicalize_target,
)


@dataclass(frozen=True)
class ScopeDecision:
    """The result of a scope evaluation.

    ``matched`` is the display form of the entry that authorized the target, or
    ``None`` when denied. ``reason`` is a stable, beginner-readable code.
    """

    allowed: bool
    reason: str
    matched_entry: str | None = None
    target: str | None = None


def _hostname_allowed(
    host: str, entries: Iterable[CanonicalScopeEntry]
) -> CanonicalScopeEntry | None:
    for entry in entries:
        if entry.type is EntryType.DOMAIN and host == entry.value:
            return entry
        if entry.type is EntryType.WILDCARD_DOMAIN:
            # Wildcard authorizes subdomains at any depth but NOT the apex
            # (PRD §4.3 rule 2). Requiring the "." + base suffix prevents a
            # look-alike like "example.com.evil.test" from matching.
            if host != entry.value and host.endswith("." + entry.value):
                return entry
    return None


def _ip_allowed(
    target: CanonicalTarget, entries: Iterable[CanonicalScopeEntry]
) -> CanonicalScopeEntry | None:
    addr = target.address
    if addr is None:  # pragma: no cover - guarded by canonicalize_target
        return None
    for entry in entries:
        if entry.type is EntryType.IP and entry.address == addr:
            return entry
        if entry.type is EntryType.CIDR and entry.network is not None:
            if entry.network.version == addr.version and addr in entry.network:
                return entry
    return None


def evaluate(
    raw_target: str,
    target_type: TargetType,
    enabled_entries: Iterable[CanonicalScopeEntry],
) -> ScopeDecision:
    """Evaluate whether ``raw_target`` is authorized by ``enabled_entries``.

    ``enabled_entries`` MUST already be filtered to *enabled* entries by the
    caller; a disabled entry never authorizes anything.
    """
    entries = list(enabled_entries)

    try:
        target = canonicalize_target(raw_target, target_type)
    except CanonicalizationError as exc:
        return ScopeDecision(
            allowed=False, reason=f"invalid_target: {exc}", matched_entry=None
        )

    if not entries:
        return ScopeDecision(
            allowed=False, reason="no_scope_entries", target=target.value
        )

    if target.type is TargetType.HOSTNAME:
        match = _hostname_allowed(target.value, entries)
    elif target.type is TargetType.IP:
        match = _ip_allowed(target, entries)
    else:  # pragma: no cover - TargetType is exhaustive
        return ScopeDecision(
            allowed=False, reason="unknown_target_type", target=target.value
        )

    if match is None:
        return ScopeDecision(
            allowed=False, reason="target_out_of_scope", target=target.value
        )

    return ScopeDecision(
        allowed=True,
        reason="in_scope",
        matched_entry=match.display,
        target=target.value,
    )
