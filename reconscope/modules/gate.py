"""The job authorization gate (PRD §4.2, §4.4, §12.3).

The gate is the choke point every job passes through before it may run. For an
**active** module it requires, in order:

1. A current authorization attestation on the project.
2. At least one enabled scope entry.
3. The target matching an enabled scope entry (via the scope service).

**Passive** modules do not require an attestation or scope match (they query
third parties, not the target directly), but they still pass through the gate so
that all execution is funnelled through one place.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from reconscope.modules.contract import InteractionType, ModuleContext, ReconModule
from reconscope.scope.canonical import CanonicalScopeEntry
from reconscope.scope.service import ScopeDecision, evaluate


@dataclass(frozen=True)
class ProjectAuthorization:
    """The authorization state of a project at the moment a job is requested.

    ``attestation_current`` is True only when the user has an accepted, not-yet
    invalidated attestation (PRD §4.2). ``enabled_entries`` are the project's
    enabled scope entries, already canonicalized.
    """

    attestation_current: bool
    enabled_entries: tuple[CanonicalScopeEntry, ...]

    @classmethod
    def build(
        cls,
        attestation_current: bool,
        enabled_entries: Iterable[CanonicalScopeEntry],
    ) -> ProjectAuthorization:
        return cls(
            attestation_current=attestation_current,
            enabled_entries=tuple(enabled_entries),
        )


@dataclass(frozen=True)
class GateDecision:
    """Outcome of the gate check."""

    allowed: bool
    reason: str
    scope: ScopeDecision | None = None

    @property
    def matched_entry(self) -> str | None:
        return self.scope.matched_entry if self.scope else None


def authorize_job(
    module: ReconModule,
    ctx: ModuleContext,
    authz: ProjectAuthorization,
) -> GateDecision:
    """Decide whether ``module`` may run against ``ctx.target``.

    This function is pure and side-effect free so it can be unit-tested in
    isolation and called both by the API layer and by the job supervisor
    immediately before ``run()``.
    """
    if ctx.target_type not in module.accepted_target_types:
        return GateDecision(
            allowed=False,
            reason=f"target_type_not_supported: {ctx.target_type.value}",
        )

    if module.interaction is InteractionType.PASSIVE:
        return GateDecision(allowed=True, reason="passive_module")

    # From here down: active module. All three conditions are mandatory.
    if not authz.attestation_current:
        return GateDecision(allowed=False, reason="authorization_missing")

    if not authz.enabled_entries:
        return GateDecision(allowed=False, reason="no_scope_entries")

    scope = evaluate(ctx.target, ctx.target_type, authz.enabled_entries)
    if not scope.allowed:
        return GateDecision(allowed=False, reason=scope.reason, scope=scope)

    return GateDecision(allowed=True, reason="in_scope", scope=scope)
