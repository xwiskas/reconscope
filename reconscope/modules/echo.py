"""A minimal active test module used to prove the M0 safety boundary.

``ConnectivityEcho`` performs no real network activity in M0. Its only purpose
is to be an *active* module that the gate must authorize before ``run()`` may be
reached. The M0 exit criterion — "a test module can run only against an
authorized in-scope target" — is demonstrated with this module plus
:func:`run_gated`.
"""

from __future__ import annotations

from reconscope.modules.contract import (
    IntensityLabel,
    InteractionType,
    ModuleContext,
    ModuleResult,
    ReconModule,
)
from reconscope.modules.gate import GateDecision, ProjectAuthorization, authorize_job
from reconscope.scope.canonical import TargetType


class GateBlockedError(PermissionError):
    """Raised when code attempts to run a module the gate did not authorize."""

    def __init__(self, decision: GateDecision):
        self.decision = decision
        super().__init__(f"blocked by gate: {decision.reason}")


class ConnectivityEcho:
    """An active no-op module for exercising the authorization gate."""

    module_id = "test.connectivity_echo"
    module_version = "0.1.0"
    display_name = "Connectivity echo (test)"
    description = "Test-only active module used to verify scope enforcement."
    interaction = InteractionType.ACTIVE
    intensity = IntensityLabel.QUIET
    accepted_target_types = (TargetType.HOSTNAME, TargetType.IP)

    def plan(self, ctx: ModuleContext) -> str:
        return (
            f"Would perform an active connectivity check against {ctx.target!r} "
            f"({ctx.target_type.value}). No traffic is sent in Milestone 0."
        )

    def run(self, ctx: ModuleContext) -> ModuleResult:
        return ModuleResult(
            module_id=self.module_id,
            ok=True,
            summary=f"echo ok for {ctx.target}",
            data={"target": ctx.target, "target_type": ctx.target_type.value},
        )


def run_gated(
    module: ReconModule,
    ctx: ModuleContext,
    authz: ProjectAuthorization,
) -> ModuleResult:
    """Authorize then run a module, raising if the gate blocks it.

    This is the ONLY sanctioned way to execute a module: the gate is checked
    immediately before ``run()``. In later milestones the job supervisor plays
    this role (with cancellation, timeouts, and evidence capture); the contract
    is identical.
    """
    decision = authorize_job(module, ctx, authz)
    if not decision.allowed:
        raise GateBlockedError(decision)
    return module.run(ctx)
