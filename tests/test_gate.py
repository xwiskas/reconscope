"""Authorization-gate tests — the M0 exit criterion (PRD §4.2, §16.1).

"A test module can run only against an authorized in-scope target."
"""

import pytest

from reconscope.modules.contract import (
    IntensityLabel,
    InteractionType,
    ModuleContext,
    ModuleResult,
)
from reconscope.modules.echo import ConnectivityEcho, GateBlockedError, run_gated
from reconscope.modules.gate import ProjectAuthorization, authorize_job
from reconscope.scope.canonical import TargetType, canonicalize_scope_entry


class _PassiveStub:
    module_id = "test.passive"
    module_version = "0.1.0"
    display_name = "passive stub"
    description = "passive test module"
    interaction = InteractionType.PASSIVE
    intensity = IntensityLabel.QUIET
    accepted_target_types = (TargetType.HOSTNAME, TargetType.IP)

    def plan(self, ctx):  # pragma: no cover - trivial
        return "passive"

    def run(self, ctx):
        return ModuleResult(self.module_id, True, "ok")


def _authz(attested, *entries):
    return ProjectAuthorization.build(
        attestation_current=attested,
        enabled_entries=[canonicalize_scope_entry(e) for e in entries],
    )


def _ctx(target, ttype=TargetType.HOSTNAME):
    return ModuleContext(target=target, target_type=ttype)


class TestActiveGate:
    def test_blocked_without_attestation(self):
        d = authorize_job(
            ConnectivityEcho(), _ctx("example.com"), _authz(False, "example.com")
        )
        assert not d.allowed
        assert d.reason == "authorization_missing"

    def test_blocked_without_scope_entries(self):
        d = authorize_job(ConnectivityEcho(), _ctx("example.com"), _authz(True))
        assert not d.allowed
        assert d.reason == "no_scope_entries"

    def test_blocked_when_out_of_scope(self):
        d = authorize_job(
            ConnectivityEcho(), _ctx("evil.test"), _authz(True, "example.com")
        )
        assert not d.allowed
        assert d.reason == "target_out_of_scope"

    def test_allowed_when_attested_and_in_scope(self):
        d = authorize_job(
            ConnectivityEcho(), _ctx("example.com"), _authz(True, "example.com")
        )
        assert d.allowed
        assert d.matched_entry == "example.com"

    def test_unsupported_target_type_blocked(self):
        class OnlyHost(ConnectivityEcho):
            accepted_target_types = (TargetType.HOSTNAME,)

        d = authorize_job(
            OnlyHost(), _ctx("203.0.113.1", TargetType.IP), _authz(True, "203.0.113.1")
        )
        assert not d.allowed
        assert d.reason.startswith("target_type_not_supported")


class TestPassiveGate:
    def test_passive_allowed_without_attestation_or_scope(self):
        d = authorize_job(_PassiveStub(), _ctx("example.com"), _authz(False))
        assert d.allowed
        assert d.reason == "passive_module"


class TestRunGated:
    def test_run_gated_executes_when_allowed(self):
        result = run_gated(
            ConnectivityEcho(), _ctx("example.com"), _authz(True, "example.com")
        )
        assert isinstance(result, ModuleResult)
        assert result.ok
        assert result.data["target"] == "example.com"

    def test_run_gated_raises_when_blocked(self):
        with pytest.raises(GateBlockedError):
            run_gated(
                ConnectivityEcho(), _ctx("evil.test"), _authz(True, "example.com")
            )
