"""Reconnaissance module contract, registry, and the authorization gate."""

from reconscope.modules.contract import (
    IntensityLabel,
    InteractionType,
    ModuleContext,
    ModuleResult,
    ReconModule,
)
from reconscope.modules.gate import GateDecision, ProjectAuthorization, authorize_job

__all__ = [
    "InteractionType",
    "IntensityLabel",
    "ModuleContext",
    "ModuleResult",
    "ReconModule",
    "GateDecision",
    "ProjectAuthorization",
    "authorize_job",
]
