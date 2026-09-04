"""The module contract every recon module implements (PRD §12.3).

Milestone 0 defines the contract and a single test module. Later milestones add
real passive/active modules that implement this same interface. The contract
deliberately separates *declaring* what a module will do (``plan``) from
*doing* it (``run``), so the job layer can enforce scope after ``plan`` and
immediately before ``run`` for every active module — a module can never mark
itself exempt.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Protocol, runtime_checkable

from reconscope.scope.canonical import TargetType


class InteractionType(str, Enum):
    """Whether the module intentionally creates target-directed traffic."""

    PASSIVE = "passive"
    ACTIVE = "active"


class IntensityLabel(str, Enum):
    """Plain-language estimate of request volume / detectability (PRD §4.5)."""

    QUIET = "quiet"
    MODERATE = "moderate"
    LOUD = "loud"


@dataclass(frozen=True)
class ModuleContext:
    """Everything a module needs to plan/run one job against one target."""

    target: str
    target_type: TargetType
    config: dict = field(default_factory=dict)


@dataclass
class ModuleResult:
    """A minimal result envelope for M0. Real evidence/findings arrive in M1+."""

    module_id: str
    ok: bool
    summary: str
    data: dict = field(default_factory=dict)


@runtime_checkable
class ReconModule(Protocol):
    """Structural contract for a reconnaissance module.

    Concrete modules are registered in the module registry. Only the members
    needed for the M0 safety boundary are required here; the full manifest and
    ``parse()`` (normalized findings) are introduced with real modules later.
    """

    module_id: str
    module_version: str
    display_name: str
    description: str
    interaction: InteractionType
    intensity: IntensityLabel
    accepted_target_types: tuple[TargetType, ...]

    def plan(self, ctx: ModuleContext) -> str:
        """Return a human-readable preview of what running would do."""
        ...

    def run(self, ctx: ModuleContext) -> ModuleResult:
        """Execute the (already-authorized) job and return a result."""
        ...
