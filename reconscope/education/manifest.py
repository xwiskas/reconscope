"""Learning Manifests (PRD §8.3).

Every module carries a versioned Learning Manifest. A module cannot be marked
release-ready until every required field is present and non-empty. The
:func:`validate_manifest` helper enforces that and is exercised by a contract
test over the whole registry, so an under-documented module fails CI.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class WorkedExample:
    """One worked example using documentation-only names (PRD §8.3)."""

    scenario: str
    expected: str


@dataclass(frozen=True)
class LearningManifest:
    module_id: str
    version: str
    # What / when / why.
    what: str
    methodology_position: str
    prerequisites: str
    # Traffic and privacy.
    interaction: str  # "passive" | "active"
    intensity: str  # "quiet" | "moderate" | "loud"
    data_leaves_machine: str
    observers: str
    # Budgets for the selected preset.
    budget: str
    # The real tool/library and its options.
    tool: str
    options_explained: str
    protocol_explanation: str
    # Result meanings and uncertainty.
    result_states: str
    attacker_relevance: str
    defender_relevance: str
    false_positives: str
    limitations: str
    # Guidance.
    safe_next_steps: str
    prohibited_next_steps: str
    glossary_terms: tuple[str, ...]
    worked_examples: tuple[WorkedExample, ...]
    # Ownership.
    content_owner: str
    last_reviewed: str  # ISO date
    references: tuple[str, ...] = field(default_factory=tuple)


# Fields that must be non-empty for a module to be release-ready.
_REQUIRED_STR_FIELDS = (
    "module_id", "version", "what", "methodology_position", "prerequisites",
    "interaction", "intensity", "data_leaves_machine", "observers", "budget",
    "tool", "options_explained", "protocol_explanation", "result_states",
    "attacker_relevance", "defender_relevance", "false_positives", "limitations",
    "safe_next_steps", "prohibited_next_steps", "content_owner", "last_reviewed",
)


def validate_manifest(manifest: LearningManifest) -> list[str]:
    """Return a list of problems; an empty list means release-ready."""
    problems: list[str] = []
    for name in _REQUIRED_STR_FIELDS:
        value = getattr(manifest, name)
        if not isinstance(value, str) or not value.strip():
            problems.append(f"missing or empty field: {name}")
    if not manifest.glossary_terms:
        problems.append("missing glossary_terms")
    if not manifest.worked_examples:
        problems.append("missing worked_examples")
    return problems
