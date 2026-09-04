"""Value types for normalized findings (PRD §8.1)."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class Confidence(str, Enum):
    """How strongly a finding is supported by its evidence (PRD §8.1)."""

    CONFIRMED_BY_RESPONSE = "confirmed-by-response"
    TOOL_INFERRED = "tool-inferred"
    DERIVED_HINT = "derived-hint"


@dataclass(frozen=True)
class NormalizedFinding:
    """A single normalized observation a module produces.

    The runner persists these; modules never touch the database. ``value`` is
    the primary normalized string (a hostname, a record, a field name); ``data``
    carries structured extras. ``source`` names the provider/tool so provenance
    is preserved even when several sources report the same value.
    """

    finding_type: str
    value: str
    confidence: Confidence
    data: dict = field(default_factory=dict)
    source: str | None = None
    # Which evidence blob (by its ``name``) backs this finding, if any.
    evidence_name: str | None = None
