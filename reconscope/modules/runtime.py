"""Runtime types shared by recon modules and the job runner (PRD §8, §12.3).

A module is a *pure producer*: given a :class:`RunContext` (target + injected
provider services), it returns a :class:`ModuleRunResult` carrying evidence
blobs and normalized findings. It does not touch the database, the gate, the
activity log, or the filesystem. The job runner performs those side effects.
This keeps modules trivial to unit-test with fake services and no network.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from reconscope.findings.types import NormalizedFinding
from reconscope.providers.services import ProviderServices
from reconscope.scope.canonical import TargetType


@dataclass(frozen=True)
class EvidenceBlob:
    """Raw evidence a module wants preserved. Written to disk by the runner."""

    name: str
    media_type: str
    content: bytes
    provider: str | None = None
    sensitive: bool = False


@dataclass(frozen=True)
class RunContext:
    """Everything a module needs to run one job against one target."""

    target: str
    target_type: TargetType
    services: ProviderServices
    config: dict = field(default_factory=dict)


@dataclass
class ModuleRunResult:
    """What a module returns. ``status`` follows the job state vocabulary."""

    status: str  # succeeded | partial | failed
    summary: str
    findings: list[NormalizedFinding] = field(default_factory=list)
    evidence: list[EvidenceBlob] = field(default_factory=list)
    provider: str | None = None
    error_code: str | None = None
    error_detail: str | None = None

    @property
    def ok(self) -> bool:
        return self.status in ("succeeded", "partial")

    @classmethod
    def failed(
        cls, summary: str, error_code: str, detail: str | None = None,
        provider: str | None = None,
    ) -> ModuleRunResult:
        return cls(
            status="failed",
            summary=summary,
            error_code=error_code,
            error_detail=detail,
            provider=provider,
        )
