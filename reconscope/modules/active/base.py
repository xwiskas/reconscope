"""Shared base for active modules."""

from __future__ import annotations

from reconscope.modules.contract import IntensityLabel, InteractionType
from reconscope.scope.canonical import TargetType


class ActiveModule:
    """Common defaults for active modules (PRD §7)."""

    interaction = InteractionType.ACTIVE
    intensity = IntensityLabel.MODERATE
    accepted_target_types: tuple[TargetType, ...] = (
        TargetType.HOSTNAME,
        TargetType.IP,
    )
    # Whether the module contacts the pinned IP (network-level tools) or the
    # requested host (where vhost/SNI matters). See ActiveJobRunner.
    contact_target: str = "ip"
