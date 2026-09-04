"""Shared base for passive modules."""

from __future__ import annotations

from reconscope.modules.contract import IntensityLabel, InteractionType
from reconscope.scope.canonical import TargetType


class PassiveModule:
    """Common defaults for passive modules (PRD §6): passive + quiet.

    Concrete modules set ``module_id``, ``module_version``, ``display_name``,
    ``description``, ``manifest``, and implement ``plan``/``run``.
    """

    interaction = InteractionType.PASSIVE
    intensity = IntensityLabel.QUIET
    accepted_target_types: tuple[TargetType, ...] = (TargetType.HOSTNAME,)
