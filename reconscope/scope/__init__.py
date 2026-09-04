"""The scope subsystem: the single authority for active-contact decisions.

Nothing outside this package should decide whether an active action may touch a
target. Import :func:`reconscope.scope.service.evaluate` and the canonicalizers
here rather than re-implementing any comparison.
"""

from reconscope.scope.canonical import (
    CanonicalizationError,
    CanonicalScopeEntry,
    CanonicalTarget,
    EntryType,
    TargetType,
    canonicalize_scope_entry,
    canonicalize_target,
)
from reconscope.scope.service import ScopeDecision, evaluate

__all__ = [
    "CanonicalScopeEntry",
    "CanonicalTarget",
    "CanonicalizationError",
    "EntryType",
    "TargetType",
    "ScopeDecision",
    "canonicalize_scope_entry",
    "canonicalize_target",
    "evaluate",
]
