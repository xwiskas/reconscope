"""Public-organization social-footprint logic (PRD P14).

Pure, network-free helpers: a versioned platform registry, public-web query
generation, social-link extraction from existing evidence, and evidence-based
identity-confidence classification. The passive module wraps these; keeping them
here makes them unit-testable and reusable.
"""

from reconscope.social.footprint import (
    PLATFORMS,
    REGISTRY_VERSION,
    IdentityConfidence,
    Platform,
    build_queries,
    classify_confidence,
    extract_social_links,
)

__all__ = [
    "PLATFORMS",
    "REGISTRY_VERSION",
    "IdentityConfidence",
    "Platform",
    "build_queries",
    "classify_confidence",
    "extract_social_links",
]
