"""Pure social-footprint helpers (PRD P14).

Nothing here makes a network request. Query generation produces *suggested*
public-web searches the user opens manually; link extraction scans HTML the app
has already collected; confidence classification is rule-based on evidence the
user records. No login scraping, no follower/graph enumeration, no person
profiling — those are out of the product boundary.
"""

from __future__ import annotations

import re
import urllib.parse
from dataclasses import dataclass
from enum import Enum

REGISTRY_VERSION = "2026-09-04.1"


@dataclass(frozen=True)
class Platform:
    key: str
    display_name: str
    # Host substrings that identify a profile URL for this platform.
    hosts: tuple[str, ...]
    # A site: dork target used when building a public-web search.
    site_dork: str
    policy_note: str


PLATFORMS: tuple[Platform, ...] = (
    Platform("facebook", "Facebook", ("facebook.com",), "facebook.com",
             "Use public pages only; do not access anything behind a login."),
    Platform("instagram", "Instagram", ("instagram.com",), "instagram.com",
             "Public profiles only; no login scraping."),
    Platform("linkedin", "LinkedIn", ("linkedin.com",), "linkedin.com/company",
             "Organization pages only; respect LinkedIn's terms."),
    Platform("x", "X (Twitter)", ("x.com", "twitter.com"), "x.com",
             "Public posts only; no automated collection."),
    Platform("github", "GitHub", ("github.com",), "github.com",
             "Public organization/repos only."),
    Platform("youtube", "YouTube", ("youtube.com", "youtu.be"), "youtube.com",
             "Public channels only."),
    Platform("reddit", "Reddit", ("reddit.com",), "reddit.com",
             "Public communities/posts only."),
    Platform("mastodon", "Mastodon", ("mastodon.",), "mastodon.social",
             "Public instances only; instance policies vary."),
)

_BY_HOST = [(host, p) for p in PLATFORMS for host in p.hosts]

_URL_RE = re.compile(r"https?://[^\s\"'<>)]+", re.IGNORECASE)


class IdentityConfidence(str, Enum):
    CONFIRMED = "confirmed-link"
    STRONG = "strong-candidate"
    POSSIBLE = "possible-candidate"
    REJECTED = "rejected-unrelated"


@dataclass(frozen=True)
class SuggestedQuery:
    platform: str
    term: str
    dork: str
    url: str


def _search_url(dork: str) -> str:
    # DuckDuckGo tends to avoid the interstitials Google shows for dorks.
    return "https://duckduckgo.com/?" + urllib.parse.urlencode({"q": dork})


def build_queries(
    domain: str | None,
    subjects: list[dict] | None = None,
) -> list[SuggestedQuery]:
    """Generate public-web search suggestions for approved research subjects.

    ``subjects`` is a list of ``{"type": ..., "value": ...}`` (organization,
    product, public_handle, public_profile_url). Only these approved terms and
    the project domain are used; the function never invents new people/terms.
    """
    terms: list[str] = []
    if domain:
        terms.append(domain)
    for subject in subjects or []:
        value = str(subject.get("value", "")).strip()
        if value:
            terms.append(value)

    queries: list[SuggestedQuery] = []
    seen: set[tuple[str, str]] = set()
    for term in terms:
        for platform in PLATFORMS:
            key = (platform.key, term)
            if key in seen:
                continue
            seen.add(key)
            dork = f'site:{platform.site_dork} "{term}"'
            queries.append(
                SuggestedQuery(
                    platform=platform.key,
                    term=term,
                    dork=dork,
                    url=_search_url(dork),
                )
            )
    return queries


def extract_social_links(text: str) -> list[dict]:
    """Extract known social-profile URLs from already-collected HTML/text.

    Returns de-duplicated ``{"platform", "url"}`` records. Makes no request.
    """
    found: dict[str, dict] = {}
    for match in _URL_RE.findall(text or ""):
        url = match.rstrip(".,);")
        lowered = url.lower()
        for host, platform in _BY_HOST:
            if host in lowered:
                found.setdefault(url, {"platform": platform.key, "url": url})
                break
    return sorted(found.values(), key=lambda r: (r["platform"], r["url"]))


def classify_confidence(
    *,
    official_site_links_to_profile: bool,
    profile_links_to_in_scope_domain: bool,
    weak_signal_match: bool,
    contradicted: bool = False,
) -> IdentityConfidence:
    """Classify how strongly a profile is tied to the organization (PRD P14).

    Evidence-based only: an identical handle or name alone is never enough for
    a confirmed link.
    """
    if contradicted:
        return IdentityConfidence.REJECTED
    if official_site_links_to_profile:
        return IdentityConfidence.CONFIRMED
    if profile_links_to_in_scope_domain:
        return IdentityConfidence.STRONG
    if weak_signal_match:
        return IdentityConfidence.POSSIBLE
    return IdentityConfidence.REJECTED
