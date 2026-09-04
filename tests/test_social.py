"""Tests for the pure social-footprint helpers (PRD P14)."""

import pytest

from reconscope.social.footprint import (
    IdentityConfidence,
    build_queries,
    classify_confidence,
    extract_social_links,
)


def test_build_queries_only_uses_given_terms():
    queries = build_queries("example.com", [{"type": "product", "value": "WidgetPro"}])
    terms = {q.term for q in queries}
    assert terms == {"example.com", "WidgetPro"}


def test_extract_links_dedupes_and_identifies_platform():
    text = (
        "https://www.linkedin.com/company/example "
        "https://www.linkedin.com/company/example "
        "https://youtu.be/abc"
    )
    links = extract_social_links(text)
    platforms = {link["platform"] for link in links}
    assert platforms == {"linkedin", "youtube"}
    assert len(links) == 2  # linkedin de-duplicated


class TestConfidence:
    def test_confirmed_requires_official_link_out(self):
        assert (
            classify_confidence(
                official_site_links_to_profile=True,
                profile_links_to_in_scope_domain=False,
                weak_signal_match=False,
            )
            is IdentityConfidence.CONFIRMED
        )

    def test_name_only_is_at_most_possible(self):
        assert (
            classify_confidence(
                official_site_links_to_profile=False,
                profile_links_to_in_scope_domain=False,
                weak_signal_match=True,
            )
            is IdentityConfidence.POSSIBLE
        )

    def test_contradiction_rejects(self):
        assert (
            classify_confidence(
                official_site_links_to_profile=True,
                profile_links_to_in_scope_domain=True,
                weak_signal_match=True,
                contradicted=True,
            )
            is IdentityConfidence.REJECTED
        )


def test_no_terms_yields_no_queries():
    assert build_queries(None, []) == []


@pytest.mark.parametrize("bad", ["", None])
def test_extract_links_handles_empty(bad):
    assert extract_social_links(bad) == []
