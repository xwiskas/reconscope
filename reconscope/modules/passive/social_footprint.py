"""P14 — Public organization social footprint, baseline (PRD §6 P14).

Baseline is always available with no API key: it generates public-web search
suggestions for approved research subjects, and (when website evidence exists)
extracts social-profile links from it. It opens nothing and sends nothing on its
own — the user opens suggested searches manually in their normal browser.
"""

from __future__ import annotations

import json

from reconscope.education.manifest import LearningManifest, WorkedExample
from reconscope.findings.types import Confidence, NormalizedFinding
from reconscope.modules.passive.base import PassiveModule
from reconscope.modules.runtime import EvidenceBlob, ModuleRunResult, RunContext
from reconscope.social.footprint import (
    REGISTRY_VERSION,
    build_queries,
    extract_social_links,
)


class SocialFootprint(PassiveModule):
    module_id = "passive.social_footprint"
    module_version = "0.1.0"
    display_name = "Public social footprint"
    description = "Suggest public-web searches and extract social links (no login)."

    manifest = LearningManifest(
        module_id=module_id,
        version=module_version,
        what="Builds public-web search suggestions for an organization's social "
        "presence and, if website evidence exists, extracts social-profile links "
        "from it.",
        methodology_position="Passive OSINT: an organization's public presence "
        "can reveal products, technologies, locations, and contacts that inform "
        "later authorized work.",
        prerequisites="At least a domain or one approved research subject "
        "(organization name, product, or public handle).",
        interaction="passive",
        intensity="quiet",
        data_leaves_machine="Nothing automatically. You open suggested searches "
        "yourself; only then does a search engine or platform see the query.",
        observers="Whichever search engine or platform you choose to open a "
        "suggestion in can see the query, your account state, and your IP.",
        budget="No automatic requests; any number of manual searches you choose.",
        tool="Local query builder plus a local link extractor "
        f"(platform registry {REGISTRY_VERSION}).",
        options_explained="Queries are built only from the project domain and "
        "approved research subjects; broadening terms requires a new preview.",
        protocol_explanation="No protocol is used automatically; suggestions are "
        "ordinary search-engine URLs you may open in your browser.",
        result_states="suggested queries produced; social links extracted from "
        "existing evidence, if any.",
        attacker_relevance="Public profiles disclose staff-authored technology "
        "choices, events, and contact channels useful for context.",
        defender_relevance="Shows what your organization discloses publicly and "
        "where an impersonating profile might exist.",
        false_positives="An identical name or handle does NOT prove the same "
        "owner; matches are candidates pending manual validation.",
        limitations="Baseline uses only public information and never logs in, "
        "scrapes private data, or enumerates followers or an individual's graph.",
        safe_next_steps="Open a suggestion, capture the public URL as evidence, "
        "and record an evidence-based confidence label.",
        prohibited_next_steps="Do not log in, bypass CAPTCHAs, scrape private "
        "accounts, enumerate followers/friends, or profile individuals.",
        glossary_terms=("passive-recon",),
        worked_examples=(
            WorkedExample(
                scenario="Domain example.com, organization 'Example Inc'",
                expected="Per-platform site: search suggestions for the domain "
                "and organization name that you can open manually.",
            ),
        ),
        content_owner="ReconScope education",
        last_reviewed="2026-09-04",
    )

    def plan(self, ctx: RunContext) -> str:
        subjects = ctx.config.get("subjects") or []
        return (
            "Would generate public-web search suggestions for the domain and "
            f"{len(subjects)} approved research subject(s). No requests are sent."
        )

    def run(self, ctx: RunContext) -> ModuleRunResult:
        subjects = ctx.config.get("subjects") or []
        domain = ctx.target if ctx.config.get("use_target_as_domain", True) else None

        queries = build_queries(domain, subjects)
        findings: list[NormalizedFinding] = [
            NormalizedFinding(
                finding_type="social_query",
                value=q.url,
                confidence=Confidence.DERIVED_HINT,
                data={"platform": q.platform, "term": q.term, "dork": q.dork},
                source="social-footprint",
                evidence_name="social_queries.json",
            )
            for q in queries
        ]

        # If prior website evidence text was provided, extract social links.
        for link in extract_social_links(ctx.config.get("evidence_text", "")):
            findings.append(
                NormalizedFinding(
                    finding_type="social_link",
                    value=link["url"],
                    confidence=Confidence.DERIVED_HINT,
                    data={"platform": link["platform"], "label": "possible-candidate"},
                    source="social-footprint",
                )
            )

        evidence = [
            EvidenceBlob(
                name="social_queries.json",
                media_type="application/json",
                content=json.dumps(
                    [
                        {"platform": q.platform, "term": q.term, "url": q.url}
                        for q in queries
                    ],
                    indent=2,
                ).encode("utf-8"),
                provider="social-footprint",
            )
        ]

        return ModuleRunResult(
            status="succeeded",
            summary=f"Generated {len(queries)} search suggestion(s).",
            findings=findings,
            evidence=evidence,
            provider="social-footprint",
        )
