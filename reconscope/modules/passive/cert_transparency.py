"""P4 — Certificate-transparency search via crt.sh (PRD §6 P4)."""

from __future__ import annotations

import json

from reconscope.education.manifest import LearningManifest, WorkedExample
from reconscope.findings.types import Confidence, NormalizedFinding
from reconscope.modules.passive.base import PassiveModule
from reconscope.modules.runtime import EvidenceBlob, ModuleRunResult, RunContext
from reconscope.providers.http import ProviderError
from reconscope.scope.canonical import CanonicalizationError, canonical_domain

_PROVIDER = "crt.sh"
_CACHE_TTL = 24 * 60 * 60  # 24 hours (PRD P4)


class CertTransparency(PassiveModule):
    module_id = "passive.cert_transparency"
    module_version = "0.1.0"
    display_name = "Certificate transparency"
    description = "Find candidate subdomains from public certificate logs (crt.sh)."

    manifest = LearningManifest(
        module_id=module_id,
        version=module_version,
        what="Searches public certificate-transparency logs (via crt.sh) for "
        "certificate names that mention the domain, yielding candidate hostnames.",
        methodology_position="A high-value passive discovery step: certificates "
        "are logged publicly, so they reveal subdomains without touching the "
        "target.",
        prerequisites="A domain seed target.",
        interaction="passive",
        intensity="quiet",
        data_leaves_machine="The domain you search for is sent to crt.sh.",
        observers="crt.sh (and its network path) sees your query and IP.",
        budget="One search request, cached for 24 hours; 30s timeout, one retry.",
        tool="crt.sh JSON endpoint over HTTPS.",
        options_explained="The query uses a wildcard (%25.domain) to match names "
        "under the domain; results are normalized and de-duplicated locally.",
        protocol_explanation="A single HTTPS GET returns JSON rows, each with "
        "certificate name value(s) that may include several names and wildcards.",
        result_states="candidate hostnames found, no results, or a provider "
        "error/outage (which fails only this module).",
        attacker_relevance="Certificates frequently disclose internal or "
        "forgotten subdomains that widen the attack surface.",
        defender_relevance="Shows what names your organization has certificates "
        "for — useful for finding forgotten or shadow assets.",
        false_positives="A logged name may no longer resolve, may belong to a "
        "different owner, or may be a wildcard; names are candidates, not "
        "confirmed live hosts.",
        limitations="Coverage depends on which logs crt.sh indexes; very large "
        "domains may be truncated.",
        safe_next_steps="Review candidates and add only authorized ones to scope "
        "before any active check.",
        prohibited_next_steps="Do not resolve or connect to candidates as part "
        "of this passive step, and do not add them to active scope automatically.",
        glossary_terms=("certificate-transparency", "san", "passive-recon"),
        worked_examples=(
            WorkedExample(
                scenario="Search example.com",
                expected="A de-duplicated list of candidate hostnames such as "
                "www.example.com and any subdomains that appeared in certificates.",
            ),
        ),
        content_owner="ReconScope education",
        last_reviewed="2026-09-04",
        references=("https://crt.sh/",),
    )

    def plan(self, ctx: RunContext) -> str:
        return (
            f"Would search crt.sh for certificate names under {ctx.target!r} "
            "and list de-duplicated candidate hostnames."
        )

    def run(self, ctx: RunContext) -> ModuleRunResult:
        domain = ctx.target
        cache = ctx.services.cache
        cache_key = f"{_PROVIDER}:{domain}"

        rows = cache.get(cache_key)
        cached = rows is not None
        if not cached:
            try:
                rows = ctx.services.http.get_json(
                    _PROVIDER,
                    "https://crt.sh/",
                    params={"q": f"%.{domain}", "output": "json"},
                )
            except ProviderError as exc:
                return ModuleRunResult.failed(
                    f"crt.sh could not be queried ({exc.code}).",
                    error_code=exc.code,
                    detail=exc.detail,
                    provider=_PROVIDER,
                )
            if not isinstance(rows, list):
                rows = []
            cache.set(cache_key, rows, _CACHE_TTL)

        candidates: dict[str, dict] = {}
        for row in rows:
            names_field = (row or {}).get("name_value", "")
            common = (row or {}).get("common_name", "")
            for raw_name in list(str(names_field).split("\n")) + [str(common)]:
                raw_name = raw_name.strip()
                if not raw_name:
                    continue
                is_wildcard = raw_name.startswith("*.")
                base = raw_name[2:] if is_wildcard else raw_name
                try:
                    canonical = canonical_domain(base)
                except CanonicalizationError:
                    continue
                entry = candidates.setdefault(
                    canonical, {"wildcard": False}
                )
                if is_wildcard:
                    entry["wildcard"] = True

        findings = [
            NormalizedFinding(
                finding_type="candidate_hostname",
                value=name,
                confidence=Confidence.DERIVED_HINT,
                data={"wildcard": meta["wildcard"], "label": "provider-asserted"},
                source=_PROVIDER,
                evidence_name="crtsh.json",
            )
            for name, meta in sorted(candidates.items())
        ]

        evidence = [
            EvidenceBlob(
                name="crtsh.json",
                media_type="application/json",
                content=json.dumps(rows, indent=2).encode("utf-8"),
                provider=_PROVIDER,
            )
        ]

        note = " (from cache)" if cached else ""
        return ModuleRunResult(
            status="succeeded",
            summary=f"Found {len(findings)} candidate hostname(s){note}.",
            findings=findings,
            evidence=evidence,
            provider=_PROVIDER,
        )
