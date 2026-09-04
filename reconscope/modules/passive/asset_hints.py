"""P5 — Derived asset hints (PRD §6 P5). Local classification, no network."""

from __future__ import annotations

from reconscope.education.manifest import LearningManifest, WorkedExample
from reconscope.findings.types import Confidence, NormalizedFinding
from reconscope.modules.passive.base import PassiveModule
from reconscope.modules.runtime import ModuleRunResult, RunContext

# (label token, category, explanation). Matched against dot-separated labels of
# a hostname. These are *hints* about naming, never confirmed environments.
_RULES: tuple[tuple[str, str, str], ...] = (
    ("dev", "development", "label 'dev' commonly denotes a development host"),
    ("develop", "development", "label 'develop' denotes a development host"),
    ("stg", "staging", "label 'stg' commonly denotes a staging host"),
    ("stage", "staging", "label 'stage' denotes a staging host"),
    ("staging", "staging", "label 'staging' denotes a staging host"),
    ("test", "testing", "label 'test' denotes a testing host"),
    ("qa", "testing", "label 'qa' denotes a quality-assurance host"),
    ("uat", "testing", "label 'uat' denotes a user-acceptance host"),
    ("admin", "administrative", "label 'admin' suggests an admin interface"),
    ("internal", "internal", "label 'internal' suggests non-public intent"),
    ("intranet", "internal", "label 'intranet' suggests internal intent"),
    ("vpn", "remote-access", "label 'vpn' suggests remote-access infrastructure"),
    ("jenkins", "ci-cd", "label 'jenkins' suggests a CI server"),
    ("gitlab", "ci-cd", "label 'gitlab' suggests a source/CI server"),
    ("jira", "internal-tooling", "label 'jira' suggests issue tracking"),
)


class AssetHints(PassiveModule):
    module_id = "passive.asset_hints"
    module_version = "0.1.0"
    display_name = "Derived asset hints"
    description = "Flag likely dev/staging/admin names among known hostnames."

    manifest = LearningManifest(
        module_id=module_id,
        version=module_version,
        what="Looks at hostnames already discovered (DNS, certificates) and "
        "flags names that commonly indicate non-production or administrative "
        "systems.",
        methodology_position="A local triage step after discovery: it helps "
        "prioritize which authorized hosts are interesting, before any active "
        "check.",
        prerequisites="A set of candidate hostnames from earlier passive steps.",
        interaction="passive",
        intensity="quiet",
        data_leaves_machine="Nothing — classification is entirely local.",
        observers="No one; no network request is made.",
        budget="No network requests.",
        tool="Local string rules.",
        options_explained="Each hint shows the exact naming rule that matched.",
        protocol_explanation="No protocol; hostnames are split into labels and "
        "compared against a small rule list.",
        result_states="hint produced, or no hint for a given name.",
        attacker_relevance="Non-production and admin systems are often weaker or "
        "less monitored, so their names draw attention.",
        defender_relevance="Highlights names that may expose non-production "
        "environments you did not intend to publish.",
        false_positives="A matching label does not prove the environment exists, "
        "is reachable, or is exposed; naming is a convention, not a fact.",
        limitations="Only recognizes common English naming tokens; custom "
        "naming will be missed.",
        safe_next_steps="Confirm any interesting name via DNS, and add it to "
        "scope only if you are authorized before an active check.",
        prohibited_next_steps="Do not add a hinted asset to active scope "
        "automatically or treat a hint as an exposure.",
        glossary_terms=("passive-recon", "dns"),
        worked_examples=(
            WorkedExample(
                scenario="Classify dev.example.com and admin.example.com",
                expected="'dev' → development hint; 'admin' → administrative hint.",
            ),
        ),
        content_owner="ReconScope education",
        last_reviewed="2026-09-04",
    )

    def plan(self, ctx: RunContext) -> str:
        count = len(ctx.config.get("candidates") or [ctx.target])
        return f"Would classify {count} hostname(s) using local naming rules."

    def run(self, ctx: RunContext) -> ModuleRunResult:
        candidates = ctx.config.get("candidates") or [ctx.target]
        findings: list[NormalizedFinding] = []
        for host in candidates:
            labels = str(host).lower().split(".")
            for token, category, explanation in _RULES:
                if token in labels:
                    findings.append(
                        NormalizedFinding(
                            finding_type="asset_hint",
                            value=str(host),
                            confidence=Confidence.DERIVED_HINT,
                            data={
                                "category": category,
                                "rule": f"label == '{token}'",
                                "explanation": explanation,
                            },
                            source="asset_hints",
                        )
                    )
                    break

        return ModuleRunResult(
            status="succeeded",
            summary=f"Produced {len(findings)} naming hint(s).",
            findings=findings,
            provider="local",
        )
