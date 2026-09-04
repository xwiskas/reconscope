"""P3 — Reverse DNS lookup (PRD §6 P3)."""

from __future__ import annotations

from reconscope.education.manifest import LearningManifest, WorkedExample
from reconscope.findings.types import Confidence, NormalizedFinding
from reconscope.modules.passive.base import PassiveModule
from reconscope.modules.runtime import EvidenceBlob, ModuleRunResult, RunContext
from reconscope.providers.dns import DnsStatus
from reconscope.scope.canonical import TargetType


class ReverseDns(PassiveModule):
    module_id = "passive.reverse_dns"
    module_version = "0.1.0"
    display_name = "Reverse DNS (PTR)"
    description = "Look up the PTR record(s) for an IP address."
    accepted_target_types = (TargetType.IP,)

    manifest = LearningManifest(
        module_id=module_id,
        version=module_version,
        what="Asks the resolver for the PTR record(s) mapping an IP back to a "
        "name.",
        methodology_position="Passive enrichment of an IP: a PTR can hint at "
        "the operator or service naming, but is operator-controlled.",
        prerequisites="An IP address (e.g. from a DNS A/AAAA record).",
        interaction="passive",
        intensity="quiet",
        data_leaves_machine="The IP address you look up.",
        observers="Your configured recursive resolver.",
        budget="One reverse lookup per run.",
        tool="Python resolver (dnspython).",
        options_explained="No options; a single PTR query for the address.",
        protocol_explanation="The IP is converted to a reverse-zone name "
        "(in-addr.arpa / ip6.arpa) and queried for PTR records.",
        result_states="ok (names returned), nodata, nxdomain, timeout, error.",
        attacker_relevance="Names can reveal hosting providers or internal "
        "naming conventions.",
        defender_relevance="Confirms what reverse names are published for your "
        "addresses.",
        false_positives="PTR is set by whoever controls the reverse zone and "
        "need not match forward DNS; it is a hint, not identity proof.",
        limitations="Many addresses have no PTR, or a generic provider PTR.",
        safe_next_steps="Cross-check any name against forward DNS and "
        "certificate data before trusting it.",
        prohibited_next_steps="Do not treat a PTR name as authorization to "
        "contact that host.",
        glossary_terms=("ptr", "dns", "passive-recon"),
        worked_examples=(
            WorkedExample(
                scenario="Reverse-lookup a documentation address",
                expected="Either a provider PTR name or a 'no data' result.",
            ),
        ),
        content_owner="ReconScope education",
        last_reviewed="2026-09-04",
    )

    def plan(self, ctx: RunContext) -> str:
        return f"Would look up the PTR record(s) for {ctx.target!r}."

    def run(self, ctx: RunContext) -> ModuleRunResult:
        resolver = ctx.services.resolver
        if resolver is None:
            return ModuleRunResult.failed(
                "No DNS resolver is configured.", "resolver_unavailable"
            )

        answer = resolver.reverse(ctx.target)
        lines = [f"PTR for {ctx.target}: {answer.status.value}"]
        findings: list[NormalizedFinding] = []
        for name in answer.records:
            lines.append(f"    {name}")
            findings.append(
                NormalizedFinding(
                    finding_type="ptr_name",
                    value=name.rstrip("."),
                    confidence=Confidence.CONFIRMED_BY_RESPONSE,
                    data={"ttl": answer.ttl},
                    source=answer.resolver or resolver.resolver_id,
                    evidence_name="reverse_dns.txt",
                )
            )
        if answer.detail:
            lines.append(f"    ! {answer.detail}")

        evidence = [
            EvidenceBlob(
                name="reverse_dns.txt",
                media_type="text/plain",
                content="\n".join(lines).encode("utf-8"),
                provider=resolver.resolver_id,
            )
        ]

        if answer.status in (DnsStatus.TIMEOUT, DnsStatus.ERROR, DnsStatus.REFUSED):
            return ModuleRunResult(
                status="failed",
                summary=f"Reverse lookup {answer.status.value}.",
                evidence=evidence,
                error_code=f"dns_{answer.status.value}",
                provider=resolver.resolver_id,
            )

        return ModuleRunResult(
            status="succeeded",
            summary=f"Found {len(findings)} PTR name(s) for {ctx.target}.",
            findings=findings,
            evidence=evidence,
            provider=resolver.resolver_id,
        )
