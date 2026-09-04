"""P2 — Recursive DNS lookup (PRD §6 P2)."""

from __future__ import annotations

from reconscope.education.manifest import LearningManifest, WorkedExample
from reconscope.findings.types import Confidence, NormalizedFinding
from reconscope.modules.passive.base import PassiveModule
from reconscope.modules.runtime import EvidenceBlob, ModuleRunResult, RunContext
from reconscope.providers.dns import DnsStatus

_RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")
_MAX_QUERIES = 20  # PRD P2 budget

_CONCLUSIVE = {DnsStatus.OK, DnsStatus.NODATA, DnsStatus.NXDOMAIN}


class DnsRecords(PassiveModule):
    module_id = "passive.dns_records"
    module_version = "0.1.0"
    display_name = "DNS records"
    description = "Look up common DNS records through the configured resolver."

    manifest = LearningManifest(
        module_id=module_id,
        version=module_version,
        what="Asks a recursive DNS resolver for the domain's A, AAAA, MX, NS, "
        "TXT, CNAME, and SOA records.",
        methodology_position="Early passive step: DNS maps names to addresses "
        "and services and often reveals mail, hosting, and infrastructure.",
        prerequisites="A domain seed target.",
        interaction="passive",
        intensity="quiet",
        data_leaves_machine="The domain name and record types you query.",
        observers="Your configured recursive resolver (and any upstream it "
        "uses) can see the queries and your IP address.",
        budget=f"At most {_MAX_QUERIES} DNS queries per run "
        f"({len(_RECORD_TYPES)} record types).",
        tool="Python resolver (dnspython) using the system resolver settings.",
        options_explained="Record types are fixed to a common set; no wordlist "
        "or guessing is performed (that would be active enumeration).",
        protocol_explanation="Each lookup is one DNS question/answer for a "
        "(name, type) pair; the resolver returns records and a TTL, or a status "
        "such as NXDOMAIN or no-data.",
        result_states="ok (records returned), nodata (name exists, no such "
        "record), nxdomain (name does not exist), timeout, refused, error.",
        attacker_relevance="Reveals hosting, mail providers, and naming that "
        "guide further recon.",
        defender_relevance="Confirms which records are published and whether "
        "unexpected or stale entries exist.",
        false_positives="TTL caching can return stale data; CNAME chains and "
        "geo/split-horizon DNS can vary by resolver and location.",
        limitations="Only queries a fixed record set; does not enumerate "
        "subdomains and does not query names found inside TXT data.",
        safe_next_steps="Review certificate-transparency names and registration "
        "data; add authorized hosts to scope before any active check.",
        prohibited_next_steps="Do not treat a resolved name as authorization to "
        "actively contact it.",
        glossary_terms=("dns", "ptr", "passive-recon"),
        worked_examples=(
            WorkedExample(
                scenario="Query example.com",
                expected="A/AAAA addresses, NS and SOA for the zone, and any MX "
                "or TXT records the operator publishes.",
            ),
        ),
        content_owner="ReconScope education",
        last_reviewed="2026-09-04",
        references=("https://www.rfc-editor.org/rfc/rfc1034",),
    )

    def plan(self, ctx: RunContext) -> str:
        return (
            f"Would query {', '.join(_RECORD_TYPES)} records for {ctx.target!r} "
            "through your configured recursive resolver."
        )

    def run(self, ctx: RunContext) -> ModuleRunResult:
        resolver = ctx.services.resolver
        if resolver is None:
            return ModuleRunResult.failed(
                "No DNS resolver is configured.", "resolver_unavailable"
            )

        findings: list[NormalizedFinding] = []
        lines: list[str] = [f"DNS records for {ctx.target}", ""]
        statuses: list[DnsStatus] = []

        for rtype in _RECORD_TYPES:
            answer = resolver.query(ctx.target, rtype)
            statuses.append(answer.status)
            lines.append(
                f"{rtype}: {answer.status.value}"
                + (f" (ttl={answer.ttl})" if answer.ttl is not None else "")
            )
            for record in answer.records:
                lines.append(f"    {record}")
                findings.append(
                    NormalizedFinding(
                        finding_type="dns_record",
                        value=record,
                        confidence=Confidence.CONFIRMED_BY_RESPONSE,
                        data={"rtype": rtype, "ttl": answer.ttl},
                        source=answer.resolver or resolver.resolver_id,
                        evidence_name="dns.txt",
                    )
                )
            if answer.detail:
                lines.append(f"    ! {answer.detail}")

        evidence = [
            EvidenceBlob(
                name="dns.txt",
                media_type="text/plain",
                content="\n".join(lines).encode("utf-8"),
                provider=resolver.resolver_id,
            )
        ]

        if not any(s in _CONCLUSIVE for s in statuses):
            return ModuleRunResult(
                status="failed",
                summary="All DNS lookups timed out or errored.",
                evidence=evidence,
                error_code="dns_unreachable",
                provider=resolver.resolver_id,
            )

        return ModuleRunResult(
            status="succeeded",
            summary=f"Collected {len(findings)} DNS record(s) for {ctx.target}.",
            findings=findings,
            evidence=evidence,
            provider=resolver.resolver_id,
        )
