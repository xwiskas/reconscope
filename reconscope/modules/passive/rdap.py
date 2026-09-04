"""P1 — Registration & network ownership via RDAP (PRD §6 P1)."""

from __future__ import annotations

import json

from reconscope.education.manifest import LearningManifest, WorkedExample
from reconscope.findings.types import Confidence, NormalizedFinding
from reconscope.modules.passive.base import PassiveModule
from reconscope.modules.runtime import EvidenceBlob, ModuleRunResult, RunContext
from reconscope.providers.http import ProviderError
from reconscope.scope.canonical import TargetType

_PROVIDER = "rdap"
_CACHE_TTL = 24 * 60 * 60  # 24 hours (PRD P1)


def _entity_name(entity: dict) -> str | None:
    """Pull a display name out of an RDAP entity's jCard, if present."""
    vcard = entity.get("vcardArray")
    if isinstance(vcard, list) and len(vcard) == 2:
        for item in vcard[1]:
            if isinstance(item, list) and item and item[0] == "fn":
                return str(item[3])
    handle = entity.get("handle")
    return str(handle) if handle else None


class Rdap(PassiveModule):
    module_id = "passive.rdap"
    module_version = "0.1.0"
    display_name = "Registration (RDAP)"
    description = "Retrieve domain/IP registration data via RDAP."
    accepted_target_types = (TargetType.HOSTNAME, TargetType.IP)

    manifest = LearningManifest(
        module_id=module_id,
        version=module_version,
        what="Retrieves structured registration data for a domain or IP using "
        "RDAP (the modern, JSON successor to WHOIS).",
        methodology_position="A foundational passive step: who registered the "
        "name/address, when, and which nameservers or network it uses.",
        prerequisites="A domain or IP seed target.",
        interaction="passive",
        intensity="quiet",
        data_leaves_machine="The domain or IP you look up.",
        observers="The RDAP bootstrap service and the authoritative registry/RIR.",
        budget="One request, cached for 24 hours.",
        tool="RDAP over HTTPS via the rdap.org bootstrap.",
        options_explained="The path is /domain/<name> or /ip/<addr>; no other "
        "options are sent.",
        protocol_explanation="A single HTTPS GET returns a JSON object with "
        "events (dates), entities (registrar/registrant), nameservers, and "
        "status values.",
        result_states="data returned, fields redacted/unavailable, or a "
        "provider error (fails only this module).",
        attacker_relevance="Registration dates, nameservers, and org names give "
        "context and pivot points.",
        defender_relevance="Confirms registration details and expiry, and spots "
        "unexpected registrar or nameserver changes.",
        false_positives="Registrant fields are frequently redacted for privacy; "
        "a registrant is not necessarily the current operator of a host.",
        limitations="Registry coverage and field availability vary; some TLDs "
        "expose little data.",
        safe_next_steps="Combine with DNS and certificate data to understand the "
        "footprint.",
        prohibited_next_steps="Do not infer authorization to test from ownership "
        "data.",
        glossary_terms=("rdap", "dns", "asn", "passive-recon"),
        worked_examples=(
            WorkedExample(
                scenario="Look up example.com",
                expected="Registration and expiry events, nameservers, and a "
                "registrar entity (registrant often redacted).",
            ),
        ),
        content_owner="ReconScope education",
        last_reviewed="2026-09-04",
        references=("https://about.rdap.org/",),
    )

    def plan(self, ctx: RunContext) -> str:
        kind = "ip" if ctx.target_type is TargetType.IP else "domain"
        return f"Would fetch RDAP {kind} registration data for {ctx.target!r}."

    def run(self, ctx: RunContext) -> ModuleRunResult:
        kind = "ip" if ctx.target_type is TargetType.IP else "domain"
        url = f"https://rdap.org/{kind}/{ctx.target}"
        cache = ctx.services.cache
        cache_key = f"{_PROVIDER}:{kind}:{ctx.target}"

        doc = cache.get(cache_key)
        cached = doc is not None
        if not cached:
            try:
                doc = ctx.services.http.get_json(_PROVIDER, url)
            except ProviderError as exc:
                return ModuleRunResult.failed(
                    f"RDAP lookup failed ({exc.code}).",
                    error_code=exc.code,
                    detail=exc.detail,
                    provider=_PROVIDER,
                )
            cache.set(cache_key, doc, _CACHE_TTL)

        findings: list[NormalizedFinding] = []

        def add(finding_type: str, value: str, data: dict | None = None):
            findings.append(
                NormalizedFinding(
                    finding_type=finding_type,
                    value=value,
                    confidence=Confidence.CONFIRMED_BY_RESPONSE,
                    data=data or {},
                    source=_PROVIDER,
                    evidence_name="rdap.json",
                )
            )

        if isinstance(doc, dict):
            for event in doc.get("events", []) or []:
                action = event.get("eventAction")
                date = event.get("eventDate")
                if action and date:
                    add("registration_event", f"{action}: {date}",
                        {"action": action, "date": date})
            for ns in doc.get("nameservers", []) or []:
                name = ns.get("ldhName")
                if name:
                    add("nameserver", str(name).lower())
            for entity in doc.get("entities", []) or []:
                name = _entity_name(entity)
                roles = entity.get("roles") or []
                if name:
                    add("registration_entity", name, {"roles": roles})
            for status in doc.get("status", []) or []:
                add("registration_status", str(status))
            if ctx.target_type is TargetType.IP:
                start = doc.get("startAddress")
                end = doc.get("endAddress")
                if start and end:
                    add("network_range", f"{start} - {end}")
                if doc.get("name"):
                    add("network_name", str(doc["name"]))
                if doc.get("country"):
                    add("network_country", str(doc["country"]))

        evidence = [
            EvidenceBlob(
                name="rdap.json",
                media_type="application/json",
                content=json.dumps(doc, indent=2).encode("utf-8"),
                provider=_PROVIDER,
                # Registration contacts can be personal data (PRD §8.2).
                sensitive=True,
            )
        ]

        note = " (from cache)" if cached else ""
        return ModuleRunResult(
            status="succeeded",
            summary=f"Parsed {len(findings)} registration field(s){note}.",
            findings=findings,
            evidence=evidence,
            provider=_PROVIDER,
        )
