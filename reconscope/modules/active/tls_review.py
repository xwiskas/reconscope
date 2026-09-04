"""A13 — TLS certificate and configuration review (PRD §7 A13, certificate mode)."""

from __future__ import annotations

import json

from reconscope.education.manifest import LearningManifest, WorkedExample
from reconscope.findings.types import Confidence, NormalizedFinding
from reconscope.modules.active.base import ActiveModule
from reconscope.modules.runtime import EvidenceBlob, ModuleRunResult, RunContext


class TlsReview(ActiveModule):
    module_id = "active.tls_review"
    module_version = "0.1.0"
    display_name = "TLS certificate review"
    description = "Inspect the presented certificate and negotiated TLS parameters."

    manifest = LearningManifest(
        module_id=module_id,
        version=module_version,
        what="Completes a TLS handshake and reports the certificate (subject, "
        "issuer, validity, SANs) and the negotiated protocol and cipher.",
        methodology_position="After finding a TLS port: understand the identity "
        "the service presents and whether it validates.",
        prerequisites="An in-scope host with a TLS service and attestation.",
        interaction="active",
        intensity="quiet",
        data_leaves_machine="One TLS handshake to the target (no application "
        "request afterwards in certificate mode).",
        observers="The target and network monitors; a handshake is ordinary.",
        budget="One (optionally two) handshakes; 10s timeout; no HTTP request.",
        tool="Python TLS (ssl) with certificate parsing via cryptography.",
        options_explained="Certificate mode inspects the leaf certificate and the "
        "negotiated version/cipher; it does not enumerate every cipher suite.",
        protocol_explanation="During the handshake the server presents its "
        "certificate chain and agrees a protocol version and cipher suite.",
        result_states="certificate + parameters returned, a validation failure "
        "(hostname/expiry/chain), or a connection error.",
        attacker_relevance="Certificate names (SANs) can reveal other hostnames; "
        "weak protocols/ciphers indicate configuration to review.",
        defender_relevance="Confirms the certificate identity, expiry, and whether "
        "it validates against public trust.",
        false_positives="A validation failure here is a configuration observation, "
        "not proof of exploitability; internal CAs legitimately fail public trust.",
        limitations="Certificate mode does not enumerate all supported protocol "
        "versions or ciphers.",
        safe_next_steps="Note upcoming expiry or deprecated protocols; review the "
        "SANs for other in-scope hostnames.",
        prohibited_next_steps="Do not describe a deprecated protocol as an "
        "exploited vulnerability.",
        glossary_terms=("tls", "san", "certificate-transparency"),
        worked_examples=(
            WorkedExample(
                scenario="Inspect https on an authorized host",
                expected="Subject/issuer, validity dates, SAN list, and the "
                "negotiated TLS version and cipher.",
            ),
        ),
        content_owner="ReconScope education",
        last_reviewed="2026-09-04",
        references=("https://datatracker.ietf.org/doc/html/rfc8446",),
    )

    def plan(self, ctx: RunContext) -> str:
        port = ctx.config.get("port", 443)
        return f"Would complete a TLS handshake with {ctx.target}:{port}."

    def run(self, ctx: RunContext) -> ModuleRunResult:
        fetch = ctx.services.tls_fetcher
        if fetch is None:
            return ModuleRunResult.failed(
                "No TLS fetcher configured.", "tls_unavailable"
            )
        port = int(ctx.config.get("port", 443))
        info = fetch(ctx.target, port, 10.0)

        if not info.ok:
            return ModuleRunResult.failed(
                f"TLS handshake failed: {info.error}", "tls_handshake_failed",
                provider="tls",
            )

        findings: list[NormalizedFinding] = []

        def add(ftype: str, value: str, data: dict | None = None):
            findings.append(
                NormalizedFinding(
                    ftype, value, Confidence.CONFIRMED_BY_RESPONSE, data or {}, "tls",
                    evidence_name="tls.json",
                )
            )

        if info.subject:
            add("tls_subject", info.subject)
        if info.issuer:
            add("tls_issuer", info.issuer)
        if info.not_after:
            add("tls_not_after", info.not_after, {"not_before": info.not_before})
        if info.version:
            add("tls_version", info.version, {"cipher": info.cipher})
        for san in info.sans:
            add("tls_san", san)
        if info.validation_ok is False:
            add("tls_validation", "public-trust validation failed",
                {"error": info.validation_error})

        evidence = [
            EvidenceBlob(
                "tls.json", "application/json",
                json.dumps(info.__dict__, indent=2, default=list).encode("utf-8"),
                provider="tls",
            )
        ]
        return ModuleRunResult(
            status="succeeded",
            summary=f"TLS {info.version or '?'} certificate for {ctx.target}.",
            findings=findings,
            evidence=evidence,
            provider="tls",
        )
