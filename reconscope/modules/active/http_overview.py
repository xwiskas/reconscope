"""A7 — HTTP overview: one bounded, scope-checked request (PRD §7 A7)."""

from __future__ import annotations

import hashlib
from urllib.parse import urljoin, urlsplit

from reconscope.education.manifest import LearningManifest, WorkedExample
from reconscope.findings.types import Confidence, NormalizedFinding
from reconscope.modules.active.base import ActiveModule
from reconscope.modules.runtime import EvidenceBlob, ModuleRunResult, RunContext
from reconscope.providers.http import ProviderError
from reconscope.scope.canonical import (
    CanonicalizationError,
    TargetType,
    canonical_ip,
)
from reconscope.scope.service import evaluate

_MAX_REDIRECTS = 3
_BODY_CAP = 1024 * 1024  # 1 MiB (PRD A7)
_SECURITY_HEADERS = (
    "server", "content-type", "strict-transport-security",
    "content-security-policy", "x-frame-options", "location",
)


def _host_target_type(host: str) -> TargetType:
    try:
        canonical_ip(host)
        return TargetType.IP
    except CanonicalizationError:
        return TargetType.HOSTNAME


def _in_scope(host: str, scope_entries) -> bool:
    if not scope_entries:
        return False
    decision = evaluate(host, _host_target_type(host), scope_entries)
    return decision.allowed


class HttpOverview(ActiveModule):
    module_id = "active.http_overview"
    module_version = "0.1.0"
    display_name = "HTTP overview"
    description = "Fetch one page from a web service, validating every redirect."
    # HTTP needs the requested hostname (vhost/SNI); pinned IPs are recorded.
    contact_target = "host"

    manifest = LearningManifest(
        module_id=module_id,
        version=module_version,
        what="Sends one GET request to a selected web service and records the "
        "status, key headers, and a bounded snippet of the response.",
        methodology_position="After finding an open web port: a first, quiet look "
        "at what the service returns.",
        prerequisites="An in-scope web service (scheme, host, port) and attestation.",
        interaction="active",
        intensity="moderate",
        data_leaves_machine="One HTTP request (plus up to three in-scope "
        "redirects) to the target.",
        observers="The target web server and anything logging its traffic.",
        budget="One GET, at most 3 redirects, 1 MiB body cap, 10s connect / 20s "
        "total timeout.",
        tool="ReconScope HTTP client (no crawling).",
        options_explained="Redirects are followed only when the destination host "
        "is independently in scope; credentials in a redirect URL are refused.",
        protocol_explanation="A single HTTP request/response; any 3xx Location is "
        "checked against scope before a further request is made.",
        result_states="a status code with headers, a blocked out-of-scope "
        "redirect, or a connection error.",
        attacker_relevance="Headers and redirects reveal the stack, security "
        "posture, and where the app sends clients.",
        defender_relevance="Shows the response and security headers an external "
        "client sees.",
        false_positives="A single request can miss vhost- or path-specific "
        "behavior; a missing security header is an observation, not a proven flaw.",
        limitations="No crawling, no form submission, no script execution.",
        safe_next_steps="Inspect TLS on HTTPS ports; add the service to a web "
        "inventory for deeper (still bounded) review later.",
        prohibited_next_steps="Do not submit forms, follow out-of-scope redirects, "
        "or execute returned scripts.",
        glossary_terms=("tls", "banner", "active-recon"),
        worked_examples=(
            WorkedExample(
                scenario="GET / on an authorized site",
                expected="A 200 or a redirect, with the Server header and a hash "
                "of the body.",
            ),
        ),
        content_owner="ReconScope education",
        last_reviewed="2026-09-04",
        references=(
            "https://owasp.org/www-project-web-security-testing-guide/",
        ),
    )

    def plan(self, ctx: RunContext) -> str:
        scheme = ctx.config.get("scheme", "http")
        port = ctx.config.get("port", 80)
        return f"Would GET {scheme}://{ctx.target}:{port}/ (one request, no crawl)."

    def run(self, ctx: RunContext) -> ModuleRunResult:
        scheme = ctx.config.get("scheme", "http")
        port = ctx.config.get("port", 443 if scheme == "https" else 80)
        scope_entries = ctx.config.get("scope_entries", [])

        url = f"{scheme}://{ctx.target}:{port}/"
        findings: list[NormalizedFinding] = []
        hops: list[str] = []
        final: str | None = None
        response = None

        for _ in range(_MAX_REDIRECTS + 1):
            hops.append(url)
            try:
                response = ctx.services.http.get_raw(
                    "http_overview", url, follow_redirects=False
                )
            except ProviderError as exc:
                return ModuleRunResult.failed(
                    f"Request failed ({exc.code}).", exc.code, exc.detail, "http"
                )

            if 300 <= response.status_code < 400 and "location" in response.headers:
                nxt = urljoin(url, response.headers["location"])
                parts = urlsplit(nxt)
                if parts.username or parts.password:
                    findings.append(
                        NormalizedFinding(
                            "http_redirect_blocked", nxt,
                            Confidence.CONFIRMED_BY_RESPONSE,
                            {"reason": "credentials_in_url"}, "http",
                        )
                    )
                    break
                host = parts.hostname or ""
                if not _in_scope(host, scope_entries):
                    findings.append(
                        NormalizedFinding(
                            "http_redirect_blocked", nxt,
                            Confidence.CONFIRMED_BY_RESPONSE,
                            {"reason": "out_of_scope", "host": host}, "http",
                        )
                    )
                    break
                url = nxt
                continue

            final = url
            break

        if response is None:  # pragma: no cover - loop always sets it
            return ModuleRunResult.failed("No response.", "no_response", provider="http")

        body = response.content[:_BODY_CAP]
        truncated = len(response.content) > _BODY_CAP
        body_hash = hashlib.sha256(body).hexdigest()

        findings.append(
            NormalizedFinding(
                "http_status", str(response.status_code),
                Confidence.CONFIRMED_BY_RESPONSE,
                {"final_url": final, "redirects": len(hops) - 1}, "http",
                evidence_name="http.txt",
            )
        )
        for header in _SECURITY_HEADERS:
            if header in response.headers:
                findings.append(
                    NormalizedFinding(
                        "http_header", f"{header}: {response.headers[header]}",
                        Confidence.CONFIRMED_BY_RESPONSE, {"header": header}, "http",
                        evidence_name="http.txt",
                    )
                )

        header_dump = "\n".join(f"{k}: {v}" for k, v in response.headers.items())
        evidence_text = (
            "Request hops:\n" + "\n".join(hops) + "\n\n"
            f"Status: {response.status_code}\n\nHeaders:\n{header_dump}\n\n"
            f"Body sha256: {body_hash} ({len(body)} bytes"
            f"{', truncated' if truncated else ''})\n"
        )
        evidence = [
            EvidenceBlob(
                "http.txt", "text/plain", evidence_text.encode("utf-8"),
                provider="http", sensitive=True,  # may include cookies
            ),
        ]

        return ModuleRunResult(
            status="succeeded",
            summary=f"HTTP {response.status_code} for {final} "
            f"({len(hops) - 1} redirect(s)).",
            findings=findings,
            evidence=evidence,
            provider="http",
        )
