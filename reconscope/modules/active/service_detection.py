"""A4 — Service and version detection via Nmap (PRD §7 A4)."""

from __future__ import annotations

from reconscope.education.manifest import LearningManifest, WorkedExample
from reconscope.findings.types import Confidence, NormalizedFinding
from reconscope.modules.active.base import ActiveModule
from reconscope.modules.active.ports import PortSpecError, parse_port_spec
from reconscope.modules.contract import IntensityLabel
from reconscope.modules.runtime import EvidenceBlob, ModuleRunResult, RunContext
from reconscope.tools.nmap_xml import parse_nmap_xml

_TIMEOUT_S = 1200  # 20 minutes (PRD A4)


class ServiceDetection(ActiveModule):
    module_id = "active.service_detection"
    module_version = "0.1.0"
    display_name = "Service & version detection"
    description = "Best-effort service/version fingerprints on selected open ports."
    intensity = IntensityLabel.LOUD

    manifest = LearningManifest(
        module_id=module_id,
        version=module_version,
        what="Runs Nmap version detection against ports you selected to guess the "
        "service and software version.",
        methodology_position="After a port scan: turns 'port 443 open' into 'this "
        "looks like nginx 1.25 over TLS' — a hint, not verified inventory.",
        prerequisites="Open ports from a prior scan, plus attestation and scope.",
        interaction="active",
        intensity="loud",
        data_leaves_machine="Probe traffic to the selected ports on the target.",
        observers="The target; version probes are distinctive and often logged.",
        budget="Only the ports you select; light intensity by default; 20-minute "
        "cap.",
        tool="Nmap -sV --version-light with XML output.",
        options_explained="-sV enables version detection; --version-light limits "
        "probe intensity; -p restricts to your selected ports.",
        protocol_explanation="Nmap sends service-specific probes and matches the "
        "responses against its signature database.",
        result_states="a product/version guess with a confidence value, or no "
        "match. Absence of a match does not mean nothing is running.",
        attacker_relevance="Version guesses suggest which known issues to research "
        "(separately and carefully).",
        defender_relevance="Shows what your services reveal about themselves.",
        false_positives="Banners can be altered or absent; a version string is a "
        "claim, not proof, and does not by itself prove a vulnerability.",
        limitations="Only as good as Nmap's signatures; some services are silent "
        "or deliberately misleading.",
        safe_next_steps="Validate any version through authorized administrative "
        "inventory rather than trusting the banner.",
        prohibited_next_steps="Do not map a version straight to a CVE claim or "
        "attempt exploitation.",
        glossary_terms=("banner", "nmap", "cve", "active-recon"),
        worked_examples=(
            WorkedExample(
                scenario="Detect the service on an open port 22",
                expected="An SSH product/version guess with a confidence value.",
            ),
        ),
        content_owner="ReconScope education",
        last_reviewed="2026-09-04",
        references=("https://nmap.org/book/man-version-detection.html",),
    )

    def plan(self, ctx: RunContext) -> str:
        return (
            "Would run Nmap light version detection against the selected ports on "
            f"{ctx.target!r}."
        )

    def run(self, ctx: RunContext) -> ModuleRunResult:
        nmap = ctx.services.nmap
        runner = ctx.services.process_runner
        if nmap is None or not nmap.available or not nmap.path:
            return ModuleRunResult.failed("Nmap is not available.", "nmap_unavailable")
        if runner is None:
            return ModuleRunResult.failed(
                "No process runner configured.", "runner_unavailable"
            )
        try:
            spec, _count = parse_port_spec(ctx.config.get("ports", ""))
        except PortSpecError as exc:
            return ModuleRunResult.failed(
                f"Select open ports first: {exc}", "invalid_ports"
            )

        argv = [
            nmap.path, "-sT", "-Pn", "-sV", "--version-light",
            "-p", spec, "-oX", "-", ctx.target,
        ]
        proc = runner.run(argv, timeout_s=_TIMEOUT_S, cancel=ctx.config.get("cancel"))

        evidence = [
            EvidenceBlob("nmap_sv.xml", "application/xml", proc.stdout or b"", "nmap"),
        ]
        findings: list[NormalizedFinding] = []
        try:
            result = parse_nmap_xml(proc.stdout)
        except ValueError:
            return ModuleRunResult(
                status="failed",
                summary="Nmap produced no parseable XML.",
                evidence=evidence,
                provider="nmap",
                error_code="nmap_parse_failed",
            )

        for host in result.hosts:
            for port in host.ports:
                if not port.service:
                    continue
                product = port.service.get("product", "")
                version = port.service.get("version", "")
                label = " ".join(x for x in (product, version) if x) or port.service.get(
                    "name", "unknown"
                )
                findings.append(
                    NormalizedFinding(
                        finding_type="service",
                        value=f"{port.port}/{port.protocol}: {label}",
                        confidence=Confidence.TOOL_INFERRED,
                        data=dict(port.service),
                        source="nmap",
                        evidence_name="nmap_sv.xml",
                    )
                )

        if proc.cancelled or proc.timed_out:
            code = "cancelled" if proc.cancelled else "timeout"
            return ModuleRunResult(
                status="partial" if findings else "failed",
                summary=f"Version detection {code}.",
                findings=findings,
                evidence=evidence,
                provider="nmap",
                error_code=code,
            )
        return ModuleRunResult(
            status="succeeded",
            summary=f"Fingerprinted {len(findings)} service(s).",
            findings=findings,
            evidence=evidence,
            provider="nmap",
        )
