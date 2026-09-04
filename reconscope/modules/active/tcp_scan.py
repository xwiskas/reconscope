"""A2 — TCP port scan via Nmap (PRD §7 A2)."""

from __future__ import annotations

from reconscope.education.manifest import LearningManifest, WorkedExample
from reconscope.findings.types import Confidence, NormalizedFinding
from reconscope.modules.active.base import ActiveModule
from reconscope.modules.active.ports import PortSpecError, parse_port_spec
from reconscope.modules.contract import IntensityLabel
from reconscope.modules.runtime import EvidenceBlob, ModuleRunResult, RunContext
from reconscope.tools.nmap_xml import parse_nmap_xml

# preset -> (port args, max_rate, timeout_s, intensity)
_PRESETS = {
    "quick": (["--top-ports", "100"], 100, 600, "moderate"),
    "standard": (["--top-ports", "1000"], 150, 1800, "loud"),
    "thorough": (["-p-"], 200, 5400, "loud"),
}


class TcpScan(ActiveModule):
    module_id = "active.tcp_scan"
    module_version = "0.1.0"
    display_name = "TCP port scan"
    description = "Find which TCP ports accept connections (Nmap connect scan)."
    intensity = IntensityLabel.MODERATE

    manifest = LearningManifest(
        module_id=module_id,
        version=module_version,
        what="Uses Nmap to check which TCP ports on the target accept a "
        "connection, using a Windows-friendly connect scan.",
        methodology_position="The first active step after discovery: open ports "
        "reveal which services may be reachable.",
        prerequisites="An in-scope target and a current authorization attestation.",
        interaction="active",
        intensity="moderate (quick) to loud (standard/thorough)",
        data_leaves_machine="TCP connection attempts to the pinned target IP on "
        "the selected ports.",
        observers="The target and any network monitoring in between; connections "
        "may be logged.",
        budget="quick=top 100 ports; standard=top 1000; thorough=all 65535 (one "
        "host). A rate ceiling is enforced and cannot be disabled in the UI.",
        tool="Nmap connect scan (-sT -Pn) with XML output parsed by ReconScope.",
        options_explained="-sT TCP connect (no special privilege); -Pn skip host "
        "discovery (assume up); --top-ports/-p select ports; --max-rate bounds "
        "packet rate; -oX - emits XML to stdout.",
        protocol_explanation="For each port Nmap completes (or fails) a TCP "
        "handshake; a completed handshake means 'open', a reset means 'closed', "
        "and no response means 'filtered'.",
        result_states="open, closed, filtered, or unknown. Timed-out or cancelled "
        "scans are marked partial if some ports were already observed.",
        attacker_relevance="Open ports are the reachable surface an attacker "
        "probes next.",
        defender_relevance="Confirms which ports are actually exposed versus what "
        "you intended.",
        false_positives="Firewalls and rate limits can make open ports look "
        "filtered; 'top ports' does not prove unscanned ports are closed.",
        limitations="Connect scans are more detectable and slower than raw-socket "
        "scans; results reflect one moment in time.",
        safe_next_steps="Run light service detection on selected open ports; "
        "inspect HTTP or TLS on web ports.",
        prohibited_next_steps="Do not treat an open port as a vulnerability, and "
        "do not scan hosts outside your authorized scope.",
        glossary_terms=("nmap", "banner", "active-recon", "cidr"),
        worked_examples=(
            WorkedExample(
                scenario="Quick scan of an authorized lab host",
                expected="A short list of open ports (e.g. 22, 80, 443) with the "
                "reason Nmap observed for each.",
            ),
        ),
        content_owner="ReconScope education",
        last_reviewed="2026-09-04",
        references=("https://nmap.org/book/man-port-scanning-techniques.html",),
    )

    def plan(self, ctx: RunContext) -> str:
        preset = ctx.config.get("preset", "quick")
        return f"Would run an Nmap {preset} TCP connect scan against {ctx.target!r}."

    def run(self, ctx: RunContext) -> ModuleRunResult:
        nmap = ctx.services.nmap
        runner = ctx.services.process_runner
        if nmap is None or not nmap.available or not nmap.path:
            return ModuleRunResult.failed(
                "Nmap is not available.", "nmap_unavailable"
            )
        if runner is None:
            return ModuleRunResult.failed(
                "No process runner configured.", "runner_unavailable"
            )

        preset = ctx.config.get("preset", "quick")
        if preset == "custom":
            try:
                spec, count = parse_port_spec(ctx.config.get("ports", ""))
            except PortSpecError as exc:
                return ModuleRunResult.failed(f"Invalid ports: {exc}", "invalid_ports")
            port_args = ["-p", spec]
            max_rate, timeout_s = 150, 5400
        elif preset in _PRESETS:
            port_args, max_rate, timeout_s, _intensity = _PRESETS[preset]
        else:
            return ModuleRunResult.failed(f"Unknown preset: {preset}", "invalid_preset")

        argv = [
            nmap.path, "-sT", "-Pn", "--max-rate", str(max_rate),
            *port_args, "-oX", "-", ctx.target,
        ]

        proc = runner.run(argv, timeout_s=timeout_s, cancel=ctx.config.get("cancel"))

        evidence = [
            EvidenceBlob(
                name="nmap.xml",
                media_type="application/xml",
                content=proc.stdout or b"",
                provider="nmap",
            ),
            EvidenceBlob(
                name="nmap.command.txt",
                media_type="text/plain",
                content=(" ".join(argv) + "\n\n" + proc.stderr.decode("utf-8", "replace"))
                .encode("utf-8"),
                provider="nmap",
            ),
        ]

        findings: list[NormalizedFinding] = []
        parsed_ok = False
        try:
            result = parse_nmap_xml(proc.stdout)
            parsed_ok = True
        except ValueError:
            result = None

        if result is not None:
            for host in result.hosts:
                for port in host.ports:
                    conf = (
                        Confidence.CONFIRMED_BY_RESPONSE
                        if port.state in ("open", "closed")
                        else Confidence.TOOL_INFERRED
                    )
                    findings.append(
                        NormalizedFinding(
                            finding_type="tcp_port",
                            value=f"{port.port}/{port.protocol}",
                            confidence=conf,
                            data={
                                "state": port.state,
                                "reason": port.reason,
                                "service": port.service.get("name"),
                            },
                            source="nmap",
                            evidence_name="nmap.xml",
                        )
                    )

        if proc.cancelled or proc.timed_out:
            status = "partial" if findings else "failed"
            code = "cancelled" if proc.cancelled else "timeout"
            return ModuleRunResult(
                status=status,
                summary=f"Scan {code}; {len(findings)} port(s) observed.",
                findings=findings,
                evidence=evidence,
                provider="nmap",
                error_code=code,
            )
        if not parsed_ok:
            return ModuleRunResult(
                status="failed",
                summary="Nmap produced no parseable XML.",
                evidence=evidence,
                provider="nmap",
                error_code="nmap_parse_failed",
            )

        open_count = sum(1 for f in findings if f.data.get("state") == "open")
        return ModuleRunResult(
            status="succeeded",
            summary=f"{open_count} open of {len(findings)} scanned port(s).",
            findings=findings,
            evidence=evidence,
            provider="nmap",
        )
