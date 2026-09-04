"""Deterministic next-step recommendations (PRD §8.4).

Pure rules over the project's findings. Each recommendation states *why* it
appears. Selecting one opens a configured module form in the UI — nothing runs
automatically.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class Recommendation:
    reason: str
    action: str  # "run_module" | "add_scope" | "note"
    module_id: str | None = None
    config: dict = field(default_factory=dict)


def _open_tcp_ports(findings: list[dict]) -> set[int]:
    ports: set[int] = set()
    for f in findings:
        if f.get("finding_type") == "tcp_port" and (f.get("data") or {}).get(
            "state"
        ) == "open":
            try:
                ports.add(int(str(f.get("value", "")).split("/")[0]))
            except ValueError:
                continue
    return ports


def recommend_next_steps(findings: list[dict]) -> list[Recommendation]:
    """Return ordered, deduplicated recommendations for the current findings."""
    recs: list[Recommendation] = []
    types = {f.get("finding_type") for f in findings}

    if not findings:
        recs.append(
            Recommendation(
                "No findings yet. Start with passive registration and DNS.",
                "run_module",
                "passive.rdap",
            )
        )
        return recs

    if "candidate_hostname" in types:
        recs.append(
            Recommendation(
                "Certificate-transparency candidates were found. Review them and "
                "add authorized ones to scope before any active check.",
                "add_scope",
            )
        )

    open_ports = _open_tcp_ports(findings)
    if 80 in open_ports:
        recs.append(
            Recommendation(
                "TCP 80 is open. Run one bounded HTTP overview request.",
                "run_module",
                "active.http_overview",
                {"scheme": "http", "port": 80},
            )
        )
    if 443 in open_ports:
        recs.append(
            Recommendation(
                "TCP 443 is open. Inspect the TLS certificate.",
                "run_module",
                "active.tls_review",
                {"port": 443},
            )
        )
        recs.append(
            Recommendation(
                "TCP 443 is open. Run an HTTPS overview request.",
                "run_module",
                "active.http_overview",
                {"scheme": "https", "port": 443},
            )
        )

    if open_ports and "service" not in types:
        recs.append(
            Recommendation(
                "Open ports were found but not fingerprinted. Run light service "
                "detection on the open ports.",
                "run_module",
                "active.service_detection",
                {"ports": ",".join(str(p) for p in sorted(open_ports))},
            )
        )

    if "service" in types:
        recs.append(
            Recommendation(
                "Service/version guesses were recorded. Validate software and "
                "versions through authorized administrative inventory — a banner "
                "is not proof.",
                "note",
            )
        )

    if "asset_hint" in types:
        recs.append(
            Recommendation(
                "Naming hints (dev/staging/admin) were flagged. Confirm any "
                "interesting name via DNS and authorization before acting.",
                "note",
            )
        )

    # Always remind the learner to check coverage before concluding.
    recs.append(
        Recommendation(
            "Review the coverage of what was and was not tested before drawing a "
            "conclusion.",
            "note",
        )
    )
    return recs
