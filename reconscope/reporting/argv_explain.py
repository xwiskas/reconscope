"""Explain every argument of an external command (PRD §8.3).

Maps each token of a tool command to a plain-language meaning, distinguishing
fixed reviewed arguments from values derived from user input (the target and
ports). Used by the "Explain every argument" control.
"""

from __future__ import annotations

from dataclasses import dataclass

# Flags whose meaning is fixed and reviewed.
_NMAP_FLAGS: dict[str, str] = {
    "-sT": "TCP connect scan (completes the handshake; no special privilege).",
    "-sV": "Service/version detection.",
    "-Pn": "Skip host discovery; treat the host as online.",
    "-O": "OS detection.",
    "-sn": "Host discovery only; no port scan.",
    "-oX": "Write results as XML.",
    "--version-light": "Limit version-detection probe intensity.",
    "--top-ports": "Scan the N most common ports.",
    "--max-rate": "Cap the packet send rate.",
    "-p": "Scan exactly these ports.",
    "-p-": "Scan all 65535 TCP ports.",
}

# Flags that consume the following token as their value.
_VALUE_FLAGS = {"-oX", "--top-ports", "--max-rate", "-p"}


@dataclass(frozen=True)
class ArgExplanation:
    token: str
    meaning: str
    kind: str  # "executable" | "flag" | "value" | "target"
    user_derived: bool = False


def explain_argv(argv: list[str]) -> list[ArgExplanation]:
    """Annotate an argument array (currently tuned for Nmap)."""
    if not argv:
        return []
    out: list[ArgExplanation] = [
        ArgExplanation(argv[0], "The external tool being run.", "executable")
    ]
    i = 1
    n = len(argv)
    while i < n:
        tok = argv[i]
        is_last = i == n - 1
        if tok in _NMAP_FLAGS:
            out.append(ArgExplanation(tok, _NMAP_FLAGS[tok], "flag"))
            if tok in _VALUE_FLAGS and i + 1 < n:
                val = argv[i + 1]
                # -oX '-' is a fixed choice; ports are user-derived.
                user = tok in ("-p", "--top-ports")
                out.append(
                    ArgExplanation(
                        val,
                        f"Value for {tok}.",
                        "value",
                        user_derived=user,
                    )
                )
                i += 2
                continue
        elif is_last:
            out.append(
                ArgExplanation(
                    tok, "The target to scan (from your in-scope selection).",
                    "target", user_derived=True,
                )
            )
        else:
            out.append(ArgExplanation(tok, "Argument.", "flag"))
        i += 1
    return out
