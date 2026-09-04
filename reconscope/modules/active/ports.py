"""Strict validation of user-supplied port specifications (PRD §7, §13.3).

A custom port list is data, never a command fragment. We accept only digits,
commas, and hyphen ranges, bound the total count, and normalize the string. Any
other character (a space, a shell metacharacter, a flag) is rejected before it
can reach an argument array.
"""

from __future__ import annotations

_MAX_TCP_PORTS = 65535


class PortSpecError(ValueError):
    pass


def parse_port_spec(spec: str, *, max_ports: int = _MAX_TCP_PORTS) -> tuple[str, int]:
    """Return ``(normalized_spec, count)`` or raise :class:`PortSpecError`."""
    if spec is None:
        raise PortSpecError("no ports given")
    cleaned = spec.strip().replace(" ", "")
    if not cleaned:
        raise PortSpecError("no ports given")

    allowed = set("0123456789,-")
    if not set(cleaned) <= allowed:
        raise PortSpecError("ports may contain only digits, commas, and hyphens")

    ports: set[int] = set()
    for part in cleaned.split(","):
        if not part:
            raise PortSpecError("empty port segment")
        if "-" in part:
            bits = part.split("-")
            if len(bits) != 2 or not bits[0] or not bits[1]:
                raise PortSpecError(f"invalid range: {part!r}")
            lo, hi = int(bits[0]), int(bits[1])
            if lo > hi:
                raise PortSpecError(f"range start > end: {part!r}")
            _check_port(lo)
            _check_port(hi)
            ports.update(range(lo, hi + 1))
        else:
            value = int(part)
            _check_port(value)
            ports.add(value)

    if len(ports) > max_ports:
        raise PortSpecError(f"too many ports: {len(ports)} > {max_ports}")

    normalized = ",".join(str(p) for p in sorted(ports))
    return normalized, len(ports)


def _check_port(value: int) -> None:
    if not (1 <= value <= 65535):
        raise PortSpecError(f"port out of range: {value}")
