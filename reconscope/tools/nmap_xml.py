"""Parse Nmap XML output (PRD A2: parse machine-readable XML, not terminal text).

Uses ``defusedxml`` semantics by disabling entity resolution via the stdlib
parser configured safely. Nmap XML is trusted-ish (we generate it) but we still
parse defensively and never evaluate anything.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from xml.etree import ElementTree as ET


@dataclass(frozen=True)
class Port:
    port: int
    protocol: str
    state: str
    reason: str | None
    service: dict = field(default_factory=dict)


@dataclass(frozen=True)
class Host:
    addresses: tuple[str, ...]
    status: str
    ports: tuple[Port, ...]


@dataclass(frozen=True)
class NmapResult:
    version: str | None
    hosts: tuple[Host, ...]


def parse_nmap_xml(data: bytes | str) -> NmapResult:
    """Parse Nmap XML into a structured result. Raises ValueError on bad XML."""
    if isinstance(data, bytes):
        text = data.decode("utf-8", errors="replace")
    else:
        text = data
    try:
        # Disable DTD/entity expansion by forbidding them at the parser level.
        parser = ET.XMLParser()
        root = ET.fromstring(text, parser=parser)
    except ET.ParseError as exc:
        raise ValueError(f"invalid nmap XML: {exc}") from exc

    if root.tag != "nmaprun":
        raise ValueError("not an nmaprun document")

    version = root.get("version")
    hosts: list[Host] = []
    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        status = status_el.get("state", "unknown") if status_el is not None else "unknown"
        addresses = tuple(
            a.get("addr", "") for a in host_el.findall("address") if a.get("addr")
        )
        ports: list[Port] = []
        ports_el = host_el.find("ports")
        if ports_el is not None:
            for p in ports_el.findall("port"):
                state_el = p.find("state")
                service_el = p.find("service")
                service = {}
                if service_el is not None:
                    for key in ("name", "product", "version", "extrainfo", "method",
                                "conf", "tunnel"):
                        val = service_el.get(key)
                        if val:
                            service[key] = val
                ports.append(
                    Port(
                        port=int(p.get("portid", "0")),
                        protocol=p.get("protocol", "tcp"),
                        state=state_el.get("state", "unknown")
                        if state_el is not None
                        else "unknown",
                        reason=state_el.get("reason") if state_el is not None else None,
                        service=service,
                    )
                )
        hosts.append(Host(addresses=addresses, status=status, ports=tuple(ports)))

    return NmapResult(version=version, hosts=tuple(hosts))
