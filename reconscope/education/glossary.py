"""Starter glossary (PRD Appendix A).

The glossary is static, reviewable content. Later milestones attach per-module
Learning Manifests that reference these terms. Keeping definitions here (not in
the database) means they are versioned with the code and reviewed like code.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GlossaryTerm:
    slug: str
    term: str
    definition: str


_TERMS: list[GlossaryTerm] = [
    GlossaryTerm(
        "active-recon",
        "Active reconnaissance",
        "A technique that intentionally creates target-directed traffic, either "
        "directly or through an intermediary such as a recursive resolver.",
    ),
    GlossaryTerm(
        "passive-recon",
        "Passive reconnaissance",
        "Collection through third parties or local analysis without intentionally "
        "contacting target-controlled infrastructure. It is not private or "
        "anonymous: the third-party provider can still observe your query.",
    ),
    GlossaryTerm(
        "asn",
        "ASN",
        "An identifier for a network operator participating in Internet routing.",
    ),
    GlossaryTerm(
        "banner",
        "Banner",
        "Data returned by a service that may suggest its product or version. A "
        "banner is a hint, not proof of what software is actually running.",
    ),
    GlossaryTerm(
        "cidr",
        "CIDR",
        "Notation for an IP network range, such as 192.0.2.0/24.",
    ),
    GlossaryTerm(
        "certificate-transparency",
        "Certificate Transparency",
        "Public append-only logs intended to make TLS certificate issuance "
        "observable. Useful for discovering candidate subdomains.",
    ),
    GlossaryTerm(
        "cve",
        "CVE",
        "A public identifier for a reported vulnerability. A version string alone "
        "does not prove that a CVE applies.",
    ),
    GlossaryTerm(
        "dns",
        "DNS",
        "The system that maps domain names and other labels to records such as IP "
        "addresses and mail servers.",
    ),
    GlossaryTerm(
        "evidence",
        "Evidence",
        "Raw or faithfully normalized data produced by a source or tool, kept "
        "separate from any interpretation of it.",
    ),
    GlossaryTerm(
        "finding",
        "Finding",
        "A structured observation linked to evidence and its collection context.",
    ),
    GlossaryTerm(
        "idna",
        "IDNA",
        "The standard transformation used to represent internationalized domain "
        "names in DNS-compatible ASCII.",
    ),
    GlossaryTerm(
        "scope",
        "Scope",
        "The exact targets the user has declared authorized for active contact.",
    ),
    GlossaryTerm(
        "ptr",
        "PTR",
        "A DNS record commonly used for reverse-mapping an IP address to a name. "
        "It is an operator-controlled hint, not identity proof.",
    ),
    GlossaryTerm(
        "rdap",
        "RDAP",
        "A structured protocol for retrieving registration data about domains and "
        "Internet number resources.",
    ),
    GlossaryTerm(
        "san",
        "SAN",
        "Subject Alternative Name: a certificate field listing additional "
        "identities the certificate covers.",
    ),
    GlossaryTerm(
        "tls",
        "TLS",
        "The protocol commonly used to encrypt network connections, including "
        "HTTPS.",
    ),
]

GLOSSARY: dict[str, GlossaryTerm] = {t.slug: t for t in _TERMS}


def get_term(slug: str) -> GlossaryTerm | None:
    return GLOSSARY.get(slug)
