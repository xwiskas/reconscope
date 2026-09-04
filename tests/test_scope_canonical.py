"""Unit tests for scope canonicalization (PRD §4.3)."""

import ipaddress

import pytest

from reconscope.scope.canonical import (
    CanonicalizationError,
    EntryType,
    canonical_cidr,
    canonical_domain,
    canonical_ip,
    canonicalize_scope_entry,
)


class TestCanonicalDomain:
    def test_lowercases_and_strips_trailing_dot(self):
        assert canonical_domain("EXAMPLE.COM.") == "example.com"

    def test_idna_unicode_matches_punycode(self):
        uni = canonical_domain("bücher.example")
        puny = canonical_domain("xn--bcher-kva.example")
        assert uni == puny == "xn--bcher-kva.example"

    def test_idna_case_insensitive(self):
        assert canonical_domain("BÜCHER.example") == "xn--bcher-kva.example"

    @pytest.mark.parametrize(
        "bad",
        [
            "http://example.com",
            "example.com/path",
            "user@example.com",
            "example.com:8080",
            "exa mple.com",
            "a..b.com",
            ".example.com",
            "localhost",  # single label
            "",
            "   ",
        ],
    )
    def test_rejects_unsafe_or_ambiguous(self, bad):
        with pytest.raises(CanonicalizationError):
            canonical_domain(bad)


class TestCanonicalIP:
    def test_ipv6_forms_collapse(self):
        a = canonical_ip("2001:db8::5")
        b = canonical_ip("2001:0db8:0000:0000:0000:0000:0000:0005")
        assert a == b == ipaddress.ip_address("2001:db8::5")

    def test_ipv4_mapped_ipv6_folds_to_ipv4(self):
        assert canonical_ip("::ffff:203.0.113.10") == ipaddress.ip_address(
            "203.0.113.10"
        )

    def test_strips_ipv6_brackets(self):
        assert canonical_ip("[::1]") == ipaddress.ip_address("::1")

    @pytest.mark.parametrize(
        "bad",
        [
            "192.168.001.1",  # leading zeros (octal ambiguity)
            "2130706433",  # integer form
            "0x7f000001",  # hex form
            "203.0.113.10/24",  # a CIDR, not a single IP
            "fe80::1%eth0",  # zone id
            "",
        ],
    )
    def test_rejects_ambiguous_forms(self, bad):
        with pytest.raises(CanonicalizationError):
            canonical_ip(bad)


class TestCanonicalCIDR:
    def test_normalizes_host_bits(self):
        assert str(canonical_cidr("192.168.1.5/24")) == "192.168.1.0/24"

    def test_rejects_overly_broad_ipv4(self):
        with pytest.raises(CanonicalizationError):
            canonical_cidr("10.0.0.0/8")

    def test_rejects_overly_broad_ipv6(self):
        with pytest.raises(CanonicalizationError):
            canonical_cidr("2001:db8::/64")

    def test_accepts_bounded_ipv6(self):
        assert str(canonical_cidr("2001:db8::/112")) == "2001:db8::/112"


class TestEntryDetection:
    def test_detects_types(self):
        assert canonicalize_scope_entry("example.com").type is EntryType.DOMAIN
        assert (
            canonicalize_scope_entry("*.example.com").type
            is EntryType.WILDCARD_DOMAIN
        )
        assert canonicalize_scope_entry("203.0.113.10").type is EntryType.IP
        assert canonicalize_scope_entry("203.0.113.0/24").type is EntryType.CIDR

    def test_wildcard_stores_base_domain(self):
        entry = canonicalize_scope_entry("*.Example.com")
        assert entry.value == "example.com"
        assert entry.display == "*.Example.com"
