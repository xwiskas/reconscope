"""MANDATORY scope-bypass test suite (PRD §16.2).

The release fails acceptance if any of these fail. Each test encodes one way an
out-of-scope target might try to slip past the scope check, and asserts that it
cannot. "Bypass" always means *getting an out-of-scope target allowed*; erring
toward denial is safe.
"""

import pytest

from reconscope.scope.canonical import TargetType, canonicalize_scope_entry
from reconscope.scope.service import evaluate


def _scope(*entries):
    return [canonicalize_scope_entry(e) for e in entries]


def _allowed(target, ttype, *entries):
    return evaluate(target, ttype, _scope(*entries)).allowed


# --------------------------------------------------------------------------- #
# Exact-domain matching
# --------------------------------------------------------------------------- #
class TestExactDomain:
    def test_exact_match_allowed(self):
        assert _allowed("example.com", TargetType.HOSTNAME, "example.com")

    @pytest.mark.parametrize(
        "variant", ["EXAMPLE.COM", "example.com.", "Example.Com"]
    )
    def test_case_and_trailing_dot_still_match(self, variant):
        assert _allowed(variant, TargetType.HOSTNAME, "example.com")

    @pytest.mark.parametrize(
        "attacker",
        [
            "sub.example.com",  # exact entry must NOT authorize subdomains
            "notexample.com",
            "evil-example.com",
            "example.com.evil.test",  # suffix look-alike
            "examplexcom",
        ],
    )
    def test_lookalikes_denied(self, attacker):
        assert not _allowed(attacker, TargetType.HOSTNAME, "example.com")


# --------------------------------------------------------------------------- #
# Wildcard-domain matching
# --------------------------------------------------------------------------- #
class TestWildcardDomain:
    @pytest.mark.parametrize(
        "host", ["a.example.com", "a.b.example.com", "A.Example.com", "x.example.com."]
    )
    def test_subdomains_allowed(self, host):
        assert _allowed(host, TargetType.HOSTNAME, "*.example.com")

    def test_apex_not_matched_by_wildcard(self):
        assert not _allowed("example.com", TargetType.HOSTNAME, "*.example.com")

    @pytest.mark.parametrize(
        "attacker",
        [
            "a.example.com.evil.test",
            "xexample.com",
            "example.com.evil.test",
            "notexample.com",
        ],
    )
    def test_wildcard_lookalikes_denied(self, attacker):
        assert not _allowed(attacker, TargetType.HOSTNAME, "*.example.com")


# --------------------------------------------------------------------------- #
# IP / CIDR matching and alternate notations
# --------------------------------------------------------------------------- #
class TestIPMatching:
    def test_exact_ip_allowed(self):
        assert _allowed("203.0.113.10", TargetType.IP, "203.0.113.10")

    def test_other_ip_denied(self):
        assert not _allowed("203.0.113.11", TargetType.IP, "203.0.113.10")

    def test_ipv4_mapped_ipv6_cannot_bypass_v4_entry(self):
        # The mapped form must resolve to the same v4 address (allowed here),
        # never sneak past as an "unmatched" IPv6.
        assert _allowed("::ffff:203.0.113.10", TargetType.IP, "203.0.113.10")

    def test_ipv6_expanded_form_matches(self):
        assert _allowed(
            "2001:0db8:0000:0000:0000:0000:0000:0005",
            TargetType.IP,
            "2001:db8::5",
        )

    def test_cidr_contains_allowed(self):
        assert _allowed("203.0.113.55", TargetType.IP, "203.0.113.0/24")

    def test_cidr_outside_denied(self):
        assert not _allowed("203.0.114.1", TargetType.IP, "203.0.113.0/24")

    def test_ipv6_cidr(self):
        assert _allowed("2001:db8::5", TargetType.IP, "2001:db8::/112")
        assert not _allowed("2001:db9::5", TargetType.IP, "2001:db8::/112")

    def test_version_mismatch_denied(self):
        # An IPv4 target must not match an IPv6 CIDR entry (and vice versa).
        assert not _allowed("203.0.113.5", TargetType.IP, "2001:db8::/112")
        assert not _allowed("2001:db8::5", TargetType.IP, "203.0.113.0/24")


# --------------------------------------------------------------------------- #
# IDNA / internationalized domains
# --------------------------------------------------------------------------- #
class TestIDNA:
    def test_unicode_entry_matches_punycode_target(self):
        assert _allowed(
            "xn--bcher-kva.example", TargetType.HOSTNAME, "bücher.example"
        )

    def test_unicode_target_matches_unicode_entry(self):
        assert _allowed("BÜCHER.example", TargetType.HOSTNAME, "bücher.example")


# --------------------------------------------------------------------------- #
# Structural guarantees
# --------------------------------------------------------------------------- #
class TestStructural:
    def test_empty_scope_denies_everything(self):
        d = evaluate("example.com", TargetType.HOSTNAME, [])
        assert not d.allowed
        assert d.reason == "no_scope_entries"

    def test_invalid_target_is_denied_not_crashed(self):
        d = evaluate("not a domain/", TargetType.HOSTNAME, _scope("example.com"))
        assert not d.allowed
        assert d.reason.startswith("invalid_target")

    def test_disabled_entry_not_passed_means_denied(self):
        # The caller passes only ENABLED entries; simulate a disabled entry by
        # omitting it. The target must then be out of scope.
        d = evaluate("example.com", TargetType.HOSTNAME, _scope("other.test"))
        assert not d.allowed
        assert d.reason == "target_out_of_scope"

    def test_decision_reports_matched_entry(self):
        d = evaluate("a.example.com", TargetType.HOSTNAME, _scope("*.example.com"))
        assert d.allowed
        assert d.matched_entry == "*.example.com"
