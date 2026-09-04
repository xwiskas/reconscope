"""Unit tests for individual passive modules (fakes, no network)."""

import httpx

from reconscope.modules.passive import (
    AssetHints,
    CertTransparency,
    DnsRecords,
    Rdap,
    ReverseDns,
    SocialFootprint,
)
from reconscope.modules.runtime import RunContext
from reconscope.providers.dns import DnsAnswer, DnsStatus
from reconscope.scope.canonical import TargetType
from tests.conftest import FakeResolver, make_services


def _ctx(target, ttype=TargetType.HOSTNAME, services=None, config=None):
    return RunContext(
        target=target,
        target_type=ttype,
        services=services or make_services(),
        config=config or {},
    )


class TestDnsRecords:
    def test_collects_records(self):
        resolver = FakeResolver(
            answers={
                ("example.com", "A"): DnsAnswer(
                    "example.com", "A", DnsStatus.OK, ("192.0.2.1",), 300,
                    "fake-resolver",
                ),
                ("example.com", "MX"): DnsAnswer(
                    "example.com", "MX", DnsStatus.OK, ("10 mail.example.com.",),
                    300, "fake-resolver",
                ),
            }
        )
        result = DnsRecords().run(_ctx("example.com", services=make_services(resolver=resolver)))
        assert result.status == "succeeded"
        values = {f.value for f in result.findings}
        assert "192.0.2.1" in values
        assert any("mail.example.com" in v for v in values)
        assert result.evidence and result.evidence[0].name == "dns.txt"

    def test_all_timeout_fails(self):
        resolver = FakeResolver(
            answers={
                (n := "example.com", rt): DnsAnswer(n, rt, DnsStatus.TIMEOUT)
                for rt in ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA")
            }
        )
        result = DnsRecords().run(_ctx("example.com", services=make_services(resolver=resolver)))
        assert result.status == "failed"
        assert result.error_code == "dns_unreachable"

    def test_no_resolver_fails(self):
        result = DnsRecords().run(_ctx("example.com", services=make_services(resolver=None)))
        assert result.status == "failed"
        assert result.error_code == "resolver_unavailable"


class TestReverseDns:
    def test_ptr(self):
        resolver = FakeResolver(
            reverse={
                "203.0.113.10": DnsAnswer(
                    "203.0.113.10", "PTR", DnsStatus.OK, ("host.example.com.",),
                    3600, "fake-resolver",
                )
            }
        )
        result = ReverseDns().run(
            _ctx("203.0.113.10", TargetType.IP, make_services(resolver=resolver))
        )
        assert result.status == "succeeded"
        assert result.findings[0].value == "host.example.com"


class TestCertTransparency:
    def _handler(self, rows, status=200):
        def handler(request):
            assert "crt.sh" in request.url.host
            return httpx.Response(status, json=rows)
        return handler

    def test_parses_and_dedupes(self):
        rows = [
            {"name_value": "www.example.com\n*.example.com", "common_name": "example.com"},
            {"name_value": "www.example.com", "common_name": "www.example.com"},
        ]
        services = make_services(handler=self._handler(rows))
        result = CertTransparency().run(_ctx("example.com", services=services))
        assert result.status == "succeeded"
        values = sorted(f.value for f in result.findings)
        assert values == ["example.com", "www.example.com"]
        wildcard = {f.value: f.data["wildcard"] for f in result.findings}
        assert wildcard["example.com"] is True  # from *.example.com

    def test_provider_outage_fails_only_this_module(self):
        def handler(request):
            return httpx.Response(503, text="unavailable")
        services = make_services(handler=handler)
        result = CertTransparency().run(_ctx("example.com", services=services))
        assert result.status == "failed"
        assert result.error_code == "provider_unavailable"
        assert result.provider == "crt.sh"

    def test_uses_cache_on_second_run(self):
        calls = {"n": 0}
        rows = [{"name_value": "a.example.com", "common_name": "a.example.com"}]

        def handler(request):
            calls["n"] += 1
            return httpx.Response(200, json=rows)

        services = make_services(handler=handler)
        CertTransparency().run(_ctx("example.com", services=services))
        CertTransparency().run(_ctx("example.com", services=services))
        assert calls["n"] == 1  # second run served from cache


class TestRdap:
    def test_parses_events_and_entities(self):
        doc = {
            "events": [{"eventAction": "registration", "eventDate": "2000-01-01"}],
            "nameservers": [{"ldhName": "NS1.EXAMPLE.COM"}],
            "entities": [
                {
                    "roles": ["registrar"],
                    "vcardArray": ["vcard", [["fn", {}, "text", "Example Registrar"]]],
                }
            ],
            "status": ["active"],
        }

        def handler(request):
            assert "rdap.org" in request.url.host
            return httpx.Response(200, json=doc)

        result = Rdap().run(_ctx("example.com", services=make_services(handler=handler)))
        assert result.status == "succeeded"
        types = {f.finding_type for f in result.findings}
        assert {"registration_event", "nameserver", "registration_entity"} <= types
        assert result.evidence[0].sensitive is True


class TestAssetHints:
    def test_flags_dev_and_admin(self):
        result = AssetHints().run(
            _ctx(
                "example.com",
                config={"candidates": ["dev.example.com", "admin.example.com", "www.example.com"]},
            )
        )
        flagged = {f.value: f.data["category"] for f in result.findings}
        assert flagged["dev.example.com"] == "development"
        assert flagged["admin.example.com"] == "administrative"
        assert "www.example.com" not in flagged


class TestSocialFootprint:
    def test_generates_queries(self):
        result = SocialFootprint().run(
            _ctx(
                "example.com",
                config={"subjects": [{"type": "organization", "value": "Example Inc"}]},
            )
        )
        assert result.status == "succeeded"
        platforms = {
            f.data["platform"]
            for f in result.findings
            if f.finding_type == "social_query"
        }
        assert {"facebook", "linkedin", "github", "x"} <= platforms

    def test_extracts_links_from_evidence(self):
        result = SocialFootprint().run(
            _ctx(
                "example.com",
                config={"evidence_text": "follow https://github.com/exampleinc today"},
            )
        )
        links = [f for f in result.findings if f.finding_type == "social_link"]
        assert links and links[0].data["platform"] == "github"
