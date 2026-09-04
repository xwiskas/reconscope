"""Unit tests for active modules with fake tools (no real nmap/network)."""

import httpx
import pytest

from reconscope.modules.active.http_overview import HttpOverview
from reconscope.modules.active.ports import PortSpecError, parse_port_spec
from reconscope.modules.active.service_detection import ServiceDetection
from reconscope.modules.active.tcp_scan import TcpScan
from reconscope.modules.active.tls_review import TlsReview
from reconscope.modules.runtime import RunContext
from reconscope.providers.tls import TlsInfo
from reconscope.scope.canonical import TargetType, canonicalize_scope_entry
from tests.conftest import (
    SAMPLE_NMAP_XML,
    FakeProcessRunner,
    available_nmap,
    make_services,
)


def _ctx(target, services, config=None, ttype=TargetType.IP):
    return RunContext(target=target, target_type=ttype, services=services, config=config or {})


class TestPortSpec:
    def test_valid(self):
        assert parse_port_spec("80,443,8000-8002") == ("80,443,8000,8001,8002", 5)

    @pytest.mark.parametrize("bad", ["80; rm -rf /", "$(x)", "80|443", "-p80", "abc", ""])
    def test_rejects_injection(self, bad):
        with pytest.raises(PortSpecError):
            parse_port_spec(bad)


class TestTcpScan:
    def test_parses_ports_and_builds_safe_argv(self):
        runner = FakeProcessRunner(stdout=SAMPLE_NMAP_XML)
        services = make_services(process_runner=runner, nmap=available_nmap())
        result = TcpScan().run(_ctx("203.0.113.10", services, {"preset": "quick"}))
        assert result.status == "succeeded"
        states = {f.value: f.data["state"] for f in result.findings}
        assert states["22/tcp"] == "open"
        assert states["443/tcp"] == "filtered"
        # argv is a list (shell=False) with the expected safe flags.
        argv = runner.calls[0]
        assert isinstance(argv, list)
        assert "-sT" in argv and "-Pn" in argv
        assert argv[argv.index("--top-ports") + 1] == "100"
        assert argv[-1] == "203.0.113.10"

    def test_nmap_unavailable(self):
        from reconscope.tools.capability import NmapCapability

        services = make_services(
            process_runner=FakeProcessRunner(), nmap=NmapCapability(available=False)
        )
        result = TcpScan().run(_ctx("203.0.113.10", services, {"preset": "quick"}))
        assert result.status == "failed"
        assert result.error_code == "nmap_unavailable"

    def test_invalid_custom_ports_never_runs_process(self):
        runner = FakeProcessRunner(stdout=SAMPLE_NMAP_XML)
        services = make_services(process_runner=runner, nmap=available_nmap())
        result = TcpScan().run(
            _ctx("203.0.113.10", services, {"preset": "custom", "ports": "80; drop"})
        )
        assert result.status == "failed"
        assert result.error_code == "invalid_ports"
        assert runner.calls == []  # nothing reached the process runner

    def test_timeout_marks_partial(self):
        runner = FakeProcessRunner(stdout=SAMPLE_NMAP_XML, timed_out=True, returncode=1)
        services = make_services(process_runner=runner, nmap=available_nmap())
        result = TcpScan().run(_ctx("203.0.113.10", services, {"preset": "quick"}))
        assert result.status == "partial"
        assert result.error_code == "timeout"


class TestServiceDetection:
    def test_fingerprints_services(self):
        runner = FakeProcessRunner(stdout=SAMPLE_NMAP_XML)
        services = make_services(process_runner=runner, nmap=available_nmap())
        result = ServiceDetection().run(
            _ctx("203.0.113.10", services, {"ports": "22,80"})
        )
        assert result.status == "succeeded"
        text = " ".join(f.value for f in result.findings)
        assert "OpenSSH 9.6" in text and "nginx 1.25.4" in text
        assert "--version-light" in runner.calls[0]

    def test_requires_ports(self):
        services = make_services(process_runner=FakeProcessRunner(), nmap=available_nmap())
        result = ServiceDetection().run(_ctx("203.0.113.10", services, {}))
        assert result.error_code == "invalid_ports"


class TestHttpOverview:
    def test_simple_200(self):
        def handler(request):
            return httpx.Response(200, headers={"server": "nginx"}, text="<html>hi</html>")

        services = make_services(handler=handler)
        result = HttpOverview().run(
            _ctx("example.com", services, {"scheme": "http", "port": 80},
                 ttype=TargetType.HOSTNAME)
        )
        assert result.status == "succeeded"
        types = {f.finding_type for f in result.findings}
        assert "http_status" in types
        assert any(f.value.startswith("server:") for f in result.findings
                   if f.finding_type == "http_header")

    def test_out_of_scope_redirect_is_blocked_and_not_followed(self):
        contacted = []

        def handler(request):
            contacted.append(request.url.host)
            if request.url.host == "example.com":
                return httpx.Response(302, headers={"location": "http://evil.test/"})
            return httpx.Response(200, text="SHOULD NOT HAPPEN")

        services = make_services(handler=handler)
        result = HttpOverview().run(
            _ctx(
                "example.com",
                services,
                {
                    "scheme": "http",
                    "port": 80,
                    "scope_entries": [canonicalize_scope_entry("example.com")],
                },
                ttype=TargetType.HOSTNAME,
            )
        )
        assert "evil.test" not in contacted
        assert any(f.finding_type == "http_redirect_blocked" for f in result.findings)


class TestTlsReview:
    def test_reports_cert_fields(self):
        def fake_fetch(host, port, timeout):
            return TlsInfo(
                host=host, port=port, ok=True, version="TLSv1.3",
                cipher="TLS_AES_256_GCM_SHA384", subject="CN=example.com",
                issuer="CN=Example CA", not_before="2026-01-01T00:00:00",
                not_after="2026-12-31T00:00:00", sans=("example.com", "www.example.com"),
                validation_ok=True,
            )

        services = make_services(tls_fetcher=fake_fetch)
        result = TlsReview().run(
            _ctx("example.com", services, {"port": 443}, ttype=TargetType.HOSTNAME)
        )
        assert result.status == "succeeded"
        sans = {f.value for f in result.findings if f.finding_type == "tls_san"}
        assert sans == {"example.com", "www.example.com"}
        assert any(f.finding_type == "tls_version" for f in result.findings)

    def test_handshake_failure(self):
        def fake_fetch(host, port, timeout):
            return TlsInfo(host=host, port=port, ok=False, error="connection refused")

        services = make_services(tls_fetcher=fake_fetch)
        result = TlsReview().run(
            _ctx("example.com", services, {"port": 443}, ttype=TargetType.HOSTNAME)
        )
        assert result.status == "failed"
        assert result.error_code == "tls_handshake_failed"
