"""Tests for Nmap capability detection (injected probes; no real nmap needed)."""

from reconscope.tools.capability import detect_nmap


def test_missing_nmap():
    cap = detect_nmap(which=lambda _n: None)
    assert cap.available is False
    assert "not found" in cap.error
    assert cap.install_hint  # guidance is always provided


def test_detects_version():
    cap = detect_nmap(
        which=lambda _n: r"C:\Program Files (x86)\Nmap\nmap.exe",
        version_probe=lambda _p: "Nmap version 7.94 ( https://nmap.org )",
    )
    assert cap.available is True
    assert cap.version == "7.94"


def test_unparseable_version():
    cap = detect_nmap(which=lambda _n: "nmap", version_probe=lambda _p: "garbage")
    assert cap.available is False
    assert "version" in cap.error
