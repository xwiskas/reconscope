"""Tests for frozen-build path resolution and installer artifacts (M4)."""

import sys
from pathlib import Path

from reconscope.main import frontend_dist_dir

_REPO_ROOT = Path(__file__).resolve().parents[2]


def test_frozen_dist_is_found_next_to_bundle(monkeypatch, tmp_path):
    bundled = tmp_path / "frontend_dist"
    bundled.mkdir()
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    assert frontend_dist_dir() == bundled


def test_frozen_dist_none_when_missing(monkeypatch, tmp_path):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    monkeypatch.setattr(sys, "_MEIPASS", str(tmp_path), raising=False)
    assert frontend_dist_dir() is None


def test_entry_point_importable():
    import importlib

    launcher = importlib.import_module("reconscope.launcher")
    assert callable(launcher.main)


def test_installer_artifacts_exist():
    for name in ("reconscope.spec", "reconscope.iss", "build.ps1"):
        assert (_REPO_ROOT / "installer" / name).is_file(), name
