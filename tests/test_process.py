"""Subprocess supervisor tests, including process-tree cancellation."""

import sys
import threading
import time

import pytest

from reconscope.jobs.process import ProcessError, SubprocessRunner

PY = sys.executable


def test_rejects_non_list_argv():
    with pytest.raises(ProcessError):
        SubprocessRunner().run("echo hi", timeout_s=5)  # type: ignore[arg-type]


def test_captures_stdout():
    r = SubprocessRunner().run([PY, "-c", "print('hello-recon')"], timeout_s=10)
    assert r.returncode == 0
    assert b"hello-recon" in r.stdout
    assert not r.timed_out and not r.cancelled


def test_timeout_kills():
    r = SubprocessRunner().run(
        [PY, "-c", "import time; time.sleep(30)"], timeout_s=0.5
    )
    assert r.timed_out is True
    assert r.returncode != 0 or r.returncode is None


def test_output_limit_truncates():
    r = SubprocessRunner().run(
        [PY, "-c", "import sys; sys.stdout.write('x'*100000)"],
        timeout_s=10,
        output_limit=1000,
    )
    assert r.truncated is True
    assert len(r.stdout) <= 1000


def test_cancel_terminates_process_tree(tmp_path):
    """Cancelling a parent must kill the grandchild too (PRD §16.2)."""
    heartbeat = (tmp_path / "hb.txt").as_posix()
    grandchild = tmp_path / "grandchild.py"
    grandchild.write_text(
        "import time\n"
        f"p = r'{heartbeat}'\n"
        "while True:\n"
        "    open(p, 'a').write('x')\n"
        "    time.sleep(0.05)\n"
    )
    parent = tmp_path / "parent.py"
    parent.write_text(
        "import subprocess, sys, time\n"
        f"subprocess.Popen([sys.executable, r'{grandchild}'])\n"
        "time.sleep(60)\n"
    )

    cancel = threading.Event()
    threading.Timer(0.8, cancel.set).start()
    result = SubprocessRunner().run([PY, str(parent)], timeout_s=30, cancel=cancel)
    assert result.cancelled is True

    # Give any surviving grandchild a moment, then confirm it stopped writing.
    time.sleep(0.5)
    size1 = (tmp_path / "hb.txt").stat().st_size if (tmp_path / "hb.txt").exists() else 0
    time.sleep(0.8)
    size2 = (tmp_path / "hb.txt").stat().st_size if (tmp_path / "hb.txt").exists() else 0
    assert size1 == size2, "grandchild kept running — process tree was not killed"
