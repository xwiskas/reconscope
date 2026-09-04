"""Subprocess supervisor with timeout, output caps, and process-tree kill.

Safety-critical (PRD §12.5, §16.2): external tools are launched with an argument
array and ``shell=False`` — never a shell string — and the whole process tree is
terminated on cancellation or timeout so a scan cannot outlive its job.
"""

from __future__ import annotations

import subprocess
import sys
import threading
import time
from dataclasses import dataclass

_OUTPUT_LIMIT = 10 * 1024 * 1024  # 10 MiB (matches evidence budget)
_IS_WIN = sys.platform == "win32"


@dataclass(frozen=True)
class ProcessResult:
    returncode: int | None
    stdout: bytes
    stderr: bytes
    timed_out: bool
    cancelled: bool
    truncated: bool
    duration_s: float
    argv: list[str]


class ProcessError(RuntimeError):
    pass


def _reader(stream, sink: bytearray, limit: int, flags: dict) -> None:
    try:
        while True:
            chunk = stream.read(65536)
            if not chunk:
                break
            if len(sink) < limit:
                room = limit - len(sink)
                sink.extend(chunk[:room])
                if len(chunk) > room:
                    flags["truncated"] = True
            else:
                flags["truncated"] = True
    except Exception:  # pragma: no cover - stream closed during kill
        pass


def _kill_tree(proc: subprocess.Popen) -> None:
    if proc.poll() is not None:
        return
    if _IS_WIN:
        # taskkill terminates the process and its children (/T) forcibly (/F).
        subprocess.run(
            ["taskkill", "/PID", str(proc.pid), "/T", "/F"],
            capture_output=True,
            check=False,
        )
    else:
        import os
        import signal

        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except ProcessLookupError:  # pragma: no cover
            pass


class SubprocessRunner:
    """Runs one external command with bounded time, output, and a kill switch."""

    def run(
        self,
        argv: list[str],
        *,
        timeout_s: float,
        output_limit: int = _OUTPUT_LIMIT,
        cancel: threading.Event | None = None,
        poll_interval: float = 0.05,
    ) -> ProcessResult:
        if not argv or not isinstance(argv, list):
            raise ProcessError("argv must be a non-empty list (shell=False)")

        popen_kwargs: dict = {
            "stdout": subprocess.PIPE,
            "stderr": subprocess.PIPE,
            "shell": False,
        }
        if _IS_WIN:
            # New process group so the whole tree can be signalled/killed.
            popen_kwargs["creationflags"] = subprocess.CREATE_NEW_PROCESS_GROUP
        else:
            popen_kwargs["start_new_session"] = True

        start = time.monotonic()
        proc = subprocess.Popen(argv, **popen_kwargs)  # noqa: S603 (argv, no shell)

        out = bytearray()
        err = bytearray()
        flags = {"truncated": False}
        t_out = threading.Thread(
            target=_reader, args=(proc.stdout, out, output_limit, flags), daemon=True
        )
        t_err = threading.Thread(
            target=_reader, args=(proc.stderr, err, output_limit, flags), daemon=True
        )
        t_out.start()
        t_err.start()

        deadline = start + timeout_s
        timed_out = False
        cancelled = False
        while True:
            if proc.poll() is not None:
                break
            now = time.monotonic()
            if cancel is not None and cancel.is_set():
                cancelled = True
                _kill_tree(proc)
                break
            if now >= deadline:
                timed_out = True
                _kill_tree(proc)
                break
            time.sleep(poll_interval)

        # Ensure the process is reaped and readers finish.
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:  # pragma: no cover
            _kill_tree(proc)
            proc.wait(timeout=5)
        t_out.join(timeout=2)
        t_err.join(timeout=2)

        return ProcessResult(
            returncode=proc.returncode,
            stdout=bytes(out),
            stderr=bytes(err),
            timed_out=timed_out,
            cancelled=cancelled,
            truncated=flags["truncated"],
            duration_s=time.monotonic() - start,
            argv=list(argv),
        )
