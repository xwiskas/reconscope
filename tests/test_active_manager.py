"""Background active-job manager: progress events and cancellation."""

import threading
import time

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from reconscope.evidence.store import EvidenceStore
from reconscope.jobs.manager import ActiveJobManager
from reconscope.jobs.process import ProcessResult
from reconscope.models import (
    AuthorizationRecord,
    Base,
    Job,
    Project,
    ScopeEntry,
)
from reconscope.providers.dns import DnsAnswer, DnsStatus
from reconscope.scope.canonical import TargetType
from tests.conftest import (
    SAMPLE_NMAP_XML,
    FakeProcessRunner,
    FakeResolver,
    available_nmap,
    make_services,
)


class BlockingProcessRunner:
    """Blocks until cancelled (or timeout), so cancellation can be exercised."""

    def __init__(self):
        self.started = threading.Event()

    def run(self, argv, *, timeout_s, output_limit=0, cancel=None, poll_interval=0.05):
        self.started.set()
        cancelled = False
        if cancel is not None:
            cancel.wait(timeout=min(timeout_s, 5))
            cancelled = cancel.is_set()
        return ProcessResult(
            returncode=None if cancelled else 0,
            stdout=SAMPLE_NMAP_XML,
            stderr=b"",
            timed_out=False,
            cancelled=cancelled,
            truncated=False,
            duration_s=0.1,
            argv=list(argv),
        )


def _seed(factory):
    session = factory()
    project = Project(name="Bg")
    session.add(project)
    session.flush()
    session.add(
        ScopeEntry(
            project_id=project.id, entry_type="domain",
            normalized_value="example.com", entered_value="example.com", enabled=True,
        )
    )
    session.add(
        AuthorizationRecord(
            project_id=project.id, attestation_text="ok", notice_version="v1",
        )
    )
    session.commit()
    pid = project.id
    session.close()
    return pid


def _factory(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'm.db'}", future=True)
    Base.metadata.create_all(engine)
    return sessionmaker(bind=engine, expire_on_commit=False, future=True)


def _wait_terminal(handle, timeout=8.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        _events, terminal = handle.snapshot(0)
        if terminal:
            return
        time.sleep(0.05)
    raise AssertionError("job did not reach a terminal state in time")


def test_happy_path_emits_terminal_success(tmp_path):
    factory = _factory(tmp_path)
    pid = _seed(factory)
    resolver = FakeResolver(
        answers={
            ("example.com", "A"): DnsAnswer(
                "example.com", "A", DnsStatus.OK, ("203.0.113.10",), 300, "fake"
            )
        }
    )
    services = make_services(
        process_runner=FakeProcessRunner(stdout=SAMPLE_NMAP_XML),
        nmap=available_nmap(), resolver=resolver,
    )
    manager = ActiveJobManager(factory, EvidenceStore(tmp_path / "ev"), lambda: services)

    job_id = manager.submit(
        project_id=pid, module_id="active.tcp_scan", target="example.com",
        target_type=TargetType.HOSTNAME, config={"preset": "quick"},
    )
    handle = manager.handle(job_id)
    _wait_terminal(handle)
    events, terminal = handle.snapshot(0)
    assert terminal
    types = [e.type for e in events]
    assert "running" in types and "pinned" in types
    assert events[-1].status == "succeeded"


def test_cancellation_terminates_job(tmp_path):
    factory = _factory(tmp_path)
    pid = _seed(factory)
    resolver = FakeResolver(
        answers={
            ("example.com", "A"): DnsAnswer(
                "example.com", "A", DnsStatus.OK, ("203.0.113.10",), 300, "fake"
            )
        }
    )
    blocker = BlockingProcessRunner()
    services = make_services(
        process_runner=blocker, nmap=available_nmap(), resolver=resolver
    )
    manager = ActiveJobManager(factory, EvidenceStore(tmp_path / "ev"), lambda: services)

    job_id = manager.submit(
        project_id=pid, module_id="active.tcp_scan", target="example.com",
        target_type=TargetType.HOSTNAME, config={"preset": "quick"},
    )
    assert blocker.started.wait(timeout=5)  # the scan is running
    assert manager.cancel(job_id) is True

    handle = manager.handle(job_id)
    _wait_terminal(handle)
    events, _ = handle.snapshot(0)
    terminal = events[-1]
    assert terminal.status in ("partial", "failed")
    assert terminal.data.get("error_code") == "cancelled"

    # The job row reflects a non-success terminal state.
    session = factory()
    job = session.get(Job, job_id)
    assert job is not None and job.status in ("partial", "failed")
    session.close()


def test_cancel_unknown_job_returns_false(tmp_path):
    factory = _factory(tmp_path)
    manager = ActiveJobManager(factory, EvidenceStore(tmp_path / "ev"), lambda: None)
    assert manager.cancel("nope") is False
