"""In-process background scan runner for the web UI.

The UI's read paths open their own SQLite connection per request; a scan opens
its own connection on its own thread, and SQLite's WAL mode lets the UI keep
reading while the scan writes. We allow at most one scan per workspace at a
time — concurrent scans would race on the `scans` table and the auto-diff — and
track live state in memory so the dashboard can poll it. Durable status also
lands in the `scans` table (running/completed/failed) via the scan pipeline, so
a job lost to a server restart is still visible there.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from datetime import UTC, datetime


class JobBusy(RuntimeError):
    """A scan is already running for this workspace."""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _default_runner(workspace: str):
    # Imported lazily so pulling in the UI doesn't drag the whole scan/probe
    # stack in at import time.
    from lodan.scan import run_scan_sync

    return run_scan_sync(workspace)


@dataclass
class ScanJob:
    workspace: str
    state: str = "running"          # running | completed | failed
    started_at: str = field(default_factory=_now)
    finished_at: str | None = None
    scan_id: int | None = None
    error: str | None = None
    summary: dict | None = None     # display counts, set on success
    _thread: threading.Thread | None = field(default=None, repr=False)

    def wait(self, timeout: float | None = None) -> None:
        """Block until the job finishes (mainly a test convenience)."""
        if self._thread is not None:
            self._thread.join(timeout)


class JobManager:
    """Tracks the (at most one) in-flight scan per workspace.

    `runner` is injectable so tests can drive job state without spinning up a
    real scan; it defaults to running the full pipeline via `run_scan_sync`.
    """

    def __init__(self, runner=None) -> None:
        self._runner = runner or _default_runner
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.Lock()

    def current(self, workspace: str) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(workspace)

    def is_running(self, workspace: str) -> bool:
        job = self.current(workspace)
        return job is not None and job.state == "running"

    def start(self, workspace: str) -> ScanJob:
        with self._lock:
            existing = self._jobs.get(workspace)
            if existing is not None and existing.state == "running":
                raise JobBusy(f"a scan is already running for {workspace}")
            job = ScanJob(workspace=workspace)
            self._jobs[workspace] = job
        thread = threading.Thread(
            target=self._run, args=(job,), name=f"lodan-scan-{workspace}", daemon=True
        )
        job._thread = thread
        thread.start()
        return job

    def _run(self, job: ScanJob) -> None:
        try:
            summary = self._runner(job.workspace)
        except Exception as e:  # noqa: BLE001 — surface any failure to the UI
            with self._lock:
                job.state = "failed"
                job.error = f"{type(e).__name__}: {e}"
                job.finished_at = _now()
            return
        with self._lock:
            job.state = "completed"
            job.finished_at = _now()
            job.scan_id = getattr(summary, "scan_id", None)
            job.summary = _summary_dict(summary)


def _summary_dict(summary) -> dict:
    keys = (
        "scan_id",
        "services_discovered",
        "services_probed",
        "hosts_enriched",
        "vulns_matched",
        "authz_rejections",
        "diff_from",
        "diff_total",
    )
    return {k: getattr(summary, k, None) for k in keys}
