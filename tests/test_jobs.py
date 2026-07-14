from __future__ import annotations

import threading

import pytest

from lodan.ui.jobs import JobBusy, JobManager


class _Summary:
    scan_id = 42
    services_discovered = 2
    services_probed = 1
    hosts_enriched = 1
    vulns_matched = 0
    authz_rejections = 0
    diff_from = 3
    diff_total = 7


def test_success_records_summary() -> None:
    jm = JobManager(runner=lambda ws: _Summary())
    job = jm.start("w")
    job.wait(3)
    assert job.state == "completed"
    assert job.scan_id == 42
    assert job.summary["diff_total"] == 7
    assert job.finished_at is not None


def test_busy_guard_then_reusable() -> None:
    gate = threading.Event()

    def runner(ws: str) -> _Summary:
        gate.wait(2)
        return _Summary()

    jm = JobManager(runner=runner)
    job = jm.start("w")
    assert jm.is_running("w")
    with pytest.raises(JobBusy):
        jm.start("w")
    gate.set()
    job.wait(3)
    assert not jm.is_running("w")
    # a finished job frees the slot for the next scan
    jm.start("w").wait(3)


def test_failure_captured() -> None:
    def boom(ws: str):
        raise RuntimeError("no backend available")

    jm = JobManager(runner=boom)
    job = jm.start("w")
    job.wait(2)
    assert job.state == "failed"
    assert "no backend available" in job.error
    assert not jm.is_running("w")


def test_current_isolated_per_workspace() -> None:
    jm = JobManager(runner=lambda ws: _Summary())
    jm.start("a").wait(3)
    assert jm.current("b") is None
    assert jm.current("a").state == "completed"
