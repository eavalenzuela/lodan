from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from lodan.probes import dispatch
from lodan.probes.base import ProbeResult
from lodan.probes.runner import ProbeBudget, run_probes
from lodan.store import writer
from lodan.store.db import bootstrap, connect


class _RecordingProbe:
    name = "recording"
    default_ports = frozenset({22, 80, 443})

    calls: list[tuple[str, int]] = []

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        _RecordingProbe.calls.append((ip, port))
        return ProbeResult(
            service="recording",
            banner=f"seen {ip}:{port}",
            cert_fingerprint="deadbeef" if port == 443 else None,
            tech=["recording"],
        )


class _FailingProbe:
    name = "failing"
    default_ports = frozenset({999})

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raise RuntimeError("boom")


@pytest.fixture
def db(tmp_path: Path):
    dbp = tmp_path / "l.db"
    bootstrap(dbp)
    conn = connect(dbp)
    yield conn
    conn.close()


def test_runner_dispatches_by_port(db) -> None:
    _RecordingProbe.calls.clear()
    dispatch.clear_registry()
    dispatch.register("recording", _RecordingProbe)

    handle = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, handle, "10.0.0.5", 22, "tcp")
    writer.upsert_discovered_service(db, handle, "10.0.0.5", 443, "tcp")
    writer.upsert_discovered_service(db, handle, "10.0.0.5", 12345, "tcp")  # unmapped
    writer.upsert_discovered_service(db, handle, "10.0.0.5", 53, "udp")     # UDP skipped

    probed = asyncio.run(run_probes(db, handle, ProbeBudget()))
    assert probed == 2
    assert set(_RecordingProbe.calls) == {("10.0.0.5", 22), ("10.0.0.5", 443)}


def test_runner_writes_probe_result_back_into_service(db) -> None:
    dispatch.clear_registry()
    dispatch.register("recording", _RecordingProbe)
    handle = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, handle, "10.0.0.5", 443, "tcp")

    asyncio.run(run_probes(db, handle, ProbeBudget()))

    row = db.execute(
        "SELECT service, banner, cert_fingerprint, tech FROM services "
        "WHERE scan_id = ? AND ip = ? AND port = ?",
        (handle.scan_id, "10.0.0.5", 443),
    ).fetchone()
    assert row[0] == "recording"
    assert row[1] == "seen 10.0.0.5:443"
    assert row[2] == "deadbeef"
    assert '"recording"' in row[3]


def test_runner_records_failures_without_crashing(db) -> None:
    dispatch.clear_registry()
    dispatch.register("failing", _FailingProbe)

    handle = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, handle, "10.0.0.5", 999, "tcp")

    probed = asyncio.run(run_probes(db, handle, ProbeBudget(retries=0)))
    assert probed == 0

    (err,) = db.execute(
        "SELECT error FROM scan_errors WHERE scan_id = ? AND stage = ?",
        (handle.scan_id, "probe:failing"),
    ).fetchone()
    assert "boom" in err


def test_runner_no_tuples_returns_zero(db) -> None:
    dispatch.clear_registry()
    dispatch.register("recording", _RecordingProbe)
    handle = writer.open_scan(db, "w", ["10.0.0.0/24"])
    probed = asyncio.run(run_probes(db, handle, ProbeBudget()))
    assert probed == 0
