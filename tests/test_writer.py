from __future__ import annotations

import json
from pathlib import Path

import pytest

from lodan.store import writer
from lodan.store.db import bootstrap, connect


@pytest.fixture
def db_conn(tmp_path: Path):
    db = tmp_path / "lodan.db"
    bootstrap(db)
    conn = connect(db)
    yield conn
    conn.close()


def test_open_and_finish_scan(db_conn) -> None:
    handle = writer.open_scan(db_conn, "home-lab", ["10.0.0.0/24"], seed=42)
    row = db_conn.execute(
        "SELECT workspace, cidrs, seed, status, finished_at FROM scans WHERE id = ?",
        (handle.scan_id,),
    ).fetchone()
    assert row[0] == "home-lab"
    assert json.loads(row[1]) == ["10.0.0.0/24"]
    assert row[2] == 42
    assert row[3] == "running"
    assert row[4] is None

    writer.finish_scan(db_conn, handle)
    row = db_conn.execute(
        "SELECT status, finished_at FROM scans WHERE id = ?", (handle.scan_id,)
    ).fetchone()
    assert row[0] == "completed"
    assert row[1] is not None


def test_finish_scan_rejects_invalid_status(db_conn) -> None:
    handle = writer.open_scan(db_conn, "w", ["10.0.0.0/24"])
    with pytest.raises(ValueError):
        writer.finish_scan(db_conn, handle, status="weird")


def test_record_error(db_conn) -> None:
    handle = writer.open_scan(db_conn, "w", ["10.0.0.0/24"])
    writer.record_error(db_conn, handle, stage="discovery", error="timed out", ip="10.0.0.1")
    row = db_conn.execute(
        "SELECT stage, error, ip FROM scan_errors WHERE scan_id = ?", (handle.scan_id,)
    ).fetchone()
    assert row == ("discovery", "timed out", "10.0.0.1")


def test_upsert_discovered_service_is_idempotent(db_conn) -> None:
    handle = writer.open_scan(db_conn, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db_conn, handle, "10.0.0.5", 22, "tcp")
    writer.upsert_discovered_service(db_conn, handle, "10.0.0.5", 22, "tcp")
    (count,) = db_conn.execute(
        "SELECT COUNT(*) FROM services WHERE scan_id = ?", (handle.scan_id,)
    ).fetchone()
    assert count == 1


def test_discovered_tuples_round_trip(db_conn) -> None:
    handle = writer.open_scan(db_conn, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db_conn, handle, "10.0.0.5", 22, "tcp")
    writer.upsert_discovered_service(db_conn, handle, "10.0.0.5", 53, "udp")
    assert writer.discovered_tuples(db_conn, handle) == {
        ("10.0.0.5", 22, "tcp"),
        ("10.0.0.5", 53, "udp"),
    }
