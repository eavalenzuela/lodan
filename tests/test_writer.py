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


def _seed_favicon(conn, handle, ip, port, mmh3) -> None:
    writer.upsert_discovered_service(conn, handle, ip, port, "tcp")
    conn.execute(
        "UPDATE services SET favicon_mmh3 = ? WHERE scan_id = ? AND ip = ? AND port = ?",
        (mmh3, handle.scan_id, ip, port),
    )


def test_record_favicons_first_seen_wins_across_scans(db_conn) -> None:
    h1 = writer.open_scan(db_conn, "w", ["10.0.0.0/24"])
    _seed_favicon(db_conn, h1, "10.0.0.5", 443, 12345)
    _seed_favicon(db_conn, h1, "10.0.0.9", 443, 12345)  # same hash, later ip
    writer.finish_scan(db_conn, h1)
    assert writer.record_favicons(db_conn, h1) == 2

    h2 = writer.open_scan(db_conn, "w", ["10.0.0.0/24"])
    _seed_favicon(db_conn, h2, "10.0.0.11", 443, 12345)  # same hash, later scan
    writer.record_favicons(db_conn, h2)

    row = db_conn.execute(
        "SELECT first_seen_scan, first_seen_ip FROM favicons WHERE mmh3 = ?", (12345,)
    ).fetchone()
    assert row == (h1.scan_id, "10.0.0.5")  # earliest scan + earliest ip retained


def test_set_and_get_favicon_label_upserts(db_conn) -> None:
    # Label can be set even before the hash is seen in a scan.
    assert writer.favicon_label(db_conn, 999) is None
    writer.set_favicon_label(db_conn, 999, "Jenkins login")
    assert writer.favicon_label(db_conn, 999) == "Jenkins login"
    writer.set_favicon_label(db_conn, 999, "Jenkins (prod)")
    assert writer.favicon_label(db_conn, 999) == "Jenkins (prod)"


def test_record_favicons_preserves_label(db_conn) -> None:
    writer.set_favicon_label(db_conn, 12345, "Grafana")
    h1 = writer.open_scan(db_conn, "w", ["10.0.0.0/24"])
    _seed_favicon(db_conn, h1, "10.0.0.5", 443, 12345)
    writer.record_favicons(db_conn, h1)
    # INSERT OR IGNORE must not wipe an existing operator label.
    assert writer.favicon_label(db_conn, 12345) == "Grafana"
