from __future__ import annotations

import json
from pathlib import Path

import pytest

from lodan.diff.scanner import compute_and_store
from lodan.store import writer
from lodan.store.db import bootstrap, connect


@pytest.fixture
def db(tmp_path: Path):
    dbp = tmp_path / "l.db"
    bootstrap(dbp)
    conn = connect(dbp)
    yield conn
    conn.close()


def _service(conn, scan_id: int, ip: str, port: int, proto: str = "tcp", **extra) -> None:
    cols = ["scan_id", "ip", "port", "proto"] + list(extra.keys())
    vals = [scan_id, ip, port, proto] + list(extra.values())
    placeholders = ",".join(["?"] * len(cols))
    conn.execute(
        f"INSERT INTO services ({','.join(cols)}) VALUES ({placeholders})",
        vals,
    )


def _open_two_scans(conn) -> tuple[int, int]:
    a = writer.open_scan(conn, "w", ["10.0.0.0/24"]).scan_id
    writer.finish_scan(conn, writer.ScanHandle(a, "w"))
    b = writer.open_scan(conn, "w", ["10.0.0.0/24"]).scan_id
    writer.finish_scan(conn, writer.ScanHandle(b, "w"))
    return a, b


def test_new_and_gone_services(db) -> None:
    a, b = _open_two_scans(db)
    _service(db, a, "10.0.0.5", 22)
    _service(db, a, "10.0.0.5", 80)
    _service(db, b, "10.0.0.5", 22)         # kept
    _service(db, b, "10.0.0.5", 443)        # new

    counts = compute_and_store(db, a, b)
    assert counts.new_service == 1
    assert counts.gone_service == 1
    assert counts.changed == 0
    assert counts.new_host == 0
    assert counts.new_cert == 0

    rows = db.execute(
        "SELECT kind, ip, port FROM scan_diffs WHERE from_scan_id=? AND to_scan_id=? ORDER BY kind, port",
        (a, b),
    ).fetchall()
    assert ("gone_service", "10.0.0.5", 80) in rows
    assert ("new_service", "10.0.0.5", 443) in rows


def test_changed_banner(db) -> None:
    a, b = _open_two_scans(db)
    _service(db, a, "10.0.0.5", 80, banner="Apache/2.4.54")
    _service(db, b, "10.0.0.5", 80, banner="Apache/2.4.58")

    counts = compute_and_store(db, a, b)
    assert counts.changed == 1
    detail = json.loads(
        db.execute(
            "SELECT detail FROM scan_diffs WHERE kind='changed'"
        ).fetchone()[0]
    )
    assert detail["banner"] == {"from": "Apache/2.4.54", "to": "Apache/2.4.58"}


def test_changed_cert_fingerprint(db) -> None:
    a, b = _open_two_scans(db)
    _service(db, a, "10.0.0.5", 443, cert_fingerprint="aa" * 32)
    _service(db, b, "10.0.0.5", 443, cert_fingerprint="bb" * 32)
    counts = compute_and_store(db, a, b)
    assert counts.changed == 1


def test_no_change_when_identical(db) -> None:
    a, b = _open_two_scans(db)
    _service(db, a, "10.0.0.5", 22, banner="SSH-2.0-OpenSSH_9.3")
    _service(db, b, "10.0.0.5", 22, banner="SSH-2.0-OpenSSH_9.3")
    counts = compute_and_store(db, a, b)
    assert counts.total == 0


def test_new_host(db) -> None:
    a, b = _open_two_scans(db)
    _service(db, a, "10.0.0.5", 22)
    _service(db, b, "10.0.0.5", 22)
    _service(db, b, "10.0.0.9", 22)  # new IP
    counts = compute_and_store(db, a, b)
    assert counts.new_host == 1
    row = db.execute(
        "SELECT ip, port FROM scan_diffs WHERE kind='new_host'"
    ).fetchone()
    assert row == ("10.0.0.9", None)


def test_new_cert_workspace_scoped(db) -> None:
    # Three scans: cert X was seen in scan 1, cert Y first appears in scan 3.
    s1 = writer.open_scan(db, "w", ["10.0.0.0/24"]).scan_id
    writer.finish_scan(db, writer.ScanHandle(s1, "w"))
    s2 = writer.open_scan(db, "w", ["10.0.0.0/24"]).scan_id
    writer.finish_scan(db, writer.ScanHandle(s2, "w"))
    s3 = writer.open_scan(db, "w", ["10.0.0.0/24"]).scan_id
    writer.finish_scan(db, writer.ScanHandle(s3, "w"))

    _service(db, s1, "10.0.0.5", 443, cert_fingerprint="X")
    _service(db, s2, "10.0.0.5", 443, cert_fingerprint="X")
    _service(db, s3, "10.0.0.5", 443, cert_fingerprint="X")  # not new — seen before
    _service(db, s3, "10.0.0.7", 443, cert_fingerprint="Y")  # new to workspace

    counts = compute_and_store(db, s2, s3)
    assert counts.new_cert == 1
    detail = json.loads(
        db.execute("SELECT detail FROM scan_diffs WHERE kind='new_cert'").fetchone()[0]
    )
    assert detail["cert_fingerprint"] == "Y"


def test_compute_rejects_same_scan(db) -> None:
    a = writer.open_scan(db, "w", ["10.0.0.0/24"]).scan_id
    writer.finish_scan(db, writer.ScanHandle(a, "w"))
    with pytest.raises(ValueError):
        compute_and_store(db, a, a)


def test_clear_existing_makes_rerun_consistent(db) -> None:
    a, b = _open_two_scans(db)
    _service(db, a, "10.0.0.5", 22)
    _service(db, b, "10.0.0.5", 443)

    compute_and_store(db, a, b)
    compute_and_store(db, a, b)

    (count,) = db.execute(
        "SELECT COUNT(*) FROM scan_diffs WHERE from_scan_id=? AND to_scan_id=?",
        (a, b),
    ).fetchone()
    # one new_service + one gone_service = 2 rows, not 4
    assert count == 2
