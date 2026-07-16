"""Authorization ledger: append-only, immutable, survives retention prune."""
from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from lodan.retention import apply as retention_apply
from lodan.store import writer
from lodan.store.db import bootstrap, connect


@pytest.fixture
def conn(tmp_path: Path):
    dbp = tmp_path / "lodan.db"
    bootstrap(dbp)
    c = connect(dbp)
    yield c
    c.close()


def _open_scan(c) -> int:
    return writer.open_scan(c, workspace="w", cidrs=["10.0.0.0/24"]).scan_id


def test_append_and_read_back(conn: sqlite3.Connection) -> None:
    sid = _open_scan(conn)
    writer.record_authz_decision(
        conn, scan_id=sid, workspace="w", operator="alice",
        decision="authorized", scope_kind="cidr", target="10.0.0.0/24",
    )
    writer.record_authz_decision(
        conn, scan_id=sid, workspace="w", operator="alice",
        decision="refused", scope_kind="target", target="8.8.8.8",
        port=53, proto="udp", reason="not in authorized_ranges",
    )
    rows = writer.iter_authz_ledger(conn)
    assert [r["decision"] for r in rows] == ["authorized", "refused"]
    refused = rows[1]
    assert refused["target"] == "8.8.8.8"
    assert refused["port"] == 53
    assert refused["proto"] == "udp"
    assert refused["operator"] == "alice"
    assert refused["ts"]


def test_decision_and_scan_filters(conn: sqlite3.Connection) -> None:
    sid = _open_scan(conn)
    writer.record_authz_decision(
        conn, scan_id=sid, workspace="w", operator=None,
        decision="authorized", scope_kind="cidr", target="10.0.0.0/24",
    )
    writer.record_authz_decision(
        conn, scan_id=sid, workspace="w", operator=None,
        decision="refused", scope_kind="target", target="1.2.3.4",
    )
    assert len(writer.iter_authz_ledger(conn, decision="refused")) == 1
    assert len(writer.iter_authz_ledger(conn, decision="authorized")) == 1
    assert len(writer.iter_authz_ledger(conn, scan_id=sid)) == 2
    assert len(writer.iter_authz_ledger(conn, scan_id=sid + 999)) == 0


def test_ledger_is_immutable(conn: sqlite3.Connection) -> None:
    sid = _open_scan(conn)
    writer.record_authz_decision(
        conn, scan_id=sid, workspace="w", operator="a",
        decision="refused", scope_kind="target", target="8.8.8.8",
    )
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("UPDATE authz_ledger SET decision = 'authorized'")
    with pytest.raises(sqlite3.IntegrityError):
        conn.execute("DELETE FROM authz_ledger")
    # Both blocked — the row is untouched.
    assert writer.iter_authz_ledger(conn)[0]["decision"] == "refused"


def test_ledger_survives_scan_prune(conn: sqlite3.Connection) -> None:
    """Pruning a scan wipes its services/errors but NOT its ledger record —
    the accountability trail is independent of scan bookkeeping."""
    sid = _open_scan(conn)
    writer.finish_scan(conn, writer.ScanHandle(sid, "w"), status="completed")
    writer.record_authz_decision(
        conn, scan_id=sid, workspace="w", operator="a",
        decision="refused", scope_kind="target", target="8.8.8.8",
    )
    # No keep knobs → the one completed scan is deleted, cascading to its
    # services/hosts/errors/diffs. The ledger has no cascading FK, so it stays.
    stats = retention_apply(conn, keep_last_n=None, keep_monthly=None, dry_run=False)
    assert stats.deleted == 1
    assert conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 0

    surviving = writer.iter_authz_ledger(conn)
    assert len(surviving) == 1
    assert surviving[0]["scan_id"] == sid  # orphaned reference is intentional
