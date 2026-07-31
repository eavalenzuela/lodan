"""Persistence + query + diff coverage for the passive stack fingerprint.

Covers the glue rather than the leaves: that a StackObservation handed to the
discovery writer lands in the right columns, that the host rollup respects
per-port disagreement, that the DSL exposes the new pivots, and that
path_changed fires only on a real move.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from lodan.diff.scanner import compute_and_store
from lodan.discovery.base import StackObservation
from lodan.store import writer
from lodan.store.db import bootstrap, connect
from lodan.store.query import QueryError, compile, run_query


@pytest.fixture
def db(tmp_path: Path):
    dbp = tmp_path / "l.db"
    bootstrap(dbp)
    conn = connect(dbp)
    yield conn
    conn.close()


def _linux(ttl: int = 64, **kw) -> StackObservation:
    base = dict(
        ttl=ttl, window=64240, df=True, mss=1460, window_scale=7,
        sack_ok=True, timestamps=True,
        options=("MSS", "SAckOK", "Timestamp", "NOP", "WScale"),
    )
    base.update(kw)
    return StackObservation(**base)


def _windows(ttl: int = 128, **kw) -> StackObservation:
    base = dict(
        ttl=ttl, window=65535, df=True, mss=1460, window_scale=8, sack_ok=True,
        options=("MSS", "NOP", "WScale", "NOP", "NOP", "SAckOK"),
    )
    base.update(kw)
    return StackObservation(**base)


def _handle(conn) -> writer.ScanHandle:
    return writer.open_scan(conn, "w", ["10.0.0.0/24"])


# --- discovery write path ----------------------------------------------------

def test_discovery_persists_derived_stack_columns(db) -> None:
    h = _handle(db)
    writer.upsert_discovered_service(db, h, "10.0.0.5", 22, "tcp", stack=_linux(ttl=62))
    row = db.execute(
        "SELECT stack_sig, os_family, os_confidence, hop_count FROM services "
        "WHERE scan_id = ? AND ip = ? AND port = ?",
        (h.scan_id, "10.0.0.5", 22),
    ).fetchone()
    assert row[0] == "64:64240:1460:7:M,S,T,N,W:DF"
    assert row[1] == "linux"
    assert row[2] >= 0.9
    assert row[3] == 2


def test_discovery_without_stack_leaves_columns_null(db) -> None:
    """masscan / naabu see no raw packet — every derived column stays NULL."""
    h = _handle(db)
    writer.upsert_discovered_service(db, h, "10.0.0.6", 80, "tcp")
    row = db.execute(
        "SELECT stack_sig, os_family, os_confidence, hop_count, clock_key "
        "FROM services WHERE scan_id = ?",
        (h.scan_id,),
    ).fetchone()
    assert row == (None, None, None, None, None)


def test_clock_key_persisted_when_timestamps_present(db) -> None:
    h = _handle(db)
    writer.upsert_discovered_service(
        db, h, "10.0.0.7", 22, "tcp",
        stack=_linux(ts_val=5_000_000, observed_at=1_700_000_000.0),
    )
    (key,) = db.execute(
        "SELECT clock_key FROM services WHERE scan_id = ?", (h.scan_id,)
    ).fetchone()
    assert key is not None and key.startswith("1000:")


# --- host rollup -------------------------------------------------------------

def test_host_rollup_agrees_across_ports(db) -> None:
    h = _handle(db)
    for port in (22, 80, 443):
        writer.upsert_discovered_service(db, h, "10.0.0.5", port, "tcp", stack=_linux(ttl=62))
    assert writer.record_host_stack(db, h) == 1
    row = db.execute(
        "SELECT stack_sig, os_family, hop_count FROM hosts WHERE scan_id = ? AND ip = ?",
        (h.scan_id, "10.0.0.5"),
    ).fetchone()
    assert row[0] == "64:64240:1460:7:M,S,T,N,W:DF"
    assert row[1] == "linux"
    assert row[2] == 2


def test_host_rollup_leaves_split_host_unresolved(db) -> None:
    """Linux on :443 and Windows on :3389 is one IP fronting two machines.

    The rollup must NOT pick a winner — the disagreement is the signal.
    """
    h = _handle(db)
    writer.upsert_discovered_service(db, h, "10.0.0.9", 443, "tcp", stack=_linux())
    writer.upsert_discovered_service(db, h, "10.0.0.9", 3389, "tcp", stack=_windows())
    writer.record_host_stack(db, h)
    row = db.execute(
        "SELECT stack_sig, os_family, os_confidence FROM hosts WHERE scan_id = ? AND ip = ?",
        (h.scan_id, "10.0.0.9"),
    ).fetchone()
    assert row == (None, None, None)


def test_host_rollup_takes_modal_hop_count(db) -> None:
    h = _handle(db)
    for port, ttl in ((22, 62), (80, 62), (443, 60)):
        writer.upsert_discovered_service(db, h, "10.0.0.5", port, "tcp", stack=_linux(ttl=ttl))
    writer.record_host_stack(db, h)
    (hops,) = db.execute(
        "SELECT hop_count FROM hosts WHERE scan_id = ? AND ip = ?", (h.scan_id, "10.0.0.5")
    ).fetchone()
    assert hops == 2


def test_host_rollup_preserves_existing_enrichment(db) -> None:
    """The rollup upserts onto whatever enrich_hosts already wrote."""
    h = _handle(db)
    writer.upsert_discovered_service(db, h, "10.0.0.5", 22, "tcp", stack=_linux())
    db.execute(
        "INSERT INTO hosts (scan_id, ip, rdns, asn) VALUES (?, ?, ?, ?)",
        (h.scan_id, "10.0.0.5", "box.corp.example.com", 64512),
    )
    writer.record_host_stack(db, h)
    row = db.execute(
        "SELECT rdns, asn, os_family FROM hosts WHERE scan_id = ? AND ip = ?",
        (h.scan_id, "10.0.0.5"),
    ).fetchone()
    assert row == ("box.corp.example.com", 64512, "linux")


def test_host_rollup_skips_hosts_with_no_signal(db) -> None:
    h = _handle(db)
    writer.upsert_discovered_service(db, h, "10.0.0.6", 80, "tcp")
    assert writer.record_host_stack(db, h) == 0
    assert db.execute("SELECT COUNT(*) FROM hosts").fetchone()[0] == 0


# --- query DSL ---------------------------------------------------------------

def test_dsl_exposes_stack_pivots(db) -> None:
    h = _handle(db)
    writer.upsert_discovered_service(db, h, "10.0.0.5", 22, "tcp", stack=_linux())
    writer.upsert_discovered_service(db, h, "10.0.0.9", 3389, "tcp", stack=_windows())

    linux = run_query(db, "os_family:linux", scan_id=h.scan_id)
    assert [r["ip"] for r in linux] == ["10.0.0.5"]

    exact = run_query(db, f'stack_sig:"{linux[0]["stack_sig"]}"', scan_id=h.scan_id)
    assert [r["ip"] for r in exact] == ["10.0.0.5"]

    hops = run_query(db, "hop_count:0", scan_id=h.scan_id)
    assert {r["ip"] for r in hops} == {"10.0.0.5", "10.0.0.9"}


def test_dsl_stack_sig_wildcard_groups_by_initial_ttl(db) -> None:
    h = _handle(db)
    writer.upsert_discovered_service(db, h, "10.0.0.5", 22, "tcp", stack=_linux())
    writer.upsert_discovered_service(db, h, "10.0.0.9", 3389, "tcp", stack=_windows())
    rows = run_query(db, "stack_sig:128:*", scan_id=h.scan_id)
    assert [r["ip"] for r in rows] == ["10.0.0.9"]


def test_dsl_hop_count_rejects_wildcards() -> None:
    with pytest.raises(QueryError):
        compile("hop_count:*")


def test_dsl_combines_stack_with_existing_keys(db) -> None:
    h = _handle(db)
    writer.upsert_discovered_service(db, h, "10.0.0.5", 22, "tcp", stack=_linux())
    writer.upsert_discovered_service(db, h, "10.0.0.5", 80, "tcp", stack=_linux())
    rows = run_query(db, "os_family:linux AND port:22", scan_id=h.scan_id)
    assert [(r["ip"], r["port"]) for r in rows] == [("10.0.0.5", 22)]


# --- path_changed diff -------------------------------------------------------

def _two_scans(conn) -> tuple[writer.ScanHandle, writer.ScanHandle]:
    a = writer.open_scan(conn, "w", ["10.0.0.0/24"])
    writer.finish_scan(conn, a)
    b = writer.open_scan(conn, "w", ["10.0.0.0/24"])
    writer.finish_scan(conn, b)
    return a, b


def test_path_changed_fires_on_hop_count_move(db) -> None:
    a, b = _two_scans(db)
    writer.upsert_discovered_service(db, a, "10.0.0.5", 22, "tcp", stack=_linux(ttl=62))
    writer.upsert_discovered_service(db, b, "10.0.0.5", 22, "tcp", stack=_linux(ttl=59))
    counts = compute_and_store(db, a.scan_id, b.scan_id)
    assert counts.path_changed == 1
    (raw,) = db.execute(
        "SELECT detail FROM scan_diffs WHERE kind = 'path_changed'"
    ).fetchone()
    detail = json.loads(raw)
    assert detail["hop_count"] == {"from": 2, "to": 5}
    assert detail["stack_sig"]["from"] == detail["stack_sig"]["to"]


def test_path_changed_fires_when_os_flips_under_a_stable_banner(db) -> None:
    """Same port, same banner, different machine underneath."""
    a, b = _two_scans(db)
    writer.upsert_discovered_service(db, a, "10.0.0.5", 443, "tcp", stack=_linux())
    writer.upsert_discovered_service(db, b, "10.0.0.5", 443, "tcp", stack=_windows())
    counts = compute_and_store(db, a.scan_id, b.scan_id)
    assert counts.path_changed == 1
    assert counts.changed == 0     # nothing at the service layer moved


def test_path_changed_silent_when_stack_is_identical(db) -> None:
    a, b = _two_scans(db)
    writer.upsert_discovered_service(db, a, "10.0.0.5", 22, "tcp", stack=_linux(ttl=62))
    writer.upsert_discovered_service(db, b, "10.0.0.5", 22, "tcp", stack=_linux(ttl=62))
    assert compute_and_store(db, a.scan_id, b.scan_id).path_changed == 0


def test_path_changed_ignores_null_sides(db) -> None:
    """Switching backends mid-history must not report the whole estate moved."""
    a, b = _two_scans(db)
    writer.upsert_discovered_service(db, a, "10.0.0.5", 22, "tcp", stack=_linux())
    writer.upsert_discovered_service(db, b, "10.0.0.5", 22, "tcp")  # no raw packet
    assert compute_and_store(db, a.scan_id, b.scan_id).path_changed == 0


def test_path_changed_counts_toward_diff_total(db) -> None:
    a, b = _two_scans(db)
    writer.upsert_discovered_service(db, a, "10.0.0.5", 22, "tcp", stack=_linux(ttl=62))
    writer.upsert_discovered_service(db, b, "10.0.0.5", 22, "tcp", stack=_linux(ttl=59))
    counts = compute_and_store(db, a.scan_id, b.scan_id)
    assert counts.total == counts.as_dict()["total"] == 1
    assert counts.as_dict()["path_changed"] == 1
