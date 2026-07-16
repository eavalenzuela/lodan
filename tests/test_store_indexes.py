"""Store tuning: pivot indexes, migration of retired indexes, query plans."""
from __future__ import annotations

import sqlite3
from pathlib import Path

from lodan.store.db import bootstrap, connect

_PIVOTS = (
    "services_pivot_cert_fp",
    "services_pivot_favicon",
    "services_pivot_ja3s",
    "services_pivot_ja4s",
    "services_pivot_hostkey",
)
_RETIRED = ("services_ja3s", "services_cert_fp", "services_favicon", "services_ssh_hostkey")


def _index_names(conn) -> set[str]:
    return {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")}


def test_fresh_db_has_pivot_indexes(tmp_path: Path) -> None:
    db = tmp_path / "l.db"
    bootstrap(db)
    conn = connect(db)
    try:
        names = _index_names(conn)
        assert set(_PIVOTS) <= names
        # Retired single-column indexes are never created on a fresh DB.
        assert names.isdisjoint(_RETIRED)
    finally:
        conn.close()


def test_upgrade_drops_retired_indexes(tmp_path: Path) -> None:
    db = tmp_path / "l.db"
    # Simulate an old workspace carrying the retired single-column indexes.
    raw = sqlite3.connect(db)
    raw.executescript(
        "CREATE TABLE services (scan_id INTEGER, ip TEXT, port INTEGER, proto TEXT, "
        "ja3s TEXT, cert_fingerprint TEXT, favicon_mmh3 INTEGER, ssh_hostkey TEXT);"
        "CREATE INDEX services_ja3s ON services(ja3s);"
        "CREATE INDEX services_cert_fp ON services(cert_fingerprint);"
    )
    raw.commit()
    raw.close()

    bootstrap(db)  # runs ensure_schema -> drops retired, creates pivots
    conn = connect(db)
    try:
        names = _index_names(conn)
        assert names.isdisjoint(_RETIRED)
        assert set(_PIVOTS) <= names
    finally:
        conn.close()


def test_pivot_query_uses_index_without_temp_sort(tmp_path: Path) -> None:
    db = tmp_path / "l.db"
    bootstrap(db)
    conn = connect(db)
    try:
        plan = "\n".join(
            row[-1]
            for row in conn.execute(
                "EXPLAIN QUERY PLAN "
                "SELECT scan_id, ip, port, service, banner, ja3s FROM services "
                "WHERE ja3s = ? ORDER BY scan_id DESC, ip, port",
                ("x",),
            )
        )
        assert "services_pivot_ja3s" in plan
        # scan_id DESC in the index means the ORDER BY needs no temp b-tree.
        assert "TEMP B-TREE" not in plan.upper()
    finally:
        conn.close()
