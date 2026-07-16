"""SQLite connection + schema bootstrap helpers."""
from __future__ import annotations

import sqlite3
from importlib.resources import files
from pathlib import Path


def schema_sql() -> str:
    return (files("lodan.store") / "schema.sql").read_text(encoding="utf-8")


def connect(path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(path, isolation_level=None)
    conn.execute("PRAGMA foreign_keys = ON")
    # WAL lets the UI read while a scan writes, but only one writer holds the
    # lock at a time. Wait for it instead of erroring immediately with
    # SQLITE_BUSY — the web UI can now issue writes (favicon labels) that may
    # coincide with a background scan.
    conn.execute("PRAGMA busy_timeout = 5000")
    return conn


# Columns added to `services` after the initial schema shipped. Applied to
# pre-existing workspace DBs before schema.sql runs, so the matching indices
# (e.g. services_ja4s) don't reference a column that isn't there yet.
_SERVICES_COLUMN_MIGRATIONS = (
    ("ja4", "TEXT"),
    ("ja4s", "TEXT"),
    ("ssh_hostkey", "TEXT"),
)


def _migrate_services_columns(conn: sqlite3.Connection) -> None:
    existing = {row[1] for row in conn.execute("PRAGMA table_info(services)")}
    if not existing:
        return  # fresh DB — schema.sql creates `services` with every column
    for name, col_type in _SERVICES_COLUMN_MIGRATIONS:
        if name not in existing:
            conn.execute(f"ALTER TABLE services ADD COLUMN {name} {col_type}")


# Single-column pivot indexes superseded by the partial composite ones in
# schema.sql. DROP IF EXISTS is a cheap no-op once they're gone (and on fresh
# DBs that never had them), so this is safe to run on every ensure_schema.
_RETIRED_INDEXES = (
    "services_cert_fp",
    "services_favicon",
    "services_ja3s",
    "services_ja4s",
    "services_ssh_hostkey",
)


def _drop_retired_indexes(conn: sqlite3.Connection) -> None:
    for name in _RETIRED_INDEXES:
        conn.execute(f"DROP INDEX IF EXISTS {name}")


def ensure_schema(conn: sqlite3.Connection) -> None:
    """Apply schema.sql idempotently to an open connection.

    schema.sql is all `CREATE ... IF NOT EXISTS`, so this is safe to run on a
    fresh or existing DB. Callers that hold a live connection (e.g. the scan
    orchestrator) run this so newly-shipped tables — like `authz_ledger` — exist
    on workspace DBs created before that table was added, without waiting for a
    re-`init`. (A first-class schema_version + migration runner is a separate
    planned item; this is the idempotent stopgap.)
    """
    _migrate_services_columns(conn)
    conn.executescript(schema_sql())
    _drop_retired_indexes(conn)


def bootstrap(path: Path) -> None:
    """Create the DB file and apply schema.sql. Safe to run on an existing DB."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    try:
        ensure_schema(conn)
    finally:
        conn.close()
