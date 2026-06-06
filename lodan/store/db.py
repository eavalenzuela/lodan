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


def bootstrap(path: Path) -> None:
    """Create the DB file and apply schema.sql. Safe to run on an existing DB."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    try:
        _migrate_services_columns(conn)
        conn.executescript(schema_sql())
    finally:
        conn.close()
