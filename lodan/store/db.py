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


def bootstrap(path: Path) -> None:
    """Create the DB file and apply schema.sql. Safe to run on an existing DB."""
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = connect(path)
    try:
        conn.executescript(schema_sql())
    finally:
        conn.close()
