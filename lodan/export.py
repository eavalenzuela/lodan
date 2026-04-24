"""Workspace export: services + hosts + vulns as JSON Lines.

The export format is intentionally flat: one JSON object per line, with a
`_table` field so consumers can route by type without parsing column names.
Columns mirror the SQLite schema 1:1; JSON-array-stored fields (tech,
cert_sans) are rehydrated from their string form.

    {"_table": "scans", "id": 1, "started_at": "...", ...}
    {"_table": "hosts", "scan_id": 1, "ip": "10.0.0.5", ...}
    {"_table": "services", "scan_id": 1, "ip": "10.0.0.5", "port": 22, ...}
    {"_table": "vulns", ...}

`--format json` wraps everything in a single indented array instead.
"""
from __future__ import annotations

import contextlib
import json
import sqlite3
from collections.abc import Iterable
from typing import Any, TextIO

_TABLES = ("scans", "hosts", "services", "vulns")
_JSON_COLUMNS: dict[str, set[str]] = {
    "services": {"cert_sans", "tech", "raw"},
}


def iter_rows(
    conn: sqlite3.Connection,
    *,
    scan_id: int | None,
    tables: Iterable[str],
) -> Iterable[dict[str, Any]]:
    for table in tables:
        if table not in _TABLES:
            raise ValueError(f"unknown table: {table}")
        yield from _iter_table(conn, table, scan_id)


def _iter_table(
    conn: sqlite3.Connection,
    table: str,
    scan_id: int | None,
) -> Iterable[dict[str, Any]]:
    cursor = conn.execute(f"SELECT * FROM {table}")
    col_names = [d[0] for d in cursor.description]
    scan_col = _scan_column_for(table)
    json_cols = _JSON_COLUMNS.get(table, set())
    for row in cursor:
        record = dict(zip(col_names, row, strict=True))
        if scan_id is not None and scan_col and record.get(scan_col) != scan_id:
            continue
        for col in json_cols:
            value = record.get(col)
            if isinstance(value, str):
                with contextlib.suppress(ValueError, TypeError):
                    record[col] = json.loads(value)
            elif isinstance(value, (bytes, bytearray)):
                try:
                    record[col] = json.loads(value.decode("utf-8", "replace"))
                except (ValueError, TypeError):
                    record[col] = value.decode("utf-8", "replace")
        record["_table"] = table
        yield record


def _scan_column_for(table: str) -> str | None:
    # scans.id is the scan identifier; every other table references scan_id.
    if table == "scans":
        return "id"
    return "scan_id"


def write_jsonl(records: Iterable[dict[str, Any]], out: TextIO) -> int:
    count = 0
    for record in records:
        out.write(json.dumps(record, default=str, sort_keys=True))
        out.write("\n")
        count += 1
    return count


def write_json_array(records: Iterable[dict[str, Any]], out: TextIO) -> int:
    items = list(records)
    out.write(json.dumps(items, default=str, sort_keys=True, indent=2))
    out.write("\n")
    return len(items)
