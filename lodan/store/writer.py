"""SQLite writers for the scan lifecycle.

A scan row owns everything produced by a single `lodan scan` invocation.
Writers here are deliberately low-level and synchronous; the async scan loop
wraps them in `asyncio.to_thread` when it needs to.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


@dataclass(frozen=True)
class ScanHandle:
    scan_id: int
    workspace: str


def open_scan(
    conn: sqlite3.Connection,
    workspace: str,
    cidrs: list[str],
    seed: int | None = None,
    cloud_justification: str | None = None,
) -> ScanHandle:
    cur = conn.execute(
        "INSERT INTO scans (started_at, cidrs, workspace, seed, status, cloud_justification) "
        "VALUES (?, ?, ?, ?, 'running', ?)",
        (_now(), json.dumps(cidrs), workspace, seed, cloud_justification),
    )
    return ScanHandle(scan_id=cur.lastrowid, workspace=workspace)


def finish_scan(conn: sqlite3.Connection, handle: ScanHandle, status: str = "completed") -> None:
    if status not in {"completed", "failed"}:
        raise ValueError(f"invalid terminal status: {status}")
    conn.execute(
        "UPDATE scans SET status = ?, finished_at = ? WHERE id = ?",
        (status, _now(), handle.scan_id),
    )


def record_error(
    conn: sqlite3.Connection,
    handle: ScanHandle,
    stage: str,
    error: str,
    ip: str | None = None,
    port: int | None = None,
) -> None:
    conn.execute(
        "INSERT INTO scan_errors (scan_id, ip, port, stage, error, ts) VALUES (?, ?, ?, ?, ?, ?)",
        (handle.scan_id, ip, port, stage, error, _now()),
    )


def upsert_discovered_service(
    conn: sqlite3.Connection,
    handle: ScanHandle,
    ip: str,
    port: int,
    proto: str,
) -> None:
    """Insert an (ip, port, proto) row from port discovery. Pre-probe: service=NULL."""
    conn.execute(
        "INSERT OR IGNORE INTO services (scan_id, ip, port, proto) VALUES (?, ?, ?, ?)",
        (handle.scan_id, ip, port, proto),
    )


def discovered_tuples(conn: sqlite3.Connection, handle: ScanHandle) -> set[tuple[str, int, str]]:
    return {
        (row[0], row[1], row[2])
        for row in conn.execute(
            "SELECT ip, port, proto FROM services WHERE scan_id = ?",
            (handle.scan_id,),
        )
    }
