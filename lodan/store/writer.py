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


def update_service_from_probe(
    conn: sqlite3.Connection,
    handle: ScanHandle,
    ip: str,
    port: int,
    proto: str,
    result: ProbeResult,  # noqa: F821 — forward ref to avoid cycle
) -> None:
    """Merge a ProbeResult into the services row discovery created."""
    conn.execute(
        """
        UPDATE services
        SET service = ?,
            banner = COALESCE(?, banner),
            cert_fingerprint = COALESCE(?, cert_fingerprint),
            cert_sans = COALESCE(?, cert_sans),
            ja3 = COALESCE(?, ja3),
            ja3s = COALESCE(?, ja3s),
            ja4 = COALESCE(?, ja4),
            ja4s = COALESCE(?, ja4s),
            ssh_hostkey = COALESCE(?, ssh_hostkey),
            favicon_mmh3 = COALESCE(?, favicon_mmh3),
            tech = COALESCE(?, tech),
            raw = COALESCE(?, raw)
        WHERE scan_id = ? AND ip = ? AND port = ? AND proto = ?
        """,
        (
            result.service,
            result.banner,
            result.cert_fingerprint,
            result.sans_json(),
            result.ja3,
            result.ja3s,
            result.ja4,
            result.ja4s,
            result.ssh_hostkey,
            result.favicon_mmh3,
            result.tech_json(),
            result.raw_json() if result.raw else None,
            handle.scan_id,
            ip,
            port,
            proto,
        ),
    )


def record_favicons(conn: sqlite3.Connection, handle: ScanHandle) -> int:
    """Register this scan's favicon hashes in the workspace `favicons` table.

    INSERT OR IGNORE keyed on mmh3 means the first scan to see a hash wins the
    first_seen_* slot, so the table accumulates a stable hash→host map across
    rescans. Operator labels (set via `lodan favicon-label`) are never touched
    here. Returns the number of rows considered (not necessarily new).
    """
    rows = conn.execute(
        "SELECT favicon_mmh3, ip, port FROM services "
        "WHERE scan_id = ? AND favicon_mmh3 IS NOT NULL "
        "ORDER BY ip, port",
        (handle.scan_id,),
    ).fetchall()
    for mmh3, ip, port in rows:
        conn.execute(
            "INSERT OR IGNORE INTO favicons "
            "(mmh3, first_seen_scan, first_seen_ip, first_seen_port) "
            "VALUES (?, ?, ?, ?)",
            (mmh3, handle.scan_id, ip, port),
        )
    return len(rows)


def set_favicon_label(conn: sqlite3.Connection, mmh3: int, label: str) -> None:
    """Upsert an operator label for a favicon hash, creating the row if the
    hash hasn't been seen in a scan yet."""
    conn.execute(
        "INSERT INTO favicons (mmh3, label) VALUES (?, ?) "
        "ON CONFLICT(mmh3) DO UPDATE SET label = excluded.label",
        (mmh3, label),
    )


def favicon_label(conn: sqlite3.Connection, mmh3: int) -> str | None:
    row = conn.execute(
        "SELECT label FROM favicons WHERE mmh3 = ?", (mmh3,)
    ).fetchone()
    return row[0] if row else None


def discovered_tuples(conn: sqlite3.Connection, handle: ScanHandle) -> set[tuple[str, int, str]]:
    return {
        (row[0], row[1], row[2])
        for row in conn.execute(
            "SELECT ip, port, proto FROM services WHERE scan_id = ?",
            (handle.scan_id,),
        )
    }
