"""Resolve --from / --to tokens against a workspace's scan history.

Accepted forms:

- `<int>`            treated as a scan_id; rejected if not found.
- `latest`           the newest completed scan.
- `prev`             the second-newest completed scan.
- `YYYY-MM-DD`       the newest completed scan on or before that date.
- `YYYY-MM-DDTHH:..` same, ISO 8601 with a time component.
"""
from __future__ import annotations

import re
import sqlite3


class ResolveError(ValueError):
    pass


_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?)?$")


def resolve(conn: sqlite3.Connection, token: str) -> int:
    token = token.strip()
    if token.isdigit():
        scan_id = int(token)
        if not _scan_exists(conn, scan_id):
            raise ResolveError(f"no scan with id {scan_id}")
        return scan_id

    if token == "latest":
        return _nth_completed(conn, 0)
    if token == "prev":
        return _nth_completed(conn, 1)

    if _ISO_DATE_RE.match(token):
        scan_id = _latest_on_or_before(conn, token)
        if scan_id is None:
            raise ResolveError(f"no completed scan at or before {token}")
        return scan_id

    raise ResolveError(f"cannot resolve scan token: {token!r}")


def _scan_exists(conn: sqlite3.Connection, scan_id: int) -> bool:
    return conn.execute(
        "SELECT 1 FROM scans WHERE id = ?", (scan_id,)
    ).fetchone() is not None


def _nth_completed(conn: sqlite3.Connection, offset: int) -> int:
    row = conn.execute(
        """
        SELECT id FROM scans
        WHERE status = 'completed'
        ORDER BY id DESC
        LIMIT 1 OFFSET ?
        """,
        (offset,),
    ).fetchone()
    if row is None:
        label = "latest" if offset == 0 else "prev"
        raise ResolveError(f"{label}: not enough completed scans in this workspace")
    return row[0]


def _latest_on_or_before(conn: sqlite3.Connection, iso: str) -> int | None:
    # The started_at column is ISO-formatted; lexicographic comparison suffices.
    row = conn.execute(
        """
        SELECT id FROM scans
        WHERE status = 'completed' AND started_at <= ?
        ORDER BY started_at DESC
        LIMIT 1
        """,
        (iso + ("T99:99" if "T" not in iso and " " not in iso else ""),),
    ).fetchone()
    return row[0] if row else None


def previous_completed(conn: sqlite3.Connection, before_scan_id: int) -> int | None:
    """Find the most recent completed scan strictly before `before_scan_id`.

    Used by scan.run_scan to auto-diff each new scan against the previous.
    """
    row = conn.execute(
        """
        SELECT id FROM scans
        WHERE id < ? AND status = 'completed'
        ORDER BY id DESC
        LIMIT 1
        """,
        (before_scan_id,),
    ).fetchone()
    return row[0] if row else None
