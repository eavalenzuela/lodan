"""Workspace retention — apply config.retention to prune old scans.

Two knobs, combine with OR (the keep set is the union):

- `keep_last_n`:     keep the N most recent completed scans.
- `keep_monthly`:    for each of the M most recent months that have at least
                     one completed scan, keep the earliest scan in that month.

Non-completed scans (pending / running / failed) are never deleted — prune
is for historical cleanup, not for killing in-flight or broken runs. Those
should be cleaned up by hand.

compute_keep_set() is pure (takes rows, returns a set of ids) so tests can
exercise the policy without a DB. apply() is the one-call-does-everything
helper the CLI hits.
"""
from __future__ import annotations

import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass


@dataclass(frozen=True)
class ScanRecord:
    id: int
    started_at: str
    status: str


@dataclass
class PruneStats:
    total_scans: int = 0
    kept: int = 0
    deleted: int = 0
    skipped_non_completed: int = 0


def compute_keep_set(
    scans: Iterable[ScanRecord],
    *,
    keep_last_n: int | None,
    keep_monthly: int | None,
) -> set[int]:
    scans = list(scans)
    completed = sorted(
        (s for s in scans if s.status == "completed"),
        key=lambda s: s.started_at,
        reverse=True,
    )
    keep: set[int] = {s.id for s in scans if s.status != "completed"}

    if keep_last_n:
        keep.update(s.id for s in completed[: max(keep_last_n, 0)])

    if keep_monthly:
        # Earliest scan per YYYY-MM, for the `keep_monthly` most recent months.
        by_month: dict[str, ScanRecord] = {}
        for s in completed:
            month = s.started_at[:7]
            existing = by_month.get(month)
            if existing is None or s.started_at < existing.started_at:
                by_month[month] = s
        months_desc = sorted(by_month.keys(), reverse=True)[:keep_monthly]
        keep.update(by_month[m].id for m in months_desc)

    return keep


def apply(
    conn: sqlite3.Connection,
    *,
    keep_last_n: int | None,
    keep_monthly: int | None,
    dry_run: bool = False,
) -> PruneStats:
    scans = [
        ScanRecord(id=row[0], started_at=row[1], status=row[2])
        for row in conn.execute("SELECT id, started_at, status FROM scans")
    ]
    keep = compute_keep_set(scans, keep_last_n=keep_last_n, keep_monthly=keep_monthly)
    stats = PruneStats(
        total_scans=len(scans),
        kept=len(keep),
        skipped_non_completed=sum(1 for s in scans if s.status != "completed"),
    )
    delete_ids = [s.id for s in scans if s.id not in keep]
    stats.deleted = len(delete_ids)

    if delete_ids and not dry_run:
        # FK cascades will wipe services / hosts / vulns / scan_errors / scan_diffs.
        conn.execute("PRAGMA foreign_keys = ON")
        placeholders = ",".join("?" * len(delete_ids))
        conn.execute(
            f"DELETE FROM scans WHERE id IN ({placeholders})",
            delete_ids,
        )
    return stats
