"""Compute and persist the delta between two scans.

Five kinds of finding:

- new_service   (ip, port, proto) present in the newer scan, absent in the older.
- gone_service  present in the older scan, absent in the newer.
- changed       same (ip, port, proto) but banner / cert_fingerprint / tech differs.
- new_cert      cert_fingerprint first seen in the newer scan for this workspace,
                scoped against *every* earlier scan in the same DB (not just the
                compared-against one — "never seen before in this workspace").
- new_host      IPs present in the newer scan, absent in the older.

Each finding lands in scan_diffs keyed by (from_scan_id, to_scan_id, kind, ip,
port). A detail JSON blob carries the kind-specific fields so the UI can
render without re-querying services.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any

KINDS = ("new_service", "gone_service", "changed", "new_cert", "new_host")


@dataclass(frozen=True)
class DiffCounts:
    new_service: int = 0
    gone_service: int = 0
    changed: int = 0
    new_cert: int = 0
    new_host: int = 0

    @property
    def total(self) -> int:
        return (
            self.new_service + self.gone_service + self.changed + self.new_cert + self.new_host
        )

    def as_dict(self) -> dict[str, int]:
        return {
            "new_service": self.new_service,
            "gone_service": self.gone_service,
            "changed": self.changed,
            "new_cert": self.new_cert,
            "new_host": self.new_host,
            "total": self.total,
        }


def compute_and_store(
    conn: sqlite3.Connection,
    from_scan_id: int,
    to_scan_id: int,
    *,
    clear_existing: bool = True,
) -> DiffCounts:
    """Run every diff query and insert the results into scan_diffs.

    `clear_existing=True` wipes any prior rows for this (from, to) pair so
    repeated invocations yield a consistent view.
    """
    if from_scan_id == to_scan_id:
        raise ValueError("from and to scans must differ")

    if clear_existing:
        conn.execute(
            "DELETE FROM scan_diffs WHERE from_scan_id = ? AND to_scan_id = ?",
            (from_scan_id, to_scan_id),
        )

    counts = DiffCounts(
        new_service=_insert_new_services(conn, from_scan_id, to_scan_id),
        gone_service=_insert_gone_services(conn, from_scan_id, to_scan_id),
        changed=_insert_changed(conn, from_scan_id, to_scan_id),
        new_cert=_insert_new_certs(conn, from_scan_id, to_scan_id),
        new_host=_insert_new_hosts(conn, from_scan_id, to_scan_id),
    )
    return counts


def _insert_diff_rows(
    conn: sqlite3.Connection,
    from_scan_id: int,
    to_scan_id: int,
    kind: str,
    rows: list[tuple[str, int | None, dict[str, Any]]],
) -> int:
    if not rows:
        return 0
    conn.executemany(
        "INSERT INTO scan_diffs (from_scan_id, to_scan_id, kind, ip, port, detail) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [
            (from_scan_id, to_scan_id, kind, ip, port, json.dumps(detail, default=str))
            for ip, port, detail in rows
        ],
    )
    return len(rows)


def _insert_new_services(conn: sqlite3.Connection, f: int, t: int) -> int:
    rows = conn.execute(
        """
        SELECT ip, port, proto, service, banner
        FROM services
        WHERE scan_id = ?
          AND (ip, port, proto) NOT IN (
            SELECT ip, port, proto FROM services WHERE scan_id = ?
          )
        """,
        (t, f),
    ).fetchall()
    return _insert_diff_rows(
        conn, f, t, "new_service",
        [(ip, port, {"proto": proto, "service": svc, "banner": banner})
         for ip, port, proto, svc, banner in rows],
    )


def _insert_gone_services(conn: sqlite3.Connection, f: int, t: int) -> int:
    rows = conn.execute(
        """
        SELECT ip, port, proto, service, banner
        FROM services
        WHERE scan_id = ?
          AND (ip, port, proto) NOT IN (
            SELECT ip, port, proto FROM services WHERE scan_id = ?
          )
        """,
        (f, t),
    ).fetchall()
    return _insert_diff_rows(
        conn, f, t, "gone_service",
        [(ip, port, {"proto": proto, "service": svc, "banner": banner})
         for ip, port, proto, svc, banner in rows],
    )


def _insert_changed(conn: sqlite3.Connection, f: int, t: int) -> int:
    rows = conn.execute(
        """
        SELECT a.ip, a.port, a.proto,
               a.service, b.service,
               a.banner, b.banner,
               a.cert_fingerprint, b.cert_fingerprint,
               a.tech, b.tech
        FROM services a
        JOIN services b USING (ip, port, proto)
        WHERE a.scan_id = ? AND b.scan_id = ?
          AND (COALESCE(a.banner,'') != COALESCE(b.banner,'')
            OR COALESCE(a.cert_fingerprint,'') != COALESCE(b.cert_fingerprint,'')
            OR COALESCE(a.tech,'') != COALESCE(b.tech,''))
        """,
        (f, t),
    ).fetchall()
    return _insert_diff_rows(
        conn, f, t, "changed",
        [
            (
                ip, port,
                {
                    "proto": proto,
                    "service": {"from": s_from, "to": s_to},
                    "banner": {"from": b_from, "to": b_to},
                    "cert_fingerprint": {"from": cf_from, "to": cf_to},
                    "tech": {"from": t_from, "to": t_to},
                },
            )
            for (ip, port, proto, s_from, s_to, b_from, b_to,
                 cf_from, cf_to, t_from, t_to) in rows
        ],
    )


def _insert_new_certs(conn: sqlite3.Connection, f: int, t: int) -> int:
    rows = conn.execute(
        """
        SELECT ip, port, cert_fingerprint
        FROM services
        WHERE scan_id = ?
          AND cert_fingerprint IS NOT NULL
          AND cert_fingerprint NOT IN (
            SELECT cert_fingerprint FROM services
            WHERE scan_id < ? AND cert_fingerprint IS NOT NULL
          )
        """,
        (t, t),
    ).fetchall()
    return _insert_diff_rows(
        conn, f, t, "new_cert",
        [(ip, port, {"cert_fingerprint": fp}) for ip, port, fp in rows],
    )


def _insert_new_hosts(conn: sqlite3.Connection, f: int, t: int) -> int:
    rows = conn.execute(
        """
        SELECT DISTINCT ip FROM services WHERE scan_id = ?
        EXCEPT
        SELECT DISTINCT ip FROM services WHERE scan_id = ?
        """,
        (t, f),
    ).fetchall()
    return _insert_diff_rows(
        conn, f, t, "new_host",
        [(ip, None, {}) for (ip,) in rows],
    )
