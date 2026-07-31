"""Compute and persist the delta between two scans.

Eight kinds of finding:

- new_service   (ip, port, proto) present in the newer scan, absent in the older.
- gone_service  present in the older scan, absent in the newer.
- changed       same (ip, port, proto) but banner / cert_fingerprint / tech /
                os_guess differs.
- new_cert      cert_fingerprint first seen in the newer scan for this workspace,
                scoped against *every* earlier scan in the same DB (not just the
                compared-against one — "never seen before in this workspace").
- new_host      IPs present in the newer scan, absent in the older.
- path_changed  same (ip, port, proto) still answering, but the passive stack
                fingerprint or the hop count moved. This is the topology
                dimension the service-level kinds are blind to: an unchanged
                banner served from a different OS stack, or the same host
                suddenly a different number of hops away, means something
                moved underneath a service that looks identical on the wire.
- topology_change  host-scoped (port is NULL): the number of backends behind
                one address changed, or its device class flipped. Both are
                changes to the *shape* of a host rather than to any one of its
                services, which is why they can't ride on `changed`.
- risk_increased  a service that did not move on the wire nonetheless became
                more dangerous: a CVE it already had went onto CISA KEV, its
                remediation priority rose, or its software crossed an
                end-of-support date. Every other kind here is topology; this
                one is posture.

Each finding lands in scan_diffs keyed by (from_scan_id, to_scan_id, kind, ip,
port). A detail JSON blob carries the kind-specific fields so the UI can
render without re-querying services.
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from typing import Any

KINDS = (
    "new_service", "gone_service", "changed", "new_cert", "new_host",
    "path_changed", "topology_change", "risk_increased",
)


@dataclass(frozen=True)
class DiffCounts:
    new_service: int = 0
    gone_service: int = 0
    changed: int = 0
    new_cert: int = 0
    new_host: int = 0
    path_changed: int = 0
    topology_change: int = 0
    risk_increased: int = 0

    @property
    def total(self) -> int:
        return (
            self.new_service + self.gone_service + self.changed + self.new_cert
            + self.new_host + self.path_changed + self.topology_change
            + self.risk_increased
        )

    def as_dict(self) -> dict[str, int]:
        return {
            "new_service": self.new_service,
            "gone_service": self.gone_service,
            "changed": self.changed,
            "new_cert": self.new_cert,
            "new_host": self.new_host,
            "path_changed": self.path_changed,
            "topology_change": self.topology_change,
            "risk_increased": self.risk_increased,
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
        path_changed=_insert_path_changed(conn, from_scan_id, to_scan_id),
        topology_change=_insert_topology_change(conn, from_scan_id, to_scan_id),
        risk_increased=_insert_risk_increased(conn, from_scan_id, to_scan_id),
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
               a.tech, b.tech,
               a.os_guess, b.os_guess
        FROM services a
        JOIN services b USING (ip, port, proto)
        WHERE a.scan_id = ? AND b.scan_id = ?
          AND (COALESCE(a.banner,'') != COALESCE(b.banner,'')
            OR COALESCE(a.cert_fingerprint,'') != COALESCE(b.cert_fingerprint,'')
            OR COALESCE(a.tech,'') != COALESCE(b.tech,'')
            OR COALESCE(a.os_guess,'') != COALESCE(b.os_guess,''))
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
                    "os_guess": {"from": og_from, "to": og_to},
                },
            )
            for (ip, port, proto, s_from, s_to, b_from, b_to,
                 cf_from, cf_to, t_from, t_to, og_from, og_to) in rows
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


def _insert_path_changed(conn: sqlite3.Connection, f: int, t: int) -> int:
    """Stack fingerprint or hop count moved on a service present in both scans.

    Both sides must be non-NULL: the masscan and naabu backends never populate
    these columns, so a NULL is "not observed", not "changed". Comparing
    against NULL would make every scan that switched backends look like the
    whole estate moved.
    """
    rows = conn.execute(
        """
        SELECT a.ip, a.port, a.proto,
               a.stack_sig, b.stack_sig,
               a.os_family, b.os_family,
               a.hop_count, b.hop_count
        FROM services a
        JOIN services b USING (ip, port, proto)
        WHERE a.scan_id = ? AND b.scan_id = ?
          AND ((a.stack_sig IS NOT NULL AND b.stack_sig IS NOT NULL
                AND a.stack_sig != b.stack_sig)
            OR (a.hop_count IS NOT NULL AND b.hop_count IS NOT NULL
                AND a.hop_count != b.hop_count))
        """,
        (f, t),
    ).fetchall()
    return _insert_diff_rows(
        conn, f, t, "path_changed",
        [
            (
                ip, port,
                {
                    "proto": proto,
                    "stack_sig": {"from": sig_from, "to": sig_to},
                    "os_family": {"from": os_from, "to": os_to},
                    "hop_count": {"from": hop_from, "to": hop_to},
                },
            )
            for (ip, port, proto, sig_from, sig_to, os_from, os_to,
                 hop_from, hop_to) in rows
        ],
    )


def _insert_topology_change(conn: sqlite3.Connection, f: int, t: int) -> int:
    """Backend count or device class changed for a host present in both scans.

    Both sides must be non-NULL for each compared field, for the same reason
    path_changed requires it: an absent value means "not computed" (enrichment
    off, older scan), not "changed to nothing".
    """
    rows = conn.execute(
        """
        SELECT a.ip,
               a.min_backend_count, b.min_backend_count,
               a.device_type, b.device_type,
               b.backend_evidence
        FROM hosts a
        JOIN hosts b USING (ip)
        WHERE a.scan_id = ? AND b.scan_id = ?
          AND ((a.min_backend_count IS NOT NULL AND b.min_backend_count IS NOT NULL
                AND a.min_backend_count != b.min_backend_count)
            OR (a.device_type IS NOT NULL AND b.device_type IS NOT NULL
                AND a.device_type != b.device_type))
        """,
        (f, t),
    ).fetchall()
    return _insert_diff_rows(
        conn, f, t, "topology_change",
        [
            (
                ip, None,
                {
                    "min_backend_count": {"from": bc_from, "to": bc_to},
                    "device_type": {"from": dt_from, "to": dt_to},
                    "evidence": _load_evidence(evidence),
                },
            )
            for ip, bc_from, bc_to, dt_from, dt_to, evidence in rows
        ],
    )


_PRIORITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def _insert_risk_increased(conn: sqlite3.Connection, f: int, t: int) -> int:
    """A service got more dangerous while standing still.

    Three ways that happens with nothing changing on the wire: a CVE the host
    already had became known-exploited (newly on CISA KEV), its remediation
    priority rose, or its software crossed an end-of-support date. The rest of
    the diff engine is topology-only and blind to all three.

    Scoped to services present in BOTH scans — a brand-new service is already
    reported as new_service, and calling it "increased risk" as well would
    double-count it.
    """
    rows = conn.execute(
        """
        SELECT b.ip, b.port, b.cve, a.priority, b.priority,
               COALESCE(a.kev, 0), COALESCE(b.kev, 0), b.epss
        FROM vulns b
        JOIN vulns a ON a.ip = b.ip AND a.port = b.port AND a.cve = b.cve
                    AND a.scan_id = ?
        WHERE b.scan_id = ?
          AND ((COALESCE(a.kev, 0) = 0 AND COALESCE(b.kev, 0) = 1)
            OR (a.priority IS NOT NULL AND b.priority IS NOT NULL
                AND a.priority != b.priority))
        """,
        (f, t),
    ).fetchall()

    findings: list[tuple[str, int | None, dict[str, Any]]] = []
    for ip, port, cve, prio_from, prio_to, kev_from, kev_to, epss in rows:
        newly_kev = not kev_from and bool(kev_to)
        rose = (
            prio_from in _PRIORITY_RANK and prio_to in _PRIORITY_RANK
            and _PRIORITY_RANK[prio_to] < _PRIORITY_RANK[prio_from]
        )
        if not (newly_kev or rose):
            continue    # priority fell — good news, not a risk increase
        findings.append((ip, port, {
            "reason": "newly-kev" if newly_kev else "priority-raised",
            "cve": cve,
            "priority": {"from": prio_from, "to": prio_to},
            "kev": {"from": bool(kev_from), "to": bool(kev_to)},
            "epss": epss,
        }))

    # Newly end-of-life software, from the findings table.
    eol_rows = conn.execute(
        """
        SELECT b.ip, b.port, b.title
        FROM findings b
        WHERE b.scan_id = ? AND b.category = 'eol'
          AND NOT EXISTS (
            SELECT 1 FROM findings a
            WHERE a.scan_id = ? AND a.category = 'eol'
              AND a.ip = b.ip AND COALESCE(a.port, -1) = COALESCE(b.port, -1)
          )
          AND EXISTS (
            SELECT 1 FROM services s
            WHERE s.scan_id = ? AND s.ip = b.ip AND s.port = b.port
          )
        """,
        (t, f, f),
    ).fetchall()
    for ip, port, title in eol_rows:
        findings.append((ip, port, {"reason": "newly-eol", "detail": title}))

    # One row per (ip, port): scan_diffs is keyed on it, so several CVEs rising
    # on the same service collapse into a single finding carrying all of them.
    merged: dict[tuple[str, int | None], dict[str, Any]] = {}
    for ip, port, detail in findings:
        entry = merged.setdefault((ip, port), {"reasons": [], "items": []})
        if detail["reason"] not in entry["reasons"]:
            entry["reasons"].append(detail["reason"])
        entry["items"].append(detail)
    return _insert_diff_rows(
        conn, f, t, "risk_increased",
        [(ip, port, detail) for (ip, port), detail in merged.items()],
    )


def _load_evidence(raw: Any) -> list:
    if not raw:
        return []
    try:
        parsed = json.loads(raw)
    except (ValueError, TypeError):
        return []
    return parsed if isinstance(parsed, list) else []


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
