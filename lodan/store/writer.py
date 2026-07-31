"""SQLite writers for the scan lifecycle.

A scan row owns everything produced by a single `lodan scan` invocation.
Writers here are deliberately low-level and synchronous; the async scan loop
wraps them in `asyncio.to_thread` when it needs to.
"""
from __future__ import annotations

import hashlib
import json
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime

from lodan import normalize
from lodan.discovery import fingerprint
from lodan.discovery.base import StackObservation


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


def record_authz_decision(
    conn: sqlite3.Connection,
    *,
    scan_id: int | None,
    workspace: str,
    operator: str | None,
    decision: str,
    scope_kind: str,
    target: str,
    port: int | None = None,
    proto: str | None = None,
    reason: str | None = None,
) -> None:
    """Append one row to the immutable authorization ledger.

    `decision` is 'authorized' (a CIDR/cloud prefix we were cleared to scan) or
    'refused' (an out-of-scope target we declined to touch). The ledger is
    append-only and independent of scan bookkeeping — see schema.sql.
    """
    conn.execute(
        "INSERT INTO authz_ledger "
        "(ts, workspace, scan_id, operator, decision, scope_kind, target, port, proto, reason) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (_now(), workspace, scan_id, operator, decision, scope_kind, target, port, proto, reason),
    )


_LEDGER_COLUMNS = (
    "id", "ts", "workspace", "scan_id", "operator",
    "decision", "scope_kind", "target", "port", "proto", "reason",
)


def iter_authz_ledger(
    conn: sqlite3.Connection,
    *,
    scan_id: int | None = None,
    decision: str | None = None,
    limit: int | None = None,
) -> list[dict]:
    """Read the authorization ledger, oldest first. Optional scan/decision filters."""
    sql = f"SELECT {', '.join(_LEDGER_COLUMNS)} FROM authz_ledger"
    clauses: list[str] = []
    params: list[object] = []
    if scan_id is not None:
        clauses.append("scan_id = ?")
        params.append(scan_id)
    if decision is not None:
        clauses.append("decision = ?")
        params.append(decision)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY id"
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)
    return [dict(zip(_LEDGER_COLUMNS, row, strict=True)) for row in conn.execute(sql, params)]


def upsert_discovered_service(
    conn: sqlite3.Connection,
    handle: ScanHandle,
    ip: str,
    port: int,
    proto: str,
    stack: StackObservation | None = None,
) -> None:
    """Insert an (ip, port, proto) row from port discovery. Pre-probe: service=NULL.

    `stack` carries the passive fingerprint derived from this port's SYN-ACK
    when the backend saw the raw packet; the derived columns stay NULL
    otherwise. Deriving here (rather than in a later pass) keeps it on the
    single write that already exists for every discovered port.
    """
    os_guess = fingerprint.os_family(stack)
    conn.execute(
        "INSERT OR IGNORE INTO services "
        "(scan_id, ip, port, proto, stack_sig, os_family, os_confidence, hop_count, clock_key) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            handle.scan_id, ip, port, proto,
            fingerprint.stack_sig(stack),
            os_guess.os_family if os_guess else None,
            os_guess.confidence if os_guess else None,
            fingerprint.hop_count(stack.ttl) if stack else None,
            fingerprint.clock_key(stack),
        ),
    )


def record_host_stack(conn: sqlite3.Connection, handle: ScanHandle) -> int:
    """Roll per-port stack fingerprints up to a host-level consensus.

    Runs after discovery. `stack_sig` / `os_family` are unanimous-or-NULL so
    that a host whose ports disagree stays visibly unresolved rather than
    being asserted as one machine; `hop_count` takes the modal value since a
    single odd route shouldn't erase the host's position in the topology.
    """
    rows = conn.execute(
        "SELECT ip, stack_sig, os_family, os_confidence, hop_count FROM services "
        "WHERE scan_id = ?",
        (handle.scan_id,),
    ).fetchall()
    if not rows:
        return 0

    per_ip: dict[str, list[tuple[str | None, str | None, float | None, int | None]]] = {}
    for ip, sig, family, confidence, hops in rows:
        per_ip.setdefault(ip, []).append((sig, family, confidence, hops))

    written = 0
    for ip, entries in per_ip.items():
        sig = fingerprint.consensus([e[0] for e in entries])
        family = fingerprint.consensus([e[1] for e in entries])
        hops = fingerprint.modal_hops([e[3] for e in entries])
        # Confidence belongs to the agreed family; a split host has neither.
        confidences = [e[2] for e in entries if e[1] == family and e[2] is not None]
        confidence = max(confidences) if family and confidences else None
        if sig is None and family is None and hops is None:
            continue
        conn.execute(
            """
            INSERT INTO hosts (scan_id, ip, stack_sig, os_family, os_confidence, hop_count)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(scan_id, ip) DO UPDATE SET
                stack_sig = excluded.stack_sig,
                os_family = excluded.os_family,
                os_confidence = excluded.os_confidence,
                hop_count = excluded.hop_count
            """,
            (handle.scan_id, ip, sig, family, confidence, hops),
        )
        written += 1
    return written


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
            jarm = COALESCE(?, jarm),
            raw = COALESCE(?, raw)
        WHERE scan_id = ? AND ip = ? AND port = ? AND proto = ?
        """,
        (
            result.service,
            normalize.banner(result.banner),
            normalize.fingerprint(result.cert_fingerprint),
            normalize.sans_json(result.cert_sans),
            result.ja3,
            result.ja3s,
            result.ja4,
            result.ja4s,
            result.ssh_hostkey,
            result.favicon_mmh3,
            normalize.tech_json(result.tech),
            result.jarm,
            result.raw_json() if result.raw else None,
            handle.scan_id,
            ip,
            port,
            proto,
        ),
    )
    if result.chain_der:
        record_chain_certs(conn, handle, ip, port, result)


def record_chain_certs(
    conn: sqlite3.Connection,
    handle: ScanHandle,
    ip: str,
    port: int,
    result: ProbeResult,  # noqa: F821 — forward ref to avoid cycle
) -> int:
    """Persist every cert in the server's chain, DER included.

    The parsed metadata already rides along in `raw['chain']`; this table
    exists so the *key material* is queryable and available offline, and so a
    CA-reuse pivot can reach intermediates that the leaf-only
    `services.cert_fingerprint` column cannot see.
    """
    chain_der = result.chain_der or []
    parsed = result.raw.get("chain") if isinstance(result.raw, dict) else None
    parsed_by_pos = {}
    if isinstance(parsed, list):
        parsed_by_pos = {
            entry.get("position"): entry
            for entry in parsed
            if isinstance(entry, dict)
        }
    rows = []
    for position, der in enumerate(chain_der):
        meta = parsed_by_pos.get(position, {})
        rows.append((
            handle.scan_id, ip, port, position,
            meta.get("sha256") or hashlib.sha256(der).hexdigest(),
            meta.get("subject"), meta.get("issuer"), meta.get("serial"),
            meta.get("key_type"), meta.get("key_bits"), meta.get("curve"),
            meta.get("sig_algo"), meta.get("not_before"), meta.get("not_after"),
            None if meta.get("is_ca") is None else int(bool(meta.get("is_ca"))),
            int(bool(meta.get("self_signed"))),
            der,
        ))
    if not rows:
        return 0
    conn.executemany(
        "INSERT OR REPLACE INTO chain_certs "
        "(scan_id, ip, port, position, sha256, subject, issuer, serial, key_type, "
        " key_bits, curve, sig_algo, not_before, not_after, is_ca, self_signed, der) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        rows,
    )
    return len(rows)


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
