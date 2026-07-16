#!/usr/bin/env python3
"""Lightweight store/query benchmark for lodan.

Populates a throwaway workspace DB through the *real* write path (batched
discovery inserts + probe merges) and times the hot pivots, so performance on
large ranges is measured rather than assumed. No network, no external tools.

    python contrib/benchmark.py --services 50000 --probe-frac 0.2

Reports discovery insert throughput and the latency of each exact/SAN pivot.
Nothing here is imported by the package; it's an operator tool.
"""
from __future__ import annotations

import argparse
import tempfile
import time
from pathlib import Path

from lodan.probes.base import ProbeResult
from lodan.store import writer
from lodan.store.db import bootstrap, connect

# Batch size mirrors lodan.scan._DISCOVERY_BATCH so the benchmark reflects the
# real commit cadence.
BATCH = 1000


def _fmt(seconds: float) -> str:
    return f"{seconds * 1000:.1f} ms" if seconds < 1 else f"{seconds:.2f} s"


def populate(conn, handle, n_services: int, probe_frac: float) -> dict[str, float]:
    timings: dict[str, float] = {}

    # --- discovery inserts, batched exactly like the scan orchestrator ---
    t0 = time.perf_counter()
    pending = 0
    conn.execute("BEGIN")
    for i in range(n_services):
        ip = f"10.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}"
        port = 1 + (i % 65535)
        writer.upsert_discovered_service(conn, handle, ip, port, "tcp")
        pending += 1
        if pending >= BATCH:
            conn.execute("COMMIT")
            conn.execute("BEGIN")
            pending = 0
    conn.execute("COMMIT")
    timings["discovery_insert"] = time.perf_counter() - t0

    # --- probe merges on a fraction of rows, so pivots have real data ---
    n_probed = int(n_services * probe_frac)
    t0 = time.perf_counter()
    conn.execute("BEGIN")
    for i in range(n_probed):
        ip = f"10.{(i >> 16) & 0xFF}.{(i >> 8) & 0xFF}.{i & 0xFF}"
        port = 1 + (i % 65535)
        bucket = i % 50  # 50 distinct fingerprint values -> realistic pivot fan-out
        writer.update_service_from_probe(conn, handle, ip, port, "tcp", ProbeResult(
            service="tls",
            banner=f"server-{bucket}",
            cert_fingerprint=f"{bucket:064x}",
            cert_sans=[f"host{i}.corp.example.com", f"*.svc{bucket}.example.com"],
            ja3s=f"ja3s{bucket:028x}",
            ssh_hostkey=f"hk{bucket:062x}",
            favicon_mmh3=bucket,
        ))
    conn.execute("COMMIT")
    timings["probe_merge"] = time.perf_counter() - t0
    return timings


def time_pivot(conn, sql: str, params: tuple) -> tuple[int, float]:
    t0 = time.perf_counter()
    rows = conn.execute(sql, params).fetchall()
    return len(rows), time.perf_counter() - t0


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--services", type=int, default=50000)
    ap.add_argument("--probe-frac", type=float, default=0.2)
    args = ap.parse_args()

    db = Path(tempfile.mkdtemp(prefix="lodan-bench-")) / "lodan.db"
    bootstrap(db)
    conn = connect(db)
    handle = writer.open_scan(conn, "bench", ["10.0.0.0/8"])

    print(f"populating {args.services} services ({args.probe_frac:.0%} probed) at {db}")
    timings = populate(conn, handle, args.services, args.probe_frac)

    ins = timings["discovery_insert"]
    print(f"\ndiscovery insert : {_fmt(ins)}  ({args.services / ins:,.0f} rows/s)")
    print(f"probe merge      : {_fmt(timings['probe_merge'])}")

    print("\npivots:")
    base = ("SELECT scan_id, ip, port, service, banner, {c} FROM services "
            "WHERE {c} = ? ORDER BY scan_id DESC, ip, port")
    for label, col, val in (
        ("ja3s", "ja3s", f"ja3s{7:028x}"),
        ("favicon", "favicon_mmh3", 7),
        ("hostkey", "ssh_hostkey", f"hk{7:062x}"),
        ("cert_fp", "cert_fingerprint", f"{7:064x}"),
    ):
        count, dt = time_pivot(conn, base.format(c=col), (val,))
        print(f"  {label:10s}: {_fmt(dt):>9s}  ({count} rows)")

    san_sql = ("SELECT scan_id, ip, port FROM services "
               "WHERE cert_sans IS NOT NULL AND cert_sans LIKE ? "
               "ORDER BY scan_id DESC, ip, port")
    count, dt = time_pivot(conn, san_sql, ("%svc7.example.com%",))
    print(f"  {'san (LIKE)':10s}: {_fmt(dt):>9s}  ({count} rows)  <- full scan, no index")

    conn.close()


if __name__ == "__main__":
    main()
