"""Host enrichment phase.

After probes land, every distinct IP in `services` becomes one row in the
`hosts` table, populated with rDNS (if resolvable), ASN (if the local
IP2Location LITE DB is present), and country (same DB when it carries
country data).

Runs with a bounded semaphore so we don't open 10k PTR lookups at once.
"""
from __future__ import annotations

import asyncio
import sqlite3

from lodan.enrich.asn import ASNResolver
from lodan.enrich.rdns import resolve as rdns_resolve
from lodan.store.writer import ScanHandle


async def enrich_hosts(
    conn: sqlite3.Connection,
    handle: ScanHandle,
    *,
    do_rdns: bool = True,
    do_asn: bool = True,
    concurrency: int = 32,
    rdns_timeout: float = 2.0,
    resolver: ASNResolver | None = None,
) -> int:
    ips = [
        row[0]
        for row in conn.execute(
            "SELECT DISTINCT ip FROM services WHERE scan_id = ?", (handle.scan_id,)
        )
    ]
    if not ips:
        return 0

    asn_resolver = resolver if resolver is not None else ASNResolver()
    sem = asyncio.Semaphore(concurrency)

    async def _one(ip: str) -> tuple[str, str | None, int | None, str | None]:
        async with sem:
            rdns_val = await rdns_resolve(ip, timeout=rdns_timeout) if do_rdns else None
            asn_rec = asn_resolver.lookup(ip) if do_asn else None
            asn = asn_rec.asn if asn_rec else None
            org = asn_rec.asn_org if asn_rec else None
            return ip, rdns_val, asn, org

    results = await asyncio.gather(*(_one(ip) for ip in ips))
    for ip, rdns, asn, org in results:
        conn.execute(
            """
            INSERT INTO hosts (scan_id, ip, rdns, asn, asn_org, country)
            VALUES (?, ?, ?, ?, ?, NULL)
            ON CONFLICT(scan_id, ip) DO UPDATE SET
                rdns = COALESCE(excluded.rdns, rdns),
                asn = COALESCE(excluded.asn, asn),
                asn_org = COALESCE(excluded.asn_org, asn_org)
            """,
            (handle.scan_id, ip, rdns, asn, org),
        )
    return len(results)
