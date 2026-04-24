from __future__ import annotations

import asyncio
from pathlib import Path
from unittest.mock import patch

import pytest

from lodan.enrich import hosts as hosts_mod
from lodan.enrich.asn import ASNRecord, ASNResolver
from lodan.store import writer
from lodan.store.db import bootstrap, connect


@pytest.fixture
def db(tmp_path: Path):
    dbp = tmp_path / "l.db"
    bootstrap(dbp)
    conn = connect(dbp)
    yield conn
    conn.close()


class _StubResolver:
    available = True

    def __init__(self, table: dict[str, ASNRecord]) -> None:
        self._table = table

    def lookup(self, ip: str) -> ASNRecord | None:
        return self._table.get(ip)


def test_enrich_populates_hosts_from_services(db) -> None:
    handle = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, handle, "10.0.0.5", 22, "tcp")
    writer.upsert_discovered_service(db, handle, "10.0.0.5", 443, "tcp")
    writer.upsert_discovered_service(db, handle, "10.0.0.7", 80, "tcp")

    resolver = _StubResolver(
        {
            "10.0.0.5": ASNRecord(asn=64500, asn_org="Lab-AS"),
            "10.0.0.7": ASNRecord(asn=64501, asn_org="Other-AS"),
        }
    )

    async def _fake_rdns(ip: str, timeout: float = 2.0) -> str | None:
        return {"10.0.0.5": "host-5.corp", "10.0.0.7": None}.get(ip)

    with patch.object(hosts_mod, "rdns_resolve", _fake_rdns):
        count = asyncio.run(
            hosts_mod.enrich_hosts(db, handle, resolver=resolver, rdns_timeout=0.1)
        )
    assert count == 2

    rows = sorted(
        db.execute(
            "SELECT ip, rdns, asn, asn_org FROM hosts WHERE scan_id = ?",
            (handle.scan_id,),
        ).fetchall()
    )
    assert rows == [
        ("10.0.0.5", "host-5.corp", 64500, "Lab-AS"),
        ("10.0.0.7", None, 64501, "Other-AS"),
    ]


def test_enrich_is_idempotent_and_coalesces(db) -> None:
    handle = writer.open_scan(db, "w", ["10.0.0.0/24"])
    writer.upsert_discovered_service(db, handle, "10.0.0.5", 22, "tcp")

    async def _rdns_first(ip: str, timeout: float = 2.0) -> str | None:
        return "host-5.corp"

    async def _rdns_none(ip: str, timeout: float = 2.0) -> str | None:
        return None

    resolver = _StubResolver({"10.0.0.5": ASNRecord(asn=64500, asn_org="AS1")})
    with patch.object(hosts_mod, "rdns_resolve", _rdns_first):
        asyncio.run(hosts_mod.enrich_hosts(db, handle, resolver=resolver))

    # Second run returns None rDNS + same ASN; rDNS must not be clobbered to NULL.
    with patch.object(hosts_mod, "rdns_resolve", _rdns_none):
        asyncio.run(hosts_mod.enrich_hosts(db, handle, resolver=resolver))

    (rdns,) = db.execute("SELECT rdns FROM hosts WHERE ip = ?", ("10.0.0.5",)).fetchone()
    assert rdns == "host-5.corp"


def test_enrich_no_services_returns_zero(db) -> None:
    handle = writer.open_scan(db, "w", ["10.0.0.0/24"])
    got = asyncio.run(hosts_mod.enrich_hosts(db, handle, do_rdns=False, do_asn=False))
    assert got == 0


def test_asn_resolver_unavailable_when_bin_missing(tmp_path: Path) -> None:
    r = ASNResolver(db_path=tmp_path / "nope.bin")
    assert r.available is False
    assert r.lookup("8.8.8.8") is None
