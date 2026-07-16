"""PostgreSQL probe: SSLRequest capability check. Detection-only.

Sends the 8-byte SSLRequest (the very first thing a real client may send, before
any startup/auth) and reads the single-byte reply: 'S' = TLS offered, 'N' = not.
No StartupMessage, no username, no database, no authentication — this only tells
us Postgres is listening and whether it will negotiate TLS (a cleartext-DB
exposure signal when it answers 'N').
"""
from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from lodan.probes.base import ProbeResult

_DEFAULT_PG_PORTS = frozenset({5432})
# length=8, code=80877103 (1234<<16 | 5679) — the SSLRequest magic.
_SSL_REQUEST = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"


class PostgresProbe:
    name = "postgres"
    default_ports = _DEFAULT_PG_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(fetch(ip, port), timeout=timeout)
        return parse_postgres(raw)


async def fetch(ip: str, port: int) -> bytes:
    reader, writer = await asyncio.open_connection(ip, port)
    try:
        writer.write(_SSL_REQUEST)
        await writer.drain()
        return await reader.read(1)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def parse_postgres(raw: bytes) -> ProbeResult:
    result_raw: dict[str, Any] = {"length": len(raw), "ssl_reply": raw[:1].decode("latin-1")}
    if raw[:1] == b"S":
        result_raw["ssl"] = True
        return ProbeResult(service="postgresql", banner="PostgreSQL (SSL offered)", raw=result_raw)
    if raw[:1] == b"N":
        result_raw["ssl"] = False
        return ProbeResult(
            service="postgresql", banner="PostgreSQL (no SSL)", raw=result_raw
        )
    if raw[:1] == b"E":  # ErrorResponse — still a Postgres server
        return ProbeResult(service="postgresql", banner="PostgreSQL (rejected SSLRequest)", raw=result_raw)
    return ProbeResult(service="postgresql", banner="postgres: unexpected reply", raw=result_raw)
