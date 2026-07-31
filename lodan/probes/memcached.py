"""memcached UDP probe: `stats`.

memcached over UDP answers `stats` with no authentication at all — version,
uptime, connection counts, item counts. Two things come out of one datagram:
the version (which feeds CPE/CVE matching) and the amplification factor, since
a tiny request producing a large reply is exactly what made memcached the
vehicle for record-setting reflection attacks.

Read-only: `stats` only. No `get`, no `set`, no key enumeration.
"""
from __future__ import annotations

import asyncio
from typing import Any

from lodan.probes._udp import udp_exchange
from lodan.probes.base import ProbeResult

_DEFAULT_MEMCACHED_PORTS = frozenset({11211})

AMPLIFICATION_THRESHOLD = 5.0


class MemcachedProbe:
    name = "memcached"
    proto = "udp"
    default_ports = _DEFAULT_MEMCACHED_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        request = build_stats()
        raw = await asyncio.wait_for(
            udp_exchange(ip, port, request, timeout), timeout=timeout + 1
        )
        return parse(raw, request_bytes=len(request))


def build_stats() -> bytes:
    """UDP frame header (request id, seq, datagram count, reserved) + command."""
    return b"\x00\x01\x00\x00\x00\x01\x00\x00" + b"stats\r\n"


def parse(raw: bytes | None, *, request_bytes: int) -> ProbeResult:
    if not raw:
        return ProbeResult(service="memcached", banner="memcached: no response")
    result_raw: dict[str, Any] = {
        "response_bytes": len(raw),
        "request_bytes": request_bytes,
        "amplification": round(len(raw) / request_bytes, 2) if request_bytes else None,
    }
    body = raw[8:] if len(raw) > 8 else raw     # strip the UDP frame header
    text = body.decode("ascii", "replace")
    stats: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[0] == "STAT":
            stats[parts[1]] = parts[2]
    if not stats:
        return ProbeResult(
            service="memcached",
            banner="memcached: unexpected reply",
            raw=result_raw,
        )
    result_raw["stats"] = stats
    version = stats.get("version")
    result_raw["version"] = version
    banner = f"memcached {version}" if version else "memcached (unauthenticated)"
    amplification = result_raw["amplification"]
    if amplification and amplification >= AMPLIFICATION_THRESHOLD:
        banner += f" [amplification x{amplification}]"
    return ProbeResult(
        service="memcached", banner=banner[:300],
        amplification=amplification, raw=result_raw,
    )
