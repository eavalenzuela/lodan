"""VNC (RFB) probe: protocol version + offered security types. Detection-only.

Reads the server's `RFB 003.00x` version, echoes it back (required to advance the
handshake), and reads the list of security types the server offers. lodan stops
there — it never selects a type and never sends a challenge response or password.
A server offering type 1 ("None") accepts unauthenticated desktop control, which
is the exposure this surfaces.
"""
from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from lodan.probes.base import ProbeResult

_DEFAULT_VNC_PORTS = frozenset({5900, 5901, 5902, 5903})

_SEC_TYPES = {
    0: "Invalid", 1: "None", 2: "VNC-Auth", 5: "RA2", 6: "RA2ne",
    16: "Tight", 18: "TLS", 19: "VeNCrypt", 30: "AppleARD",
}


class VNCProbe:
    name = "vnc"
    default_ports = _DEFAULT_VNC_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(fetch(ip, port), timeout=timeout)
        return parse_vnc(raw)


async def fetch(ip: str, port: int) -> bytes:
    reader, writer = await asyncio.open_connection(ip, port)
    try:
        version = await reader.readexactly(12)
        if not version.startswith(b"RFB "):
            return version
        writer.write(version)  # accept the server's own offered version
        await writer.drain()
        rest = await reader.read(256)
        return version + rest
    except asyncio.IncompleteReadError as e:
        return e.partial
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def _sec_names(type_ids: list[int]) -> list[str]:
    return [_SEC_TYPES.get(t, f"type-{t}") for t in type_ids]


def parse_vnc(raw: bytes) -> ProbeResult:
    result_raw: dict[str, Any] = {"length": len(raw)}
    if len(raw) < 12 or not raw.startswith(b"RFB "):
        return ProbeResult(service="vnc", banner="vnc: no RFB version", raw=result_raw)

    ver_text = raw[:12].decode("latin-1", "replace").strip()
    try:
        major = int(raw[4:7])
        minor = int(raw[8:11])
    except ValueError:
        major = minor = 0
    result_raw["rfb_version"] = ver_text

    type_ids: list[int] = []
    rest = raw[12:]
    if rest:
        if (major, minor) >= (3, 7):
            count = rest[0]
            if count == 0:
                result_raw["handshake_failed"] = True
            else:
                type_ids = list(rest[1:1 + count])
        elif len(rest) >= 4:  # RFB 3.3 sends a single 4-byte security type
            sectype = int.from_bytes(rest[0:4], "big")
            if sectype:
                type_ids = [sectype]

    names = _sec_names(type_ids)
    no_auth = 1 in type_ids
    result_raw.update({"security_types": names, "no_auth": no_auth})

    banner = f"VNC ({ver_text})"
    if names:
        banner += " auth=" + ",".join(names)
    if no_auth:
        banner += " [NO AUTH]"
    return ProbeResult(service="vnc", banner=banner[:300], raw=result_raw)
