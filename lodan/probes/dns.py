"""DNS probe: version.bind CHAOS TXT query over TCP. Detection-only.

Sends the classic `version.bind`/CHAOS/TXT query — a read-only fingerprint that
many resolvers answer with their software version. No zone transfer, no
recursion abuse, no records are written. Over TCP because that's what the port
scan confirmed open; UDP/53 is discovered but probed via TCP here.
"""
from __future__ import annotations

import asyncio
import contextlib
import struct
from typing import Any

from lodan.probes.base import ProbeResult

_DEFAULT_DNS_PORTS = frozenset({53})
_RCODES = {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED"}


class DNSProbe:
    name = "dns"
    default_ports = _DEFAULT_DNS_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(fetch(ip, port), timeout=timeout)
        return parse_dns(raw)


def build_query() -> bytes:
    header = struct.pack(">HHHHHH", 0x1337, 0x0100, 1, 0, 0, 0)  # RD set, 1 question
    qname = b"\x07version\x04bind\x00"
    question = qname + struct.pack(">HH", 16, 3)  # QTYPE=TXT(16), QCLASS=CHAOS(3)
    msg = header + question
    return struct.pack(">H", len(msg)) + msg


async def fetch(ip: str, port: int) -> bytes:
    reader, writer = await asyncio.open_connection(ip, port)
    try:
        writer.write(build_query())
        await writer.drain()
        length_bytes = await reader.readexactly(2)
        length = int.from_bytes(length_bytes, "big")
        return await reader.readexactly(min(length, 4096))
    except asyncio.IncompleteReadError as e:
        return e.partial
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def _skip_name(msg: bytes, pos: int) -> int:
    """Advance past a (possibly compressed) DNS name, returning the new offset."""
    n = len(msg)
    while pos < n:
        length = msg[pos]
        if length == 0:
            return pos + 1
        if length & 0xC0 == 0xC0:  # compression pointer: 2 bytes, name ends here
            return pos + 2
        pos += 1 + length
    return n


def parse_dns(msg: bytes) -> ProbeResult:
    result_raw: dict[str, Any] = {"length": len(msg)}
    if len(msg) < 12:
        return ProbeResult(service="dns", banner="dns: short response", raw=result_raw)

    flags = int.from_bytes(msg[2:4], "big")
    rcode = flags & 0x0F
    ancount = int.from_bytes(msg[6:8], "big")
    result_raw.update({"rcode": _RCODES.get(rcode, str(rcode)), "answers": ancount})

    # Skip the single question we asked (name + qtype + qclass).
    pos = _skip_name(msg, 12) + 4
    version: str | None = None
    for _ in range(min(ancount, 16)):
        if pos >= len(msg):
            break
        pos = _skip_name(msg, pos)
        if pos + 10 > len(msg):
            break
        rtype = int.from_bytes(msg[pos:pos + 2], "big")
        rdlength = int.from_bytes(msg[pos + 8:pos + 10], "big")
        rdata = msg[pos + 10:pos + 10 + rdlength]
        pos += 10 + rdlength
        if rtype == 16 and rdata:  # TXT: 1-byte length prefix + string
            txt_len = rdata[0]
            version = rdata[1:1 + txt_len].decode("utf-8", "replace")
            break

    if version:
        result_raw["version_bind"] = version
        return ProbeResult(service="dns", banner=f"DNS version.bind: {version}"[:300], raw=result_raw)
    if rcode == 5:
        return ProbeResult(service="dns", banner="DNS (version.bind refused)", raw=result_raw)
    return ProbeResult(service="dns", banner="DNS server (no version.bind)", raw=result_raw)
