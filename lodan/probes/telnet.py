"""Telnet probe: initial option negotiation + banner. Detection-only.

Reads whatever the server sends on connect — the IAC option negotiation and any
login banner — and stops. lodan sends nothing (no option responses, no login).
Telnet being reachable at all is a cleartext-administration exposure; the banner
often also identifies the device.
"""
from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from lodan.probes._readers import read_until
from lodan.probes.base import ProbeResult

_DEFAULT_TELNET_PORTS = frozenset({23, 2323})

_IAC = 0xFF
_SB, _SE = 0xFA, 0xF0
_NEG_CMDS = {0xFB: "WILL", 0xFC: "WONT", 0xFD: "DO", 0xFE: "DONT"}


class TelnetProbe:
    name = "telnet"
    default_ports = _DEFAULT_TELNET_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(fetch(ip, port), timeout=timeout)
        return parse_telnet(raw)


async def fetch(ip: str, port: int) -> bytes:
    reader, writer = await asyncio.open_connection(ip, port)
    try:
        # Telnet sends its negotiation immediately; one bounded read captures it.
        return await read_until(reader, until=(), cap=4096)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def _strip_iac(raw: bytes) -> tuple[bytes, list[str]]:
    """Return (visible bytes, negotiated option commands) — IAC sequences removed."""
    out = bytearray()
    options: list[str] = []
    i = 0
    n = len(raw)
    while i < n:
        b = raw[i]
        if b != _IAC:
            out.append(b)
            i += 1
            continue
        if i + 1 >= n:
            break
        cmd = raw[i + 1]
        if cmd == _IAC:  # escaped literal 0xFF
            out.append(_IAC)
            i += 2
        elif cmd in _NEG_CMDS:
            opt = raw[i + 2] if i + 2 < n else -1
            options.append(f"{_NEG_CMDS[cmd]}:{opt}")
            i += 3
        elif cmd == _SB:  # subnegotiation: skip to IAC SE
            j = raw.find(bytes([_IAC, _SE]), i + 2)
            i = (j + 2) if j != -1 else n
        else:
            i += 2
    return bytes(out), options


def parse_telnet(raw: bytes) -> ProbeResult:
    result_raw: dict[str, Any] = {"length": len(raw)}
    if not raw:
        return ProbeResult(service="telnet", banner="telnet: no data", raw=result_raw)

    visible, options = _strip_iac(raw)
    text = "".join(ch for ch in visible.decode("utf-8", "replace") if ch.isprintable() or ch in "\r\n\t")
    banner_text = " ".join(text.split())[:200]
    result_raw.update({"options": options, "banner_text": banner_text})
    banner = f"Telnet {banner_text}".strip() if banner_text else "Telnet (cleartext admin)"
    return ProbeResult(service="telnet", banner=banner[:300], raw=result_raw)
