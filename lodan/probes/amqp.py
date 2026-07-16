"""AMQP 0-9-1 probe: protocol header -> Connection.Start. Detection-only.

Sends the AMQP 0-9-1 protocol header (what a client sends first) and reads the
server's `Connection.Start` method frame — which carries the broker's version and
`server-properties` (product/version, e.g. RabbitMQ) — before any authentication.
lodan stops there: no `Connection.StartOk`, no SASL credentials. A server that
speaks a different version replies with its own protocol header instead, which is
equally identifying.
"""
from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from lodan.probes.base import ProbeResult

_DEFAULT_AMQP_PORTS = frozenset({5672, 5671})
_AMQP_HEADER = b"AMQP\x00\x00\x09\x01"  # protocol id 0, major 9, minor 1


class AMQPProbe:
    name = "amqp"
    default_ports = _DEFAULT_AMQP_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(fetch(ip, port), timeout=timeout)
        return parse_amqp(raw)


async def fetch(ip: str, port: int) -> bytes:
    reader, writer = await asyncio.open_connection(ip, port)
    try:
        writer.write(_AMQP_HEADER)
        await writer.drain()
        return await reader.read(4096)
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def _extract_field(payload: bytes, name: bytes) -> str | None:
    """Pull a short-named 'S' (long-string) field value out of a field table.

    Looks for the length-prefixed field name followed by the 'S' type marker and
    a 4-byte-length string — enough to read product/version without a full
    field-table decoder. Best-effort; returns None if the shape isn't there.
    """
    marker = bytes([len(name)]) + name
    idx = payload.find(marker)
    if idx == -1:
        return None
    pos = idx + len(marker)
    if pos >= len(payload) or payload[pos:pos + 1] != b"S":
        return None
    pos += 1
    if pos + 4 > len(payload):
        return None
    slen = int.from_bytes(payload[pos:pos + 4], "big")
    value = payload[pos + 4:pos + 4 + slen]
    if len(value) != slen:
        return None
    return value.decode("utf-8", "replace")


def parse_amqp(raw: bytes) -> ProbeResult:
    result_raw: dict[str, Any] = {"length": len(raw)}
    if raw[:4] == b"AMQP":
        # Version-negotiation reply: bytes 4..8 are the server's preferred version.
        ver = ".".join(str(b) for b in raw[5:8]) if len(raw) >= 8 else "?"
        result_raw["offered_version"] = ver
        return ProbeResult(service="amqp", banner=f"AMQP (server offers {ver})", raw=result_raw)

    if not raw or raw[0] != 0x01:  # not a method frame
        return ProbeResult(service="amqp", banner="amqp: unexpected reply", raw=result_raw)

    # Method frame: type(1) channel(2) size(4) payload frame-end(1).
    payload = raw[7:-1] if len(raw) > 8 else b""
    major = payload[4] if len(payload) > 4 else 0
    minor = payload[5] if len(payload) > 5 else 0
    product = _extract_field(payload, b"product")
    version = _extract_field(payload, b"version")
    result_raw.update({
        "amqp_version": f"{major}-{minor}", "product": product, "server_version": version,
    })
    label = product or "AMQP"
    if version:
        label += f" {version}"
    return ProbeResult(service="amqp", banner=f"{label} (AMQP {major}-{minor})"[:300], raw=result_raw)
