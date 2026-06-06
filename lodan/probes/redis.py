"""Redis probe: INFO command, unauth detection only.

Sends RESP `*1\\r\\n$4\\r\\nINFO\\r\\n` and reads the bulk reply. Three
informative outcomes:

- A bulk string starting `# Server` → parse version, os, tcp_port, role.
- `-NOAUTH Authentication required.\\r\\n` → banner notes "auth required".
- Anything else → probe records raw so the operator can inspect later.

Never sends AUTH — lodan does not authenticate.
"""
from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from lodan.probes.base import ProbeResult

_DEFAULT_REDIS_PORTS = frozenset({6379, 6380})

_INTERESTING_FIELDS = (
    "redis_version",
    "redis_mode",
    "os",
    "arch_bits",
    "tcp_port",
    "role",
    "run_id",
)


class RedisProbe:
    name = "redis"
    default_ports = _DEFAULT_REDIS_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(fetch(ip, port), timeout=timeout)
        return parse_info(raw)


async def fetch(ip: str, port: int) -> bytes:
    reader, writer = await asyncio.open_connection(ip, port)
    try:
        writer.write(b"*1\r\n$4\r\nINFO\r\n")
        await writer.drain()
        # A real Redis keeps the connection open after replying, so reading
        # until EOF would block until our timeout. Stop as soon as we have a
        # complete RESP reply (or hit the 64 KB cap / EOF).
        buf = b""
        while len(buf) < 65536:
            chunk = await reader.read(4096)
            if not chunk:
                break
            buf += chunk
            if _resp_complete(buf):
                break
        return buf
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def _resp_complete(buf: bytes) -> bool:
    """True once `buf` holds a complete top-level RESP reply to INFO.

    We only need the three reply shapes INFO can produce: a bulk string
    (`$<len>\\r\\n<payload>\\r\\n`), a null bulk (`$-1\\r\\n`), or a simple
    error/status line (`-...\\r\\n` / `+...\\r\\n`).
    """
    if buf[:1] in (b"-", b"+"):
        return b"\r\n" in buf
    if buf[:1] == b"$":
        end = buf.find(b"\r\n")
        if end == -1:
            return False
        try:
            length = int(buf[1:end])
        except ValueError:
            return True  # malformed header; let the parser deal with it
        if length < 0:
            return True  # null bulk
        # header + CRLF + payload + trailing CRLF
        return len(buf) >= end + 2 + length + 2
    # Unknown reply type — wait for at least one line so the parser sees it.
    return b"\r\n" in buf


def parse_info(raw: bytes) -> ProbeResult:
    text = raw.decode("utf-8", "replace")
    result_raw: dict[str, Any] = {"length": len(raw)}

    if text.startswith("-NOAUTH") or text.startswith("-WRONGPASS"):
        first_line = text.split("\r\n", 1)[0]
        result_raw["auth_line"] = first_line
        return ProbeResult(
            service="redis",
            banner=f"Redis (auth required): {first_line.lstrip('-')}",
            raw=result_raw,
        )

    if not text.startswith("$"):
        return ProbeResult(
            service="redis",
            banner="redis: unexpected reply",
            raw={**result_raw, "head": text[:80]},
        )

    # Bulk string reply: $<len>\r\n<payload>\r\n
    try:
        header, rest = text.split("\r\n", 1)
        _length = int(header[1:])
    except ValueError:
        return ProbeResult(
            service="redis", banner="redis: malformed bulk", raw=result_raw
        )

    fields: dict[str, str] = {}
    for line in rest.splitlines():
        if ":" not in line or line.startswith("#"):
            continue
        key, value = line.split(":", 1)
        if key in _INTERESTING_FIELDS:
            fields[key] = value

    result_raw["fields"] = fields
    version = fields.get("redis_version", "unknown")
    role = fields.get("role", "")
    banner = f"Redis {version}"
    if role:
        banner += f" ({role})"
    return ProbeResult(service="redis", banner=banner, raw=result_raw)
