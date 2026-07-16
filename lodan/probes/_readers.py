"""Small shared read helpers for the line/greeting-oriented probes.

Kept deliberately tiny: connect, optionally exchange a line or two, read a
bounded amount, and hand the raw bytes to a pure parser. The parsers live in
each probe module and are what the tests exercise offline.
"""
from __future__ import annotations

import asyncio
import contextlib

_CAP = 65536


async def read_until(
    reader: asyncio.StreamReader,
    *,
    until: tuple[bytes, ...] = (),
    cap: int = _CAP,
) -> bytes:
    """Read chunks until any `until` marker appears in the buffer, EOF, or cap.

    `until=()` means "read until EOF or cap". The per-read timeout is the
    caller's `asyncio.wait_for` around the whole probe.
    """
    buf = b""
    while len(buf) < cap:
        chunk = await reader.read(4096)
        if not chunk:
            break
        buf += chunk
        if until and any(marker in buf for marker in until):
            break
    return buf


async def greet_then_command(
    ip: str,
    port: int,
    *,
    command: bytes,
    greeting_until: tuple[bytes, ...] = (b"\n",),
    reply_until: tuple[bytes, ...] = (),
    cap: int = _CAP,
) -> bytes:
    """Read a server greeting, send `command`, read the reply. Returns the whole
    conversation (greeting + reply) so the parser sees both.

    Used by the text protocols that announce themselves first (SMTP, FTP, IMAP,
    POP3). No credentials are ever sent — `command` is a capability query only.
    """
    reader, writer = await asyncio.open_connection(ip, port)
    try:
        greeting = await read_until(reader, until=greeting_until, cap=cap)
        writer.write(command)
        await writer.drain()
        reply = await read_until(reader, until=reply_until, cap=max(0, cap - len(greeting)))
        return greeting + reply
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()
