"""Reverse DNS (PTR) lookups.

Async-native via `loop.getnameinfo`; no threadpool churn unless the
resolver itself blocks. We return None for any failure — enrichment is
best-effort, never scan-fatal.
"""
from __future__ import annotations

import asyncio
import socket


async def resolve(ip: str, timeout: float = 2.0) -> str | None:
    """Return the PTR record for `ip` or None if there isn't one.

    Filters out the common "no PTR found" case where getnameinfo echoes
    back the IP we passed in.
    """
    loop = asyncio.get_event_loop()
    try:
        host, _ = await asyncio.wait_for(
            loop.getnameinfo((ip, 0), socket.NI_NAMEREQD), timeout=timeout
        )
    except (TimeoutError, socket.gaierror, OSError):
        return None
    return host if host and host != ip else None
