"""UDP transport for datagram probes.

Discovery has always populated UDP rows, but `pick_probes` returned `[]` for
anything non-TCP, so lodan was structurally blind to every datagram service it
found. This is the missing transport: one send, one bounded read, one timeout,
mirroring the fetch shape of the TCP probes.

Every probe built on this sends exactly one datagram and reads what comes
back. No retries, no amplification loops, no source spoofing — the point is to
observe that a service answers and what it says about itself.
"""
from __future__ import annotations

import asyncio


class _Collector(asyncio.DatagramProtocol):
    """Capture the first datagram (and any that arrive before the deadline)."""

    def __init__(self, future: asyncio.Future) -> None:
        self._future = future
        self.packets: list[bytes] = []

    def datagram_received(self, data: bytes, addr) -> None:  # noqa: ARG002
        self.packets.append(data)
        if not self._future.done():
            self._future.set_result(data)

    def error_received(self, exc: Exception) -> None:
        # ICMP port-unreachable surfaces here. A closed port is data, not an
        # error worth raising — the caller sees an empty read.
        if not self._future.done():
            self._future.set_exception(exc)


async def udp_exchange(
    ip: str,
    port: int,
    payload: bytes,
    timeout: float,
    *,
    collect_for: float = 0.0,
) -> bytes | None:
    """Send one datagram, return the first reply (or None on silence).

    `collect_for` keeps the socket open a little longer after the first reply
    for protocols that answer with several datagrams (SSDP, mDNS). It never
    sends anything more.
    """
    loop = asyncio.get_running_loop()
    future: asyncio.Future = loop.create_future()
    transport = None
    try:
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _Collector(future), remote_addr=(ip, port)
        )
        transport.sendto(payload)
        try:
            first = await asyncio.wait_for(future, timeout=timeout)
        except (TimeoutError, OSError):
            return None
        if collect_for > 0:
            await asyncio.sleep(collect_for)
            return b"".join(protocol.packets)
        return first
    finally:
        if transport is not None:
            transport.close()


async def udp_exchange_all(
    ip: str,
    port: int,
    payload: bytes,
    timeout: float,
    *,
    collect_for: float = 0.5,
) -> list[bytes]:
    """Like `udp_exchange`, but returns every datagram received as a list.

    For multi-responder protocols (mDNS, SSDP) where the individual records
    matter and concatenating them would destroy the framing.
    """
    loop = asyncio.get_running_loop()
    future: asyncio.Future = loop.create_future()
    transport = None
    try:
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _Collector(future), remote_addr=(ip, port)
        )
        transport.sendto(payload)
        try:
            await asyncio.wait_for(future, timeout=timeout)
        except (TimeoutError, OSError):
            return []
        await asyncio.sleep(collect_for)
        return list(protocol.packets)
    finally:
        if transport is not None:
            transport.close()
