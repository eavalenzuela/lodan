from __future__ import annotations

import asyncio
from unittest.mock import patch

from lodan.enrich import rdns


def test_resolve_returns_host_when_different_from_ip() -> None:
    async def fake(addr, flags):
        return ("host-5.corp", "0")

    with patch("asyncio.get_event_loop") as mock_loop:
        mock_loop.return_value.getnameinfo = fake
        got = asyncio.run(rdns.resolve("10.0.0.5"))
    assert got == "host-5.corp"


def test_resolve_returns_none_when_echoes_ip() -> None:
    async def fake(addr, flags):
        return ("10.0.0.5", "0")

    with patch("asyncio.get_event_loop") as mock_loop:
        mock_loop.return_value.getnameinfo = fake
        got = asyncio.run(rdns.resolve("10.0.0.5"))
    assert got is None


def test_resolve_timeout_returns_none() -> None:
    async def slow(addr, flags):
        await asyncio.sleep(1.0)
        return ("x", "y")

    with patch("asyncio.get_event_loop") as mock_loop:
        mock_loop.return_value.getnameinfo = slow
        got = asyncio.run(rdns.resolve("10.0.0.5", timeout=0.05))
    assert got is None


def test_resolve_gaierror_returns_none() -> None:
    import socket

    async def fake(addr, flags):
        raise socket.gaierror("no ptr")

    with patch("asyncio.get_event_loop") as mock_loop:
        mock_loop.return_value.getnameinfo = fake
        got = asyncio.run(rdns.resolve("10.0.0.5"))
    assert got is None
