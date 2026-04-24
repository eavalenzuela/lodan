"""Backend-neutral types for port discovery.

Every backend produces an async iterable of `DiscoveryResult`. The scan loop
doesn't care which backend — masscan, naabu, scapy, or a test fake — as long
as it honors the spec (targets, ports, proto flags, rate limit) and yields
results as they land.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from ipaddress import IPv4Network
from typing import Literal, Protocol, runtime_checkable


@dataclass(frozen=True)
class DiscoverySpec:
    targets: list[IPv4Network]
    ports: list[int]
    tcp: bool = True
    udp: bool = False
    rate_pps: int = 1000


@dataclass(frozen=True)
class DiscoveryResult:
    ip: str
    port: int
    proto: Literal["tcp", "udp"]


@runtime_checkable
class DiscoveryBackend(Protocol):
    name: str

    def available(self) -> bool: ...

    async def run(self, spec: DiscoverySpec) -> AsyncIterator[DiscoveryResult]: ...
