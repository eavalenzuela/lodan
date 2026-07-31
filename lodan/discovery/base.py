"""Backend-neutral types for port discovery.

Every backend produces an async iterable of `DiscoveryResult`. The scan loop
doesn't care which backend — masscan, naabu, scapy, or a test fake — as long
as it honors the spec (targets, ports, proto flags, rate limit) and yields
results as they land.
"""
from __future__ import annotations

from collections.abc import AsyncIterator
from dataclasses import dataclass
from ipaddress import IPv4Network, IPv6Network
from typing import Literal, Protocol, runtime_checkable


@dataclass(frozen=True)
class DiscoverySpec:
    targets: list[IPv4Network | IPv6Network]
    ports: list[int]
    tcp: bool = True
    udp: bool = False
    rate_pps: int = 1000


@dataclass(frozen=True)
class StackObservation:
    """L3/L4 header fields lifted off a discovery SYN-ACK.

    Every field here is something the responder volunteered in reply to the
    SYN discovery already sent — capturing it costs no additional packet.

    Only backends that see the raw packet can fill this in. naabu's connect
    scan exposes no L3/L4 fields, and masscan's `-oL` list output carries no
    TTL, so both leave `DiscoveryResult.stack` as None and every derived
    column degrades to NULL.
    """

    ttl: int                              # IPv4 TTL or IPv6 hop limit
    window: int                           # advertised TCP receive window
    df: bool = False                      # IPv4 Don't-Fragment bit
    ip_id: int | None = None              # IPv4 identification field
    mss: int | None = None
    window_scale: int | None = None
    sack_ok: bool = False
    timestamps: bool = False
    ts_val: int | None = None             # TSval, for the clock-skew estimate
    options: tuple[str, ...] = ()         # TCP option kinds, in wire order
    observed_at: float | None = None      # epoch seconds the reply landed


@dataclass(frozen=True)
class DiscoveryResult:
    ip: str
    port: int
    proto: Literal["tcp", "udp"]
    stack: StackObservation | None = None


@runtime_checkable
class DiscoveryBackend(Protocol):
    name: str

    def available(self) -> bool: ...

    async def run(self, spec: DiscoverySpec) -> AsyncIterator[DiscoveryResult]: ...
