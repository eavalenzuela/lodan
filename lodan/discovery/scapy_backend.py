"""Pure-Python discovery backend via scapy.

Fallback when masscan/naabu aren't installed. Requires CAP_NET_RAW (on Linux
that usually means euid 0 or a granted capability). Slower than masscan — run
it on small target sets or set a conservative rate.

scapy is imported lazily inside methods so that importing this module is
cheap and doesn't fail when scapy isn't installed.
"""
from __future__ import annotations

import asyncio
import os
import platform
from collections.abc import AsyncIterator
from typing import Any

from lodan.discovery.base import DiscoveryResult, DiscoverySpec


def _udp_payload(port: int) -> bytes:
    """Protocol-specific payloads for the common UDP services.

    Targeted payloads dramatically improve hit rate for DNS/NTP; for every
    other port we send 8 zero bytes. Richer per-protocol probing lives in the
    probe phase, not here.
    """
    if port == 53:
        # Minimal DNS query for "version.bind" CHAOS TXT, standard probe.
        return bytes.fromhex(
            "1234010000010000000000000776657273696f6e0462696e640000100003"
        )
    if port == 123:
        # NTP v4 client request; 48 zero bytes with LI=0 VN=4 Mode=3 (0x23).
        return b"\x23" + b"\x00" * 47
    return b"\x00" * 8


class ScapyBackend:
    name = "scapy"

    def available(self) -> bool:
        if platform.system() != "Linux":
            return False
        try:
            import scapy.all  # noqa: F401
        except Exception:
            return False
        # Raw sockets need CAP_NET_RAW; the cheap proxy is euid 0.
        return hasattr(os, "geteuid") and os.geteuid() == 0

    async def run(self, spec: DiscoverySpec) -> AsyncIterator[DiscoveryResult]:
        if not (spec.tcp or spec.udp):
            return
        answers = await asyncio.to_thread(_sweep, spec)
        for snd, rcv in answers:
            r = _classify(snd, rcv)
            if r is not None:
                yield r


def _sweep(spec: DiscoverySpec) -> list[tuple[Any, Any]]:
    from scapy.all import IP, TCP, UDP, Raw, conf, sr  # type: ignore

    conf.verb = 0
    packets = []
    for net in spec.targets:
        for ip in net.hosts() if net.num_addresses > 1 else [net.network_address]:
            ip_s = str(ip)
            for port in spec.ports:
                if spec.tcp:
                    packets.append(IP(dst=ip_s) / TCP(dport=port, flags="S"))
                if spec.udp:
                    packets.append(
                        IP(dst=ip_s) / UDP(dport=port) / Raw(load=_udp_payload(port))
                    )
    inter = 1.0 / spec.rate_pps if spec.rate_pps > 0 else 0
    answered, _ = sr(packets, timeout=2, verbose=0, inter=inter)
    return list(answered)


def _classify(snd: Any, rcv: Any) -> DiscoveryResult | None:
    """Turn a (sent, received) scapy pair into a DiscoveryResult or None."""
    from scapy.all import IP, TCP, UDP  # type: ignore

    src = rcv[IP].src if IP in rcv else None
    if src is None:
        return None
    if TCP in rcv:
        if rcv[TCP].flags & 0x12 == 0x12:  # SYN+ACK
            return DiscoveryResult(ip=str(src), port=int(snd[TCP].dport), proto="tcp")
        return None
    if UDP in rcv:
        return DiscoveryResult(ip=str(src), port=int(snd[UDP].dport), proto="udp")
    return None
