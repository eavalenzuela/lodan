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
import time
from collections.abc import AsyncIterator
from typing import Any

from lodan.discovery.base import DiscoveryResult, DiscoverySpec, StackObservation


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
    from scapy.all import IP, TCP, UDP, IPv6, Raw, conf, sr  # type: ignore

    conf.verb = 0
    packets = []
    for net in spec.targets:
        l3 = IPv6 if net.version == 6 else IP  # IPv4 or IPv6 network layer
        for ip in net.hosts() if net.num_addresses > 1 else [net.network_address]:
            ip_s = str(ip)
            for port in spec.ports:
                if spec.tcp:
                    packets.append(l3(dst=ip_s) / TCP(dport=port, flags="S"))
                if spec.udp:
                    packets.append(
                        l3(dst=ip_s) / UDP(dport=port) / Raw(load=_udp_payload(port))
                    )
    inter = 1.0 / spec.rate_pps if spec.rate_pps > 0 else 0
    answered, _ = sr(packets, timeout=2, verbose=0, inter=inter)
    return list(answered)


def _observe_stack(rcv: Any, ttl: int, df: bool, ip_id: int | None) -> StackObservation | None:
    """Lift the passive fingerprint fields off a SYN-ACK.

    Reads only header fields already present in the reply. A malformed or
    exotic option list degrades to whatever parsed cleanly rather than
    failing discovery — a broken responder must never cost us the open-port
    result itself.
    """
    from scapy.all import TCP  # type: ignore

    tcp = rcv[TCP]
    names: list[str] = []
    mss: int | None = None
    wscale: int | None = None
    sack_ok = False
    timestamps = False
    ts_val: int | None = None
    try:
        raw_options = list(tcp.options or [])
    except Exception:
        raw_options = []
    for entry in raw_options:
        try:
            name, value = entry
        except (TypeError, ValueError):
            continue
        names.append(str(name))
        if name == "MSS":
            mss = int(value) if value is not None else None
        elif name == "WScale":
            wscale = int(value) if value is not None else None
        elif name == "SAckOK":
            sack_ok = True
        elif name == "Timestamp":
            timestamps = True
            if isinstance(value, tuple) and value:
                ts_val = int(value[0])
    return StackObservation(
        ttl=ttl,
        window=int(tcp.window),
        df=df,
        ip_id=ip_id,
        mss=mss,
        window_scale=wscale,
        sack_ok=sack_ok,
        timestamps=timestamps,
        ts_val=ts_val,
        options=tuple(names),
        observed_at=float(getattr(rcv, "time", None) or time.time()),
    )


def _classify(snd: Any, rcv: Any) -> DiscoveryResult | None:
    """Turn a (sent, received) scapy pair into a DiscoveryResult or None."""
    from scapy.all import IP, TCP, UDP, IPv6  # type: ignore

    ttl: int | None = None
    df = False
    ip_id: int | None = None
    if IP in rcv:
        src: str | None = rcv[IP].src
        ttl = int(rcv[IP].ttl)
        # IPv4 flags is a scapy FlagValue; bit 1 is Don't-Fragment.
        df = bool(int(rcv[IP].flags) & 0x02)
        ip_id = int(rcv[IP].id)
    elif IPv6 in rcv:
        src = rcv[IPv6].src
        ttl = int(rcv[IPv6].hlim)
        # IPv6 has no in-transit fragmentation and no identification field,
        # so DF is implicit and ip_id has no analogue.
        df = True
    else:
        src = None
    if src is None:
        return None
    if TCP in rcv:
        if rcv[TCP].flags & 0x12 == 0x12:  # SYN+ACK
            stack = None
            if ttl is not None:
                try:
                    stack = _observe_stack(rcv, ttl, df, ip_id)
                except Exception:
                    stack = None  # fingerprinting is never worth losing the hit
            return DiscoveryResult(
                ip=str(src), port=int(snd[TCP].dport), proto="tcp", stack=stack,
            )
        return None
    if UDP in rcv:
        return DiscoveryResult(ip=str(src), port=int(snd[UDP].dport), proto="udp")
    return None
