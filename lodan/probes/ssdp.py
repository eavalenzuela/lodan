"""SSDP / UPnP probe: unicast M-SEARCH.

UPnP devices answer M-SEARCH with a `SERVER:` header naming the OS, the UPnP
stack and the device firmware, plus a `LOCATION:` URL pointing at the device
description. That reaches consumer routers, printers, smart TVs, media servers
and IoT gear — a whole class of device that TCP banner and TLS probes never
touch.

Sent unicast to the discovered host, not to the 239.255.255.250 multicast
group: lodan probes hosts it was authorized to probe, and multicast would pull
in replies from devices nobody asked about.
"""
from __future__ import annotations

import asyncio
from typing import Any

from lodan.probes._udp import udp_exchange
from lodan.probes.base import ProbeResult

_DEFAULT_SSDP_PORTS = frozenset({1900})


class SSDPProbe:
    name = "ssdp"
    proto = "udp"
    default_ports = _DEFAULT_SSDP_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(
            udp_exchange(ip, port, build_msearch(ip, port), timeout, collect_for=0.3),
            timeout=timeout + 2,
        )
        return parse(raw)


def build_msearch(ip: str, port: int = 1900, *, mx: int = 1) -> bytes:
    """A unicast M-SEARCH for the root device.

    `ST: upnp:rootdevice` asks for one answer per device rather than the
    firehose `ssdp:all` produces.
    """
    host = f"[{ip}]:{port}" if ":" in ip else f"{ip}:{port}"
    return (
        "M-SEARCH * HTTP/1.1\r\n"
        f"HOST: {host}\r\n"
        'MAN: "ssdp:discover"\r\n'
        f"MX: {mx}\r\n"
        "ST: upnp:rootdevice\r\n"
        "\r\n"
    ).encode("ascii")


def parse(raw: bytes | None) -> ProbeResult:
    if not raw:
        return ProbeResult(service="ssdp", banner="ssdp: no response")
    text = raw.decode("utf-8", "replace")
    headers: dict[str, str] = {}
    for line in text.splitlines():
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        key = key.strip().lower()
        if key and key not in headers:
            headers[key] = value.strip()

    result_raw: dict[str, Any] = {"response_bytes": len(raw), "headers": headers}
    server = headers.get("server")
    location = headers.get("location")
    st = headers.get("st")
    usn = headers.get("usn")
    result_raw.update({"server": server, "location": location, "st": st, "usn": usn})

    if not headers:
        return ProbeResult(
            service="ssdp", banner="ssdp: unparseable reply", raw=result_raw
        )
    parts = [p for p in (server, st) if p]
    banner = "SSDP " + " | ".join(parts) if parts else "SSDP (UPnP responder)"
    return ProbeResult(service="ssdp", banner=banner[:300], raw=result_raw)
