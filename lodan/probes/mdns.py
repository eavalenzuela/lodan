"""mDNS probe: DNS-SD service-type enumeration.

A unicast mDNS query for `_services._dns-sd._udp.local` asks a host to list
the service types it advertises — AirPlay, printing, SMB, SSH, HomeKit and so
on. That is a device-class signal for Macs, printers and IoT gear, and it
often names services on ports the port scan never reached.

Unicast to the discovered host (with the QU bit set) rather than to the
224.0.0.251 multicast group, for the same reason as SSDP: lodan asks the hosts
it was authorized to ask.
"""
from __future__ import annotations

import asyncio
import struct
from typing import Any

from lodan.probes._udp import udp_exchange
from lodan.probes.base import ProbeResult

_DEFAULT_MDNS_PORTS = frozenset({5353})

SERVICE_ENUM_NAME = "_services._dns-sd._udp.local"

_TYPE_PTR = 12
_TYPE_TXT = 16
_TYPE_SRV = 33
_CLASS_IN = 1
# Top bit of qclass: "unicast response requested" (RFC 6762 §5.4).
_QU_BIT = 0x8000


class MDNSProbe:
    name = "mdns"
    proto = "udp"
    default_ports = _DEFAULT_MDNS_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(
            udp_exchange(ip, port, build_service_query(), timeout, collect_for=0.3),
            timeout=timeout + 2,
        )
        return parse(raw)


def encode_name(name: str) -> bytes:
    out = b""
    for label in name.split("."):
        if not label:
            continue
        encoded = label.encode("utf-8")[:63]
        out += bytes([len(encoded)]) + encoded
    return out + b"\x00"


def build_service_query(name: str = SERVICE_ENUM_NAME) -> bytes:
    header = struct.pack(">HHHHHH", 0, 0, 1, 0, 0, 0)
    question = encode_name(name) + struct.pack(">HH", _TYPE_PTR, _CLASS_IN | _QU_BIT)
    return header + question


def _read_name(buf: bytes, pos: int, depth: int = 0) -> tuple[str, int]:
    """Decode a DNS name, following compression pointers.

    `depth` bounds pointer chasing: a malicious or broken responder can encode
    a pointer loop, and this must terminate on one rather than hang the probe.
    """
    labels: list[str] = []
    jumped = False
    end = pos
    while pos < len(buf):
        length = buf[pos]
        if length == 0:
            pos += 1
            if not jumped:
                end = pos
            break
        if length & 0xC0 == 0xC0:
            if pos + 2 > len(buf) or depth > 10:
                raise ValueError("bad or looping name pointer")
            pointer = struct.unpack_from(">H", buf, pos)[0] & 0x3FFF
            if not jumped:
                end = pos + 2
            jumped = True
            suffix, _ = _read_name(buf, pointer, depth + 1)
            if suffix:
                labels.append(suffix)
            break
        pos += 1
        if pos + length > len(buf):
            raise ValueError("label overruns buffer")
        labels.append(buf[pos : pos + length].decode("utf-8", "replace"))
        pos += length
        if not jumped:
            end = pos
    return ".".join(labels), end


def parse(raw: bytes | None) -> ProbeResult:
    if not raw or len(raw) < 12:
        return ProbeResult(service="mdns", banner="mdns: no response")
    result_raw: dict[str, Any] = {"response_bytes": len(raw)}
    try:
        _tid, _flags, qd, an, ns, ar = struct.unpack_from(">HHHHHH", raw, 0)
        pos = 12
        for _ in range(qd):
            _name, pos = _read_name(raw, pos)
            pos += 4
        services: list[str] = []
        instances: list[str] = []
        for _ in range(an + ns + ar):
            if pos >= len(raw):
                break
            _name, pos = _read_name(raw, pos)
            if pos + 10 > len(raw):
                break
            rtype, _rclass, _ttl, rdlength = struct.unpack_from(">HHIH", raw, pos)
            pos += 10
            rdata_end = pos + rdlength
            if rdata_end > len(raw):
                break
            if rtype == _TYPE_PTR:
                target, _ = _read_name(raw, pos)
                if target.startswith("_"):
                    services.append(target)
                else:
                    instances.append(target)
            elif rtype == _TYPE_SRV:
                instances.append(_read_name(raw, pos + 6)[0])
            pos = rdata_end
    except (ValueError, struct.error, IndexError) as e:
        return ProbeResult(
            service="mdns", banner=f"mdns: malformed response ({e})", raw=result_raw
        )

    services = sorted(set(services))
    instances = sorted(set(instances))
    result_raw.update({"service_types": services, "instances": instances})
    if not services and not instances:
        return ProbeResult(
            service="mdns", banner="mdns: responder with no advertised services",
            raw=result_raw,
        )
    banner = "mDNS " + ", ".join(services[:8] or instances[:8])
    return ProbeResult(service="mdns", banner=banner[:300], raw=result_raw)
