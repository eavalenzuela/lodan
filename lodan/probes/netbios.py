"""NetBIOS Name Service probe: NBSTAT node-status request.

UDP/137 answers an unauthenticated node-status query with the machine's
NetBIOS name, its workgroup or domain, and the adapter's MAC address. The name
is a stable cross-scan identity pivot for Windows and Samba hosts that carry no
useful TCP banner, and the MAC's OUI names the hardware vendor — which is often
the only vendor signal an embedded device gives up at all.

One datagram, no authentication, no name registration, no writes.
"""
from __future__ import annotations

import asyncio
import struct
from typing import Any

from lodan.probes._udp import udp_exchange
from lodan.probes.base import ProbeResult

_DEFAULT_NETBIOS_PORTS = frozenset({137})

# NetBIOS suffix byte -> what the name means. The <00> workstation and <20>
# server entries are the ones worth surfacing.
_SUFFIXES = {
    0x00: "workstation",
    0x03: "messenger",
    0x1B: "domain-master-browser",
    0x1C: "domain-controllers",
    0x1D: "master-browser",
    0x1E: "browser-elections",
    0x20: "file-server",
}


class NetBIOSProbe:
    name = "netbios"
    proto = "udp"
    default_ports = _DEFAULT_NETBIOS_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(
            udp_exchange(ip, port, build_nbstat(), timeout), timeout=timeout + 1
        )
        return parse(raw)


def _encode_netbios_name(name: str = "*", suffix: int = 0x00) -> bytes:
    """First-level NetBIOS name encoding (RFC 1001 §4.1).

    Each byte of the 16-byte padded name splits into two nibbles, each offset
    by 'A'. The wildcard "*" is padded with NULs rather than spaces.
    """
    padded = name.encode("ascii", "replace")[:15]
    padded = padded + b"\x00" * (15 - len(padded))
    padded += bytes([suffix])
    out = bytearray()
    for byte in padded:
        out.append(ord("A") + (byte >> 4))
        out.append(ord("A") + (byte & 0x0F))
    return bytes([len(out)]) + bytes(out) + b"\x00"


def build_nbstat(*, transaction_id: int = 0x1337) -> bytes:
    """NBSTAT (node status) request for the wildcard name."""
    header = struct.pack(
        ">HHHHHH",
        transaction_id,
        0x0000,       # flags: query, broadcast off
        1,            # qdcount
        0, 0, 0,
    )
    question = _encode_netbios_name("*") + struct.pack(">HH", 0x0021, 0x0001)
    return header + question


def _decode_name(raw: bytes) -> tuple[str, int]:
    """A node-status entry is 15 chars of name + a suffix byte."""
    name = raw[:15].decode("ascii", "replace").rstrip(" \x00")
    return name, raw[15] if len(raw) > 15 else 0


def parse(raw: bytes | None) -> ProbeResult:
    if not raw or len(raw) < 12:
        return ProbeResult(service="netbios", banner="netbios: no response")
    result_raw: dict[str, Any] = {"response_bytes": len(raw)}
    try:
        # Skip the header and the echoed question, then the RR header.
        pos = 12
        while pos < len(raw) and raw[pos] != 0:
            pos += raw[pos] + 1
        pos += 1                     # terminating null
        pos += 4                     # qtype + qclass
        pos += 4 + 4 + 2             # type + class + ttl + rdlength
        if pos >= len(raw):
            raise ValueError("truncated before node-status payload")
        count = raw[pos]
        pos += 1
    except (ValueError, IndexError) as e:
        return ProbeResult(
            service="netbios", banner=f"netbios: malformed response ({e})", raw=result_raw
        )

    names: list[dict[str, Any]] = []
    for _ in range(min(count, 64)):
        if pos + 18 > len(raw):
            break
        name, suffix = _decode_name(raw[pos : pos + 16])
        flags = struct.unpack_from(">H", raw, pos + 16)[0]
        pos += 18
        names.append({
            "name": name,
            "suffix": suffix,
            "kind": _SUFFIXES.get(suffix, f"0x{suffix:02x}"),
            "group": bool(flags & 0x8000),
        })

    mac = None
    if pos + 6 <= len(raw):
        mac_bytes = raw[pos : pos + 6]
        if any(mac_bytes):
            mac = ":".join(f"{b:02x}" for b in mac_bytes)

    # The unique <00> entry is the machine name; a group entry is the domain.
    computer = next(
        (n["name"] for n in names if n["suffix"] == 0x00 and not n["group"]), None
    )
    workgroup = next(
        (n["name"] for n in names if n["suffix"] == 0x00 and n["group"]), None
    )

    result_raw.update({
        "names": names,
        "computer_name": computer,
        "workgroup": workgroup,
        "mac": mac,
        "mac_oui": mac[:8] if mac else None,
    })
    parts = [p for p in (computer, f"({workgroup})" if workgroup else None) if p]
    banner = "NetBIOS " + " ".join(parts) if parts else "NetBIOS node status"
    if mac:
        banner += f" [{mac}]"
    return ProbeResult(
        service="netbios",
        banner=banner[:300],
        netbios_name=computer,
        mac_oui=mac[:8] if mac else None,
        raw=result_raw,
    )
