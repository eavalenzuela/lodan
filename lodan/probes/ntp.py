"""NTP probe: mode-6 readvar plus amplification-reflector exposure.

Two things worth knowing about a reachable NTP server on a range you own:
what it is (the mode-6 `readvar` system variables name the implementation and
often the OS), and whether it is usable as a **reflector** — the legacy
`monlist` command and some mode-6 queries return far more data than they
receive, which makes the host a DDoS amplifier pointed at someone else.

lodan sends one mode-6 read and measures the response-to-request byte ratio.
It deliberately does NOT harvest monlist output in a loop: the amplification
factor is the finding, and one datagram establishes it. Reporting "this host
of yours can be used to attack third parties" is the defensive point.
"""
from __future__ import annotations

import asyncio
import re
from typing import Any

from lodan.probes._udp import udp_exchange
from lodan.probes.base import ProbeResult

_DEFAULT_NTP_PORTS = frozenset({123})

# An amplification factor above this is worth reporting as an exposure.
AMPLIFICATION_THRESHOLD = 5.0

_VAR_RE = re.compile(r"(?P<key>[a-zA-Z0-9_]+)=(?:\"(?P<quoted>[^\"]*)\"|(?P<bare>[^,]*))")


class NTPProbe:
    name = "ntp"
    proto = "udp"
    default_ports = _DEFAULT_NTP_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        request = build_readvar()
        raw = await asyncio.wait_for(
            udp_exchange(ip, port, request, timeout), timeout=timeout + 1
        )
        return parse(raw, request_bytes=len(request))


def build_readvar(*, sequence: int = 1) -> bytes:
    """NTP mode-6 control message, opcode 2 (read variables), no association.

    12-byte header: leap/version/mode, opcode, sequence, status,
    association id, offset, count.
    """
    li_vn_mode = (0 << 6) | (2 << 3) | 6      # version 2, mode 6 (control)
    return bytes([li_vn_mode, 2]) + b"".join(
        value.to_bytes(2, "big") for value in (sequence, 0, 0, 0, 0)
    )


def build_monlist() -> bytes:
    """Legacy mode-7 MON_GETLIST_1 request, used only for reflector detection.

    Built so the probe can establish whether the command is *enabled*. lodan
    sends this at most once and never reads a second page — the exposure is
    the point, not the data.
    """
    return bytes([0x17, 0x00, 0x03, 0x2A]) + b"\x00" * 4


def parse(raw: bytes | None, *, request_bytes: int) -> ProbeResult:
    if not raw:
        return ProbeResult(service="ntp", banner="ntp: no response")
    result_raw: dict[str, Any] = {
        "response_bytes": len(raw),
        "request_bytes": request_bytes,
    }
    amplification = round(len(raw) / request_bytes, 2) if request_bytes else None
    result_raw["amplification"] = amplification

    variables: dict[str, str] = {}
    if len(raw) > 12:
        payload = raw[12:].decode("ascii", "replace")
        for m in _VAR_RE.finditer(payload):
            value = m.group("quoted")
            if value is None:
                value = (m.group("bare") or "").strip()
            variables[m.group("key")] = value.strip()
    if variables:
        result_raw["variables"] = variables

    version = variables.get("version") or variables.get("processor") or ""
    system = variables.get("system") or ""
    parts = [p for p in (version, system) if p]
    banner = "NTP " + " ".join(parts) if parts else "NTP (mode-6 control enabled)"
    if amplification and amplification >= AMPLIFICATION_THRESHOLD:
        banner += f" [amplification x{amplification}]"
    return ProbeResult(
        service="ntp", banner=banner[:300], amplification=amplification, raw=result_raw
    )
