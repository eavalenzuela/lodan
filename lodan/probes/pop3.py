"""POP3 probe: greeting + CAPA. Detection-only.

Reads the `+OK` greeting, sends `CAPA` (RFC 2449 capability query) then `QUIT`.
No `USER`/`PASS` is ever sent. Surfaces the advertised capabilities — notably
STLS (POP3's STARTTLS) whose absence on the cleartext 110 port is an exposure
signal.
"""
from __future__ import annotations

import asyncio
from typing import Any

from lodan.probes._readers import greet_then_command
from lodan.probes.base import ProbeResult

_DEFAULT_POP3_PORTS = frozenset({110})  # 995 is implicit TLS -> the TLS probe
_CAPA = b"CAPA\r\nQUIT\r\n"


class POP3Probe:
    name = "pop3"
    default_ports = _DEFAULT_POP3_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(
            greet_then_command(ip, port, command=_CAPA), timeout=timeout
        )
        return parse_pop3(raw)


def parse_pop3(raw: bytes) -> ProbeResult:
    text = raw.decode("utf-8", "replace")
    lines = [ln.rstrip("\r") for ln in text.split("\n")]
    result_raw: dict[str, Any] = {"length": len(raw)}
    greeting = next((ln for ln in lines if ln.startswith("+OK")), None)
    if greeting is None:
        return ProbeResult(service="pop3", banner="pop3: no greeting", raw=result_raw)

    # CAPA payload is the lines between "+OK ..." and the terminating ".".
    caps: list[str] = []
    seen_ok = False
    for ln in lines[1:]:
        if ln.startswith("+OK"):
            seen_ok = True
            continue
        if ln.strip() == ".":
            break
        if seen_ok and ln.strip():
            caps.append(ln.strip().split()[0].upper())
    stls = "STLS" in caps
    result_raw.update({"capabilities": caps, "stls": stls})

    return ProbeResult(
        service="pop3",
        banner=f"POP3 {greeting[4:].strip()[:120]}" + ("" if stls else " (no STLS)"),
        raw=result_raw,
    )
