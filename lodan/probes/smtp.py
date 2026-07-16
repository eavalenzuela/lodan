"""SMTP probe: greeting banner + EHLO capabilities. Detection-only.

Reads the server's `220` greeting, sends `EHLO` (a capability query — no mail,
no AUTH) immediately followed by `QUIT` so the server closes the connection and
the read is bounded. Surfaces the software banner and the advertised extensions,
notably whether STARTTLS is offered (a cleartext-SMTP exposure signal).
"""
from __future__ import annotations

import asyncio
from typing import Any

from lodan.probes._readers import greet_then_command
from lodan.probes.base import ProbeResult

_DEFAULT_SMTP_PORTS = frozenset({25, 587, 2525})
# EHLO name is cosmetic; QUIT bounds the read (server closes after replying).
_EHLO = b"EHLO lodan.probe\r\nQUIT\r\n"


class SMTPProbe:
    name = "smtp"
    default_ports = _DEFAULT_SMTP_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(
            greet_then_command(ip, port, command=_EHLO), timeout=timeout
        )
        return parse_smtp(raw)


def _lines(text: str) -> list[str]:
    return [ln.rstrip("\r") for ln in text.split("\n") if ln.strip()]


def parse_smtp(raw: bytes) -> ProbeResult:
    text = raw.decode("utf-8", "replace")
    lines = _lines(text)
    result_raw: dict[str, Any] = {"length": len(raw)}
    if not lines:
        return ProbeResult(service="smtp", banner="smtp: no greeting", raw=result_raw)

    greeting = next((ln for ln in lines if ln.startswith("220")), lines[0])
    # EHLO reply lines look like "250-KEYWORD ..." or the final "250 KEYWORD".
    caps: list[str] = []
    for ln in lines:
        if len(ln) >= 4 and ln[:3] == "250" and ln[3] in "- ":
            token = ln[4:].strip()
            if token:
                caps.append(token.split()[0].upper())
    starttls = "STARTTLS" in caps
    result_raw.update({"greeting": greeting[:200], "capabilities": caps, "starttls": starttls})

    banner = greeting[4:].strip() if len(greeting) > 4 else greeting
    tls_note = "" if starttls else " (no STARTTLS)"
    return ProbeResult(
        service="smtp",
        banner=f"SMTP {banner}{tls_note}"[:300],
        raw=result_raw,
    )
