"""FTP probe: greeting banner + FEAT feature list. Detection-only.

Reads the `220` greeting, sends `FEAT` (a capability query, RFC 2389) then
`QUIT`. No `USER`/`PASS` is ever sent — lodan does not attempt anonymous or any
other login. Surfaces the software banner and whether the control channel offers
AUTH TLS (a cleartext-FTP exposure signal when it does not).
"""
from __future__ import annotations

import asyncio
from typing import Any

from lodan.probes._readers import greet_then_command
from lodan.probes.base import ProbeResult

_DEFAULT_FTP_PORTS = frozenset({21})
_FEAT = b"FEAT\r\nQUIT\r\n"


class FTPProbe:
    name = "ftp"
    default_ports = _DEFAULT_FTP_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(
            greet_then_command(ip, port, command=_FEAT), timeout=timeout
        )
        return parse_ftp(raw)


def _lines(text: str) -> list[str]:
    return [ln.rstrip("\r") for ln in text.split("\n") if ln.strip()]


def parse_ftp(raw: bytes) -> ProbeResult:
    text = raw.decode("utf-8", "replace")
    lines = _lines(text)
    result_raw: dict[str, Any] = {"length": len(raw)}
    if not lines:
        return ProbeResult(service="ftp", banner="ftp: no greeting", raw=result_raw)

    greeting = next((ln for ln in lines if ln.startswith("220")), lines[0])
    # FEAT reply: "211-Features:" then " KEYWORD" indented lines then "211 End".
    features: list[str] = []
    in_feat = False
    for ln in lines:
        if ln.startswith("211-") or ln[:3] == "211" and "feat" in ln.lower():
            in_feat = True
            continue
        if ln.startswith("211 ") or ln.startswith("211-End") or ln.upper().endswith("END"):
            in_feat = False
            continue
        if in_feat and ln.startswith(" "):
            features.append(ln.strip().split()[0].upper())
    auth_tls = any(f.startswith("AUTH") for f in features)
    result_raw.update({"greeting": greeting[:200], "features": features, "auth_tls": auth_tls})

    banner = greeting[4:].strip() if len(greeting) > 4 else greeting
    tls_note = "" if auth_tls else " (no AUTH TLS)"
    return ProbeResult(
        service="ftp",
        banner=f"FTP {banner}{tls_note}"[:300],
        raw=result_raw,
    )
