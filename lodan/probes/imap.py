"""IMAP probe: greeting + CAPABILITY. Detection-only.

Reads the `* OK` greeting, sends `CAPABILITY` then `LOGOUT`. No `LOGIN` is ever
sent. Surfaces the advertised capabilities — notably STARTTLS and whether
LOGINDISABLED is set (a plaintext-login exposure signal when it is not, on the
cleartext 143 port).
"""
from __future__ import annotations

import asyncio
from typing import Any

from lodan.probes._readers import greet_then_command
from lodan.probes.base import ProbeResult

_DEFAULT_IMAP_PORTS = frozenset({143})  # 993 is implicit TLS -> the TLS probe
_CAPABILITY = b"a1 CAPABILITY\r\na2 LOGOUT\r\n"


class IMAPProbe:
    name = "imap"
    default_ports = _DEFAULT_IMAP_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(
            greet_then_command(ip, port, command=_CAPABILITY), timeout=timeout
        )
        return parse_imap(raw)


def parse_imap(raw: bytes) -> ProbeResult:
    text = raw.decode("utf-8", "replace")
    result_raw: dict[str, Any] = {"length": len(raw)}
    upper = text.upper()
    if "OK" not in upper and "* PREAUTH" not in upper:
        return ProbeResult(service="imap", banner="imap: no greeting", raw=result_raw)

    caps: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        up = s.upper()
        # Two authoritative forms: the untagged "* CAPABILITY ..." response and
        # the greeting's "[CAPABILITY ...]" bracket. A tagged status line like
        # "a1 OK Capability completed" also contains the word — ignore it.
        if up.startswith("* CAPABILITY"):
            tail = s[len("* CAPABILITY"):]
        elif "[CAPABILITY" in up:
            start = up.index("[CAPABILITY") + len("[CAPABILITY")
            end = s.find("]", start)
            tail = s[start:end] if end != -1 else s[start:]
        else:
            continue
        caps.extend(t.upper() for t in tail.split() if t)
    caps = sorted(set(caps))
    starttls = "STARTTLS" in caps
    login_disabled = "LOGINDISABLED" in caps
    result_raw.update({"capabilities": caps, "starttls": starttls, "login_disabled": login_disabled})

    greeting = next((ln for ln in text.splitlines() if ln.startswith("* OK")), "IMAP")
    return ProbeResult(
        service="imap",
        banner=f"IMAP {greeting[4:].strip()[:120]}" + ("" if starttls else " (no STARTTLS)"),
        raw=result_raw,
    )
