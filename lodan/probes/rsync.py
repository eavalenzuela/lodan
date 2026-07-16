"""rsync daemon probe: protocol greeting + anonymous module listing.

Reads the `@RSYNCD: <version>` greeting, echoes it, and requests the module
listing (an empty module name — the standard, anonymous, credential-free way to
enumerate published modules). No files are transferred and no module is entered.
An exposed rsync daemon with readable modules is a common data-exposure finding.
"""
from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from lodan.probes._readers import read_until
from lodan.probes.base import ProbeResult

_DEFAULT_RSYNC_PORTS = frozenset({873})


class RsyncProbe:
    name = "rsync"
    default_ports = _DEFAULT_RSYNC_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        raw = await asyncio.wait_for(fetch(ip, port), timeout=timeout)
        return parse_rsync(raw)


async def fetch(ip: str, port: int) -> bytes:
    reader, writer = await asyncio.open_connection(ip, port)
    try:
        greeting = await read_until(reader, until=(b"\n",), cap=256)
        first_line = greeting.split(b"\n", 1)[0]
        # Echo the server's version line, then an empty module name = "list".
        writer.write(first_line + b"\n\n")
        await writer.drain()
        rest = await read_until(reader, until=(b"@RSYNCD: EXIT",), cap=8192)
        return greeting + rest
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


def parse_rsync(raw: bytes) -> ProbeResult:
    text = raw.decode("utf-8", "replace")
    lines = [ln.rstrip("\r") for ln in text.split("\n")]
    result_raw: dict[str, Any] = {"length": len(raw)}

    greeting = next((ln for ln in lines if ln.startswith("@RSYNCD:")), None)
    if greeting is None:
        return ProbeResult(service="rsync", banner="rsync: no greeting", raw=result_raw)

    version = greeting.replace("@RSYNCD:", "").strip()
    modules: list[str] = []
    for ln in lines:
        if not ln or ln.startswith("@RSYNCD") or ln.startswith("@ERROR"):
            continue
        modules.append(ln.split("\t")[0].strip().split()[0])
    result_raw.update({"version": version, "modules": modules})

    banner = f"rsync {version}"
    if modules:
        banner += " modules=" + ",".join(modules[:8])
    return ProbeResult(service="rsync", banner=banner[:300], raw=result_raw)
