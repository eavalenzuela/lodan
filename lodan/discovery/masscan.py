"""masscan subprocess backend.

Uses masscan's list output format (`-oL -`) because it is line-oriented and
stable across versions. Each line looks like:

    open tcp 80 10.0.0.5 1734460000
    open udp 53 10.0.0.5 1734460000

Anything else (comments, banner lines from `--banners`, errors on stderr) is
ignored here — banner grabbing is a probe phase concern.

Rate limiting is handed off to masscan via `--rate`.
"""
from __future__ import annotations

import asyncio
import shutil
from collections.abc import AsyncIterator

from lodan.discovery.base import DiscoveryResult, DiscoverySpec


class MasscanBackend:
    name = "masscan"

    def available(self) -> bool:
        return shutil.which("masscan") is not None

    async def run(self, spec: DiscoverySpec) -> AsyncIterator[DiscoveryResult]:
        if not (spec.tcp or spec.udp):
            return
        argv = build_argv(spec)
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        assert proc.stdout is not None
        try:
            async for line in proc.stdout:
                result = parse_list_line(line.decode("utf-8", "replace"))
                if result is not None:
                    yield result
        finally:
            rc = await proc.wait()
            if rc not in (0, None):
                stderr = b""
                if proc.stderr is not None:
                    stderr = await proc.stderr.read()
                raise RuntimeError(
                    f"masscan exited {rc}: {stderr.decode('utf-8', 'replace').strip()}"
                )


def build_argv(spec: DiscoverySpec) -> list[str]:
    port_groups: list[str] = []
    if spec.tcp:
        port_groups.append("T:" + ",".join(str(p) for p in spec.ports))
    if spec.udp:
        port_groups.append("U:" + ",".join(str(p) for p in spec.ports))
    argv = [
        "masscan",
        "-p", ",".join(port_groups),
        "--rate", str(spec.rate_pps),
        "-oL", "-",
    ]
    argv.extend(str(t) for t in spec.targets)
    return argv


def parse_list_line(line: str) -> DiscoveryResult | None:
    """Parse one line of masscan's `-oL` output. Ignore anything non-'open'."""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    parts = line.split()
    # "open <proto> <port> <ip> <timestamp>"
    if len(parts) < 5 or parts[0] != "open":
        return None
    proto = parts[1]
    if proto not in ("tcp", "udp"):
        return None
    try:
        port = int(parts[2])
    except ValueError:
        return None
    ip = parts[3]
    return DiscoveryResult(ip=ip, port=port, proto=proto)  # type: ignore[arg-type]
