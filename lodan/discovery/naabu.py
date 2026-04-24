"""naabu subprocess backend.

Invokes `naabu -list <tmp> -p <ports> -rate <N> -json -silent -o -` and
consumes the newline-delimited JSON from stdout. naabu is TCP-only; UDP
results in the spec are silently skipped (masscan or scapy should run
the UDP sweep instead).

Unlike masscan, naabu writes its JSON output with keys like:
    {"host":"10.0.0.5","ip":"10.0.0.5","port":80,"protocol":"tcp",...}

We read `ip` / `port` / `protocol` defensively: older naabu builds omit
protocol entirely (always TCP), and some builds emit `tcp` / `udp`.
"""
from __future__ import annotations

import asyncio
import json
import shutil
import tempfile
from collections.abc import AsyncIterator
from pathlib import Path

from lodan.discovery.base import DiscoveryResult, DiscoverySpec


class NaabuBackend:
    name = "naabu"

    def available(self) -> bool:
        return shutil.which("naabu") is not None

    async def run(self, spec: DiscoverySpec) -> AsyncIterator[DiscoveryResult]:
        if not spec.tcp:
            return

        with tempfile.NamedTemporaryFile(
            "w", suffix=".txt", delete=False, encoding="utf-8"
        ) as target_file:
            for net in spec.targets:
                target_file.write(str(net) + "\n")
            target_path = target_file.name

        try:
            argv = build_argv(spec, target_path)
            proc = await asyncio.create_subprocess_exec(
                *argv,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            assert proc.stdout is not None
            try:
                async for line in proc.stdout:
                    result = parse_json_line(line.decode("utf-8", "replace"))
                    if result is not None:
                        yield result
            finally:
                rc = await proc.wait()
                if rc not in (0, None):
                    stderr = b""
                    if proc.stderr is not None:
                        stderr = await proc.stderr.read()
                    raise RuntimeError(
                        f"naabu exited {rc}: {stderr.decode('utf-8', 'replace').strip()}"
                    )
        finally:
            Path(target_path).unlink(missing_ok=True)


def build_argv(spec: DiscoverySpec, target_path: str) -> list[str]:
    ports = ",".join(str(p) for p in spec.ports)
    return [
        "naabu",
        "-list", target_path,
        "-p", ports,
        "-rate", str(spec.rate_pps),
        "-json",
        "-silent",
        "-o", "-",
    ]


def parse_json_line(line: str) -> DiscoveryResult | None:
    line = line.strip()
    if not line:
        return None
    try:
        obj = json.loads(line)
    except ValueError:
        return None
    if not isinstance(obj, dict):
        return None
    ip = obj.get("ip") or obj.get("host")
    port = obj.get("port")
    proto = (obj.get("protocol") or "tcp").lower()
    if proto not in ("tcp", "udp"):
        return None
    if not isinstance(ip, str) or not isinstance(port, int):
        return None
    return DiscoveryResult(ip=ip, port=port, proto=proto)  # type: ignore[arg-type]
