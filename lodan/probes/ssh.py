"""SSH probe.

Two phases, kept independent so either can be tested in isolation:

1. Banner: open a TCP connection, read up to 255 bytes or until CRLF, parse
   the "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5" line into {version,
   software, comment}. Works even on boxes where asyncssh refuses the full
   handshake (broken kex, old stacks).

2. Host keys: asyncssh's get_server_host_key() returns whatever host key
   algorithm the server offers by default. We record the (algo,
   sha256 fingerprint) pair, which is the pivot key for the "all hosts
   with this SSH host key" query in the PLAN.

Never authenticates, never sends a password.
"""
from __future__ import annotations

import asyncio
import contextlib
import hashlib
import re
from dataclasses import dataclass
from typing import Any

from lodan.probes.base import ProbeResult

_DEFAULT_SSH_PORTS = frozenset({22, 2022, 2222})
_BANNER_RE = re.compile(
    r"^SSH-(?P<version>\d+\.\d+)-(?P<software>\S+)(?:\s+(?P<comment>.*))?$"
)


@dataclass(frozen=True)
class SSHBanner:
    version: str
    software: str
    comment: str | None
    raw: str


class SSHProbe:
    name = "ssh"
    default_ports = _DEFAULT_SSH_PORTS

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult:
        banner = await asyncio.wait_for(fetch_banner(ip, port), timeout=timeout)
        host_keys = await _safe_host_keys(ip, port, timeout)
        return parse(banner, host_keys)


async def fetch_banner(ip: str, port: int) -> str:
    reader, writer = await asyncio.open_connection(ip, port)
    try:
        # SSH servers send their banner immediately. Read until LF or 255 bytes.
        buf = b""
        while b"\n" not in buf and len(buf) < 256:
            chunk = await reader.read(256 - len(buf))
            if not chunk:
                break
            buf += chunk
        return buf.split(b"\n", 1)[0].decode("ascii", "replace").rstrip("\r")
    finally:
        writer.close()
        with contextlib.suppress(Exception):
            await writer.wait_closed()


async def _safe_host_keys(ip: str, port: int, timeout: float) -> list[tuple[str, str]]:
    """Best-effort host key collection. Returns [] if asyncssh can't reach
    or the server refuses the scan — banner alone is still a useful result."""
    try:
        import asyncssh  # type: ignore
    except ImportError:
        return []
    try:
        keys = await asyncio.wait_for(
            asyncssh.get_server_host_key(ip, port=port), timeout=timeout
        )
    except Exception:
        return []
    return _fingerprint_keys(keys)


def _fingerprint_keys(keys: Any) -> list[tuple[str, str]]:
    """Turn asyncssh SSHKey objects (or an iterable of them) into
    [(algo, sha256_fp)] pairs. Accepts None / single / iterable for
    forward-compatibility with asyncssh API changes."""
    if keys is None:
        return []
    if hasattr(keys, "algorithm"):  # single key
        keys = [keys]
    out: list[tuple[str, str]] = []
    for k in keys:
        algo = getattr(k, "algorithm", "unknown")
        if isinstance(algo, bytes):
            algo = algo.decode("ascii", "replace")
        try:
            der = k.export_public_key("openssh").split()[1]
            raw_bytes = _b64decode(der)
        except Exception:
            continue
        fp = hashlib.sha256(raw_bytes).hexdigest()
        out.append((algo, fp))
    return out


def _b64decode(value: bytes | str) -> bytes:
    import base64

    if isinstance(value, str):
        value = value.encode("ascii")
    return base64.b64decode(value + b"=" * (-len(value) % 4))


def parse(banner_line: str, host_keys: list[tuple[str, str]] | None = None) -> ProbeResult:
    host_keys = host_keys or []
    parsed = parse_banner(banner_line)
    banner_parts: list[str] = [banner_line.strip() or "(no banner)"]
    if host_keys:
        banner_parts.append(f"{len(host_keys)} host key(s)")
    raw: dict[str, Any] = {
        "banner": banner_line,
        "parsed": parsed.__dict__ if parsed else None,
        "host_keys": [{"algo": a, "sha256": fp} for a, fp in host_keys],
    }
    return ProbeResult(
        service="ssh",
        banner=" | ".join(banner_parts),
        raw=raw,
    )


def parse_banner(line: str) -> SSHBanner | None:
    m = _BANNER_RE.match(line.strip())
    if not m:
        return None
    return SSHBanner(
        version=m.group("version"),
        software=m.group("software"),
        comment=m.group("comment"),
        raw=line,
    )
