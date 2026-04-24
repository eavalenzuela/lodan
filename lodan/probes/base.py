"""Probe-neutral types.

A probe takes an (ip, port) that discovery already confirmed is open, talks
to it for up to `timeout` seconds, and produces a ProbeResult. The scan loop
merges that result into the existing services row for the scan.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any, Protocol, runtime_checkable


@dataclass
class ProbeResult:
    service: str
    banner: str | None = None
    cert_fingerprint: str | None = None
    cert_sans: list[str] | None = None
    ja3: str | None = None
    ja3s: str | None = None
    favicon_mmh3: int | None = None
    tech: list[str] | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    def raw_json(self) -> str:
        return json.dumps(self.raw, default=str, sort_keys=True)

    def sans_json(self) -> str | None:
        return json.dumps(self.cert_sans) if self.cert_sans is not None else None

    def tech_json(self) -> str | None:
        return json.dumps(self.tech) if self.tech is not None else None

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@runtime_checkable
class Probe(Protocol):
    name: str
    default_ports: frozenset[int]

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult: ...
