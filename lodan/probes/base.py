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
    ja4: str | None = None
    ja4s: str | None = None
    ssh_hostkey: str | None = None
    favicon_mmh3: int | None = None
    tech: list[str] | None = None
    jarm: str | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    #: DER bytes of every cert in the server's chain, leaf first. Kept off
    #: `raw` because that is JSON-serialized at the storage boundary and this
    #: is binary; the writer persists it to `chain_certs` so offline key
    #: analysis can run over the real key material without reconnecting.
    chain_der: list[bytes] | None = None

    def raw_json(self) -> str:
        return json.dumps(self.raw, default=str, sort_keys=True)

    # cert_sans / tech are serialized (and canonicalized) at the storage
    # boundary by lodan.normalize; ProbeResult deliberately keeps the raw
    # values so nothing writes an un-normalized list by accident.

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@runtime_checkable
class Probe(Protocol):
    name: str
    default_ports: frozenset[int]

    async def probe(self, ip: str, port: int, timeout: float) -> ProbeResult: ...
