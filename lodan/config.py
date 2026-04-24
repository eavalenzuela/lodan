"""Workspace config model + default TOML serializer.

The config is the single source of truth for authorized ranges and scan
behavior. It is loaded with pydantic for validation; emitted as TOML so
operators can hand-edit without a lodan binary.
"""
from __future__ import annotations

import tomllib
from ipaddress import ip_network
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field, field_validator


class WorkspaceBlock(BaseModel):
    name: str
    authorized_ranges: list[str] = Field(default_factory=list)
    cloud_provider_allowed: bool = False
    cloud_provider_justification: str = ""

    @field_validator("authorized_ranges")
    @classmethod
    def _validate_cidrs(cls, v: list[str]) -> list[str]:
        for c in v:
            ip_network(c, strict=False)
        return v


class ScanBlock(BaseModel):
    backend: Literal["masscan", "naabu", "scapy"] = "masscan"
    rate_pps: int = 1000
    ports: str = "top-1000"
    tcp: bool = True
    udp: bool = True
    concurrency: int = 100
    per_host_concurrency: int = 4
    probe_timeout_s: float = 5.0
    retries: int = 1


class EnrichBlock(BaseModel):
    rdns: bool = True
    asn: bool = True
    geoip: bool = True
    cve: bool = True
    favicon: bool = True
    tech: bool = True
    keep_raw: bool = False


class DiffBlock(BaseModel):
    default_from: str = "prev"


class RetentionBlock(BaseModel):
    keep_last_n: int | None = None
    keep_monthly: int | None = None


class Config(BaseModel):
    workspace: WorkspaceBlock
    scan: ScanBlock = Field(default_factory=ScanBlock)
    enrich: EnrichBlock = Field(default_factory=EnrichBlock)
    diff: DiffBlock = Field(default_factory=DiffBlock)
    retention: RetentionBlock = Field(default_factory=RetentionBlock)

    @classmethod
    def load(cls, path: Path) -> "Config":
        with path.open("rb") as f:
            return cls.model_validate(tomllib.load(f))


def default_config_toml(name: str, cidrs: list[str]) -> str:
    cidrs_fmt = ", ".join(f'"{c}"' for c in cidrs)
    return f"""\
[workspace]
name = "{name}"
authorized_ranges = [{cidrs_fmt}]
cloud_provider_allowed = false
cloud_provider_justification = ""

[scan]
backend = "masscan"
rate_pps = 1000
ports = "top-1000"
tcp = true
udp = true
concurrency = 100
per_host_concurrency = 4
probe_timeout_s = 5
retries = 1

[enrich]
rdns = true
asn = true
geoip = true
cve = true
favicon = true
tech = true
keep_raw = false

[diff]
default_from = "prev"

# [retention]
# keep_last_n = 24
# keep_monthly = 12
"""
