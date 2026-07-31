"""Workspace config model + default TOML serializer.

The config is the single source of truth for authorized ranges and scan
behavior. It is loaded with pydantic for validation; emitted as TOML so
operators can hand-edit without a lodan binary.
"""
from __future__ import annotations

import json
import tomllib
from ipaddress import ip_network
from pathlib import Path

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
    # Backend membership is validated at scan time against the registry, not
    # at config load, so adding a backend does not require touching the model.
    backend: str = "auto"
    rate_pps: int = 1000
    ports: str = "top-100"
    tcp: bool = True
    udp: bool = True
    concurrency: int = 100
    per_host_concurrency: int = 4
    probe_timeout_s: float = 5.0
    retries: int = 1
    # TLS posture passes. The acceptance matrix costs six extra ClientHellos
    # per TLS port and answers the questions the pinned-1.2 probe structurally
    # cannot ("is TLS 1.0 still on?"). JARM costs ten and is off by default —
    # it is a clustering fingerprint, not a posture verdict, so it shouldn't
    # multiply anyone's traffic unless they asked for it.
    tls_matrix: bool = True
    jarm: bool = False
    # SNMPv2c has no bannerable handshake, so checking whether SNMP is exposed
    # necessarily carries a community string. lodan sends only the RFC-default
    # `public`, once, and treats a response as the exposure finding itself —
    # but because that is a default access token rather than a bannergrab, it
    # is off unless the operator turns it on.
    snmp: bool = False


class EnrichBlock(BaseModel):
    rdns: bool = True
    asn: bool = True
    geoip: bool = True
    cve: bool = True
    favicon: bool = True
    tech: bool = True
    device: bool = True
    # Offline scoring of captured public keys (TLS chain + SSH host keys),
    # including the ROCA fingerprint. Pure arithmetic; no traffic.
    key_posture: bool = True
    # EPSS / KEV / EOL joins. Needs `lodan update --risk`; noop without it.
    risk: bool = True
    keep_raw: bool = False


class DiffBlock(BaseModel):
    default_from: str = "prev"


class NotifyBlock(BaseModel):
    """Opt-in change notifications. A sink is enabled by being non-empty; both
    are off by default, so a fresh workspace never phones home."""

    webhook_url: str = ""            # POST the diff summary as JSON; "" disables
    email_to: str = ""               # comma-separated recipients; "" disables
    email_from: str = "lodan@localhost"
    smtp_host: str = "localhost"
    smtp_port: int = 25
    smtp_starttls: bool = False
    timeout_s: float = 10.0

    @property
    def webhook_enabled(self) -> bool:
        return bool(self.webhook_url.strip())

    @property
    def email_enabled(self) -> bool:
        return bool(self.email_to.strip())

    @property
    def enabled(self) -> bool:
        return self.webhook_enabled or self.email_enabled


class RetentionBlock(BaseModel):
    keep_last_n: int | None = None
    keep_monthly: int | None = None


class Config(BaseModel):
    workspace: WorkspaceBlock
    scan: ScanBlock = Field(default_factory=ScanBlock)
    enrich: EnrichBlock = Field(default_factory=EnrichBlock)
    diff: DiffBlock = Field(default_factory=DiffBlock)
    notify: NotifyBlock = Field(default_factory=NotifyBlock)
    retention: RetentionBlock = Field(default_factory=RetentionBlock)

    @classmethod
    def load(cls, path: Path) -> Config:
        with path.open("rb") as f:
            return cls.model_validate(tomllib.load(f))

    def dump(self) -> str:
        """Render this config back to canonical TOML.

        Used by the management layer to persist edits (add a CIDR, flip an
        enrich toggle, ...) without a round-trip TOML library. Any hand-written
        operator comments are not preserved; the layout and inline hints below
        are regenerated deterministically so the file always re-parses.
        """
        return dump_config_toml(self)


def _toml_str(s: str) -> str:
    # A JSON string literal is a valid TOML basic string: quotes, backslashes,
    # and control chars (<0x20) escape identically. We keep non-ASCII literal
    # (ensure_ascii=False) because TOML basic strings hold raw UTF-8 and json's
    # default \uXXXX escaping emits surrogate pairs for astral chars (emoji,
    # CJK-ExtB) that tomllib rejects as non-scalar. Dependency-free.
    return json.dumps(s, ensure_ascii=False)


def _toml_bool(b: bool) -> str:
    return "true" if b else "false"


def _toml_num(n: float | int) -> str:
    # Emit whole floats as integers (probe_timeout_s = 5, not 5.0) for a cleaner
    # file; either form parses back to the same pydantic value.
    if isinstance(n, float) and n.is_integer():
        return str(int(n))
    return str(n)


def _notify_lines(n: NotifyBlock) -> list[str]:
    """Render the [notify] block. Commented out (a discoverable example) while
    both sinks are disabled, so the default config never phones home; a real
    table once webhook_url or email_to is set."""
    if not n.enabled:
        return [
            "# [notify]  — fire a diff summary on a rescan that finds changes",
            '# webhook_url = "https://hooks.example.com/lodan"   # POSTs JSON',
            '# email_to = "team@example.com"                     # comma-separated',
            '# email_from = "lodan@localhost"',
            '# smtp_host = "localhost"',
            "# smtp_port = 25",
            "# smtp_starttls = false            # SMTP creds via $LODAN_SMTP_USERNAME/_PASSWORD",
            "# timeout_s = 10",
            "",
        ]
    return [
        "[notify]",
        f"webhook_url = {_toml_str(n.webhook_url)}",
        f"email_to = {_toml_str(n.email_to)}",
        f"email_from = {_toml_str(n.email_from)}",
        f"smtp_host = {_toml_str(n.smtp_host)}",
        f"smtp_port = {_toml_num(n.smtp_port)}",
        f"smtp_starttls = {_toml_bool(n.smtp_starttls)}",
        f"timeout_s = {_toml_num(n.timeout_s)}",
        "",
    ]


def dump_config_toml(cfg: Config) -> str:
    ws = cfg.workspace
    scan = cfg.scan
    enrich = cfg.enrich
    ranges_fmt = ", ".join(_toml_str(c) for c in ws.authorized_ranges)

    lines = [
        "[workspace]",
        f"name = {_toml_str(ws.name)}",
        f"authorized_ranges = [{ranges_fmt}]",
        f"cloud_provider_allowed = {_toml_bool(ws.cloud_provider_allowed)}",
        f"cloud_provider_justification = {_toml_str(ws.cloud_provider_justification)}",
        "",
        "[scan]",
        f'backend = {_toml_str(scan.backend)}'
        '                      # "auto" | "masscan" | "naabu" | "scapy"',
        f"rate_pps = {_toml_num(scan.rate_pps)}",
        f"ports = {_toml_str(scan.ports)}",
        f"tcp = {_toml_bool(scan.tcp)}",
        f"udp = {_toml_bool(scan.udp)}",
        f"concurrency = {_toml_num(scan.concurrency)}",
        f"per_host_concurrency = {_toml_num(scan.per_host_concurrency)}",
        f"probe_timeout_s = {_toml_num(scan.probe_timeout_s)}",
        f"retries = {_toml_num(scan.retries)}",
        "",
        "[enrich]",
        f"rdns = {_toml_bool(enrich.rdns)}",
        f"asn = {_toml_bool(enrich.asn)}",
        f"geoip = {_toml_bool(enrich.geoip)}",
        f"cve = {_toml_bool(enrich.cve)}",
        f"favicon = {_toml_bool(enrich.favicon)}",
        f"tech = {_toml_bool(enrich.tech)}",
        f"keep_raw = {_toml_bool(enrich.keep_raw)}",
        "",
        "[diff]",
        f"default_from = {_toml_str(cfg.diff.default_from)}",
        "",
    ]

    lines += _notify_lines(cfg.notify)

    ret = cfg.retention
    if ret.keep_last_n is None and ret.keep_monthly is None:
        lines += ["# [retention]", "# keep_last_n = 24", "# keep_monthly = 12"]
    else:
        lines.append("[retention]")
        if ret.keep_last_n is not None:
            lines.append(f"keep_last_n = {ret.keep_last_n}")
        if ret.keep_monthly is not None:
            lines.append(f"keep_monthly = {ret.keep_monthly}")

    return "\n".join(lines) + "\n"


def default_config_toml(name: str, cidrs: list[str]) -> str:
    cfg = Config(workspace=WorkspaceBlock(name=name, authorized_ranges=list(cidrs)))
    return dump_config_toml(cfg)
