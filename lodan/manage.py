"""Workspace management: safe, validated mutation of a workspace's config.

Both the CLI and the web UI call these helpers, so they are deliberately
framework-agnostic — the UI stays a thin adapter over this module. Every
mutation loads the current config, applies the change with pydantic
validation, and rewrites the whole `config.toml` atomically.

None of this bypasses the "scan what you own" contract: adding a CIDR here
only edits `authorized_ranges`. The cloud-prefix guard and the per-target
allowlist check still run at scan time (`authz.check_workspace` /
`authz.check_target`), so a range added through the UI is scanned only if it
also clears those guards. Cloud overlaps are surfaced as *warnings* at add
time so an operator sees them early, but the enforcement stays in authz.
"""
from __future__ import annotations

import os
import tempfile
import tomllib
from dataclasses import dataclass, field
from ipaddress import ip_network
from pathlib import Path

from lodan import authz, domains
from lodan.config import (
    Config,
    DiffBlock,
    EnrichBlock,
    RetentionBlock,
    ScanBlock,
    dump_config_toml,
)
from lodan.paths import workspace_config


class ManageError(ValueError):
    """A management operation was rejected (bad input, no such workspace, ...)."""


@dataclass
class AddResult:
    added: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)          # already present
    cloud_warnings: list[str] = field(default_factory=list)   # overlaps a cloud prefix


def load(workspace: str) -> Config:
    path = workspace_config(workspace)
    if not path.exists():
        raise ManageError(f"no such workspace: {workspace}")
    return Config.load(path)


def _save(workspace: str, cfg: Config) -> None:
    """Render the config and replace `config.toml` atomically.

    The rendered text is re-parsed and re-validated before it touches disk so a
    malformed edit can never leave the workspace with an unloadable config.
    """
    text = dump_config_toml(cfg)
    Config.model_validate(tomllib.loads(text))  # guard: must round-trip
    path = workspace_config(workspace)
    # A unique temp file per writer: sync route handlers run concurrently in
    # Starlette's threadpool, so a fixed temp name could let two simultaneous
    # saves interleave writes on one inode. os.replace is atomic, so the target
    # is always one writer's complete file, never a truncated blend.
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=path.name + ".", suffix=".tmp")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def normalize_target(raw: str) -> str:
    """Canonicalize an operator-supplied target into a stored CIDR string.

    Accepts a bare IPv4/IPv6 address (a bare host becomes a /32 or /128) or a
    CIDR of either family. Host bits in a CIDR are cleared (strict=False),
    matching how authz interprets the range.
    """
    raw = raw.strip()
    if not raw:
        raise ManageError("empty target")
    candidate = raw
    if "/" not in raw:
        # A bare address is a single host: /32 for IPv4, /128 for IPv6.
        candidate = f"{raw}/128" if ":" in raw else f"{raw}/32"
    try:
        net = ip_network(candidate, strict=False)
    except ValueError as e:
        raise ManageError(f"invalid IP/CIDR {raw!r}: {e}") from None
    return str(net)


def add_cidrs(workspace: str, raws: list[str]) -> AddResult:
    """Add one or more targets to `authorized_ranges`. Idempotent per target."""
    cfg = load(workspace)
    existing = list(cfg.workspace.authorized_ranges)
    result = AddResult()
    seen = set(existing)
    for raw in raws:
        cidr = normalize_target(raw)
        if cidr in seen:
            result.skipped.append(cidr)
            continue
        seen.add(cidr)
        existing.append(cidr)
        result.added.append(cidr)
        for hit in authz.cloud_overlaps(ip_network(cidr, strict=False)):
            result.cloud_warnings.append(
                f"{cidr} overlaps {hit.provider} prefix {hit.prefix}"
            )
    if result.added:
        cfg.workspace.authorized_ranges = existing
        _save(workspace, cfg)
    return result


def remove_cidr(workspace: str, raw: str) -> bool:
    """Remove a target from `authorized_ranges`. Returns whether it was present."""
    cfg = load(workspace)
    cidr = normalize_target(raw)
    ranges = cfg.workspace.authorized_ranges
    if cidr not in ranges:
        return False
    cfg.workspace.authorized_ranges = [c for c in ranges if c != cidr]
    _save(workspace, cfg)
    return True


def add_domains(workspace: str, raws: list[str]) -> AddResult:
    """Add domains to `authorized_domains`. Idempotent per domain.

    Note what this does NOT do: it never resolves anything or touches
    `authorized_ranges`. Domain scope is computed fresh at scan time and lives
    only for that run.
    """
    cfg = load(workspace)
    existing = list(cfg.workspace.authorized_domains)
    result = AddResult()
    seen = set(existing)
    for raw in raws:
        try:
            domain = domains.normalize_domain(raw)
        except domains.DomainError as e:
            raise ManageError(str(e)) from None
        if domain in seen:
            result.skipped.append(domain)
            continue
        seen.add(domain)
        existing.append(domain)
        result.added.append(domain)
    if result.added:
        cfg.workspace.authorized_domains = existing
        _save(workspace, cfg)
    return result


def remove_domain(workspace: str, raw: str) -> bool:
    """Remove a domain from `authorized_domains`. Returns whether it was there."""
    cfg = load(workspace)
    try:
        domain = domains.normalize_domain(raw)
    except domains.DomainError as e:
        raise ManageError(str(e)) from None
    current = cfg.workspace.authorized_domains
    if domain not in current:
        return False
    cfg.workspace.authorized_domains = [d for d in current if d != domain]
    _save(workspace, cfg)
    return True


def set_cloud_policy(workspace: str, allowed: bool, justification: str) -> None:
    """Set the cloud-provider opt-in flag + justification.

    Mirrors the authz rule: if the operator turns the flag on they must supply a
    non-empty justification (it is copied into each scan row for audit).
    """
    if allowed and not justification.strip():
        raise ManageError(
            "cloud_provider_allowed requires a non-empty justification"
        )
    cfg = load(workspace)
    cfg.workspace.cloud_provider_allowed = allowed
    cfg.workspace.cloud_provider_justification = justification.strip()
    _save(workspace, cfg)


_SCAN_FIELDS = set(ScanBlock.model_fields)
_ENRICH_FIELDS = set(EnrichBlock.model_fields)


def update_scan(workspace: str, updates: dict) -> None:
    """Merge validated updates into the [scan] block."""
    unknown = set(updates) - _SCAN_FIELDS
    if unknown:
        raise ManageError(f"unknown scan setting(s): {', '.join(sorted(unknown))}")
    cfg = load(workspace)
    merged = {**cfg.scan.model_dump(), **updates}
    try:
        cfg.scan = ScanBlock.model_validate(merged)
    except ValueError as e:
        raise ManageError(f"invalid scan setting: {e}") from None
    _save(workspace, cfg)


def update_enrich(workspace: str, updates: dict) -> None:
    """Merge validated updates into the [enrich] block."""
    unknown = set(updates) - _ENRICH_FIELDS
    if unknown:
        raise ManageError(f"unknown enrich setting(s): {', '.join(sorted(unknown))}")
    cfg = load(workspace)
    merged = {**cfg.enrich.model_dump(), **updates}
    try:
        cfg.enrich = EnrichBlock.model_validate(merged)
    except ValueError as e:
        raise ManageError(f"invalid enrich setting: {e}") from None
    _save(workspace, cfg)


def set_diff_default_from(workspace: str, token: str) -> None:
    """Set [diff].default_from (a scan token like 'prev' / 'latest' / an id)."""
    token = token.strip()
    if not token:
        raise ManageError("diff default_from cannot be empty")
    cfg = load(workspace)
    cfg.diff = DiffBlock(default_from=token)
    _save(workspace, cfg)


def set_retention(
    workspace: str, keep_last_n: int | None, keep_monthly: int | None
) -> None:
    """Set the [retention] policy. Pass None to clear a knob."""
    for label, val in (("keep_last_n", keep_last_n), ("keep_monthly", keep_monthly)):
        if val is not None and val < 1:
            raise ManageError(f"{label} must be >= 1 (or empty to disable)")
    cfg = load(workspace)
    cfg.retention = RetentionBlock(keep_last_n=keep_last_n, keep_monthly=keep_monthly)
    _save(workspace, cfg)
