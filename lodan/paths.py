"""Filesystem layout for lodan. Centralized so tests can monkey-patch."""
from __future__ import annotations

import os
from pathlib import Path


def lodan_home() -> Path:
    override = os.environ.get("LODAN_HOME")
    return Path(override) if override else Path.home() / ".lodan"


def data_dir() -> Path:
    return lodan_home() / "data"


def workspaces_dir() -> Path:
    return lodan_home() / "workspaces"


def workspace_dir(name: str) -> Path:
    return workspaces_dir() / name


def workspace_db(name: str) -> Path:
    return workspace_dir(name) / "lodan.db"


def workspace_config(name: str) -> Path:
    return workspace_dir(name) / "config.toml"


def nvd_dir() -> Path:
    return data_dir() / "nvd"


def nvd_db() -> Path:
    return nvd_dir() / "cve.db"


def nvd_state() -> Path:
    return nvd_dir() / "state.json"


def ip2location_dir() -> Path:
    return data_dir() / "ip2location"


def ip2location_asn_bin() -> Path:
    return ip2location_dir() / "IP2LOCATION-LITE-ASN.BIN"
