from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from lodan import manage
from lodan.cli import app as cli_app
from lodan.cloud_prefixes import all_prefixes
from lodan.config import Config
from lodan.paths import workspace_config


@pytest.fixture
def ws(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    r = CliRunner().invoke(cli_app, ["init", "w", "--cidrs", "10.0.0.0/24"])
    assert r.exit_code == 0, r.output
    return "w"


def _cfg(ws: str) -> Config:
    return Config.load(workspace_config(ws))


def test_add_bare_ip_becomes_slash32(ws: str) -> None:
    res = manage.add_cidrs(ws, ["192.168.1.5"])
    assert res.added == ["192.168.1.5/32"]
    assert "192.168.1.5/32" in _cfg(ws).workspace.authorized_ranges


def test_add_canonicalizes_host_bits(ws: str) -> None:
    res = manage.add_cidrs(ws, ["172.16.5.9/16"])
    assert res.added == ["172.16.0.0/16"]


def test_add_dedups_existing(ws: str) -> None:
    res = manage.add_cidrs(ws, ["10.0.0.0/24"])
    assert res.added == []
    assert res.skipped == ["10.0.0.0/24"]


def test_add_cloud_overlap_warns_but_still_adds(ws: str) -> None:
    _, net = next(iter(all_prefixes()))
    res = manage.add_cidrs(ws, [str(net)])
    assert res.added == [str(net)]
    assert res.cloud_warnings  # surfaced, not blocked
    assert str(net) in _cfg(ws).workspace.authorized_ranges


def test_normalize_accepts_ipv6() -> None:
    assert manage.normalize_target("::1") == "::1/128"
    assert manage.normalize_target("2001:db8::/32") == "2001:db8::/32"
    # Bare IPv6 host becomes a /128; canonicalized (compressed, lower-case).
    assert manage.normalize_target("2001:DB8:0:0:0:0:0:1") == "2001:db8::1/128"


def test_normalize_rejects_junk(ws: str) -> None:
    for bad in ["nope", "", "  ", "999.1.1.1"]:
        with pytest.raises(manage.ManageError):
            manage.normalize_target(bad)


def test_remove_reports_presence(ws: str) -> None:
    assert manage.remove_cidr(ws, "10.0.0.0/24") is True
    assert manage.remove_cidr(ws, "10.0.0.0/24") is False


def test_cloud_policy_requires_justification(ws: str) -> None:
    with pytest.raises(manage.ManageError):
        manage.set_cloud_policy(ws, True, "   ")
    manage.set_cloud_policy(ws, True, "authorized lab")
    c = _cfg(ws)
    assert c.workspace.cloud_provider_allowed is True
    assert c.workspace.cloud_provider_justification == "authorized lab"


def test_update_scan_coerces_and_rejects_unknown(ws: str) -> None:
    manage.update_scan(ws, {"rate_pps": "250", "tcp": False, "ports": "1-1024"})
    c = _cfg(ws)
    assert c.scan.rate_pps == 250
    assert c.scan.tcp is False
    assert c.scan.ports == "1-1024"
    with pytest.raises(manage.ManageError):
        manage.update_scan(ws, {"bogus": "x"})


def test_update_enrich(ws: str) -> None:
    manage.update_enrich(ws, {"cve": False})
    assert _cfg(ws).enrich.cve is False
    with pytest.raises(manage.ManageError):
        manage.update_enrich(ws, {"nope": True})


def test_set_retention_validates(ws: str) -> None:
    with pytest.raises(manage.ManageError):
        manage.set_retention(ws, 0, None)
    manage.set_retention(ws, 5, None)
    c = _cfg(ws)
    assert c.retention.keep_last_n == 5
    assert c.retention.keep_monthly is None


def test_set_diff_default_from(ws: str) -> None:
    manage.set_diff_default_from(ws, "latest")
    assert _cfg(ws).diff.default_from == "latest"
    with pytest.raises(manage.ManageError):
        manage.set_diff_default_from(ws, "   ")


def test_no_such_workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    with pytest.raises(manage.ManageError):
        manage.load("ghost")


def test_save_leaves_no_tmp_file(ws: str) -> None:
    manage.add_cidrs(ws, ["192.168.9.0/24"])
    wdir = workspace_config(ws).parent
    assert not list(wdir.glob("*.tmp"))
