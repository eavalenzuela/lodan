"""In-webapp domain management and the DNS results page, plus the config
round-trip that management edits depend on.
"""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from lodan import manage
from lodan.cli import app as cli_app
from lodan.config import Config, dump_config_toml
from lodan.paths import workspace_config, workspace_db
from lodan.probes import dispatch as probe_dispatch


@pytest.fixture(autouse=True)
def _quiet(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probe_dispatch, "register_defaults", probe_dispatch.clear_registry)
    probe_dispatch.clear_registry()


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    runner = CliRunner()
    assert runner.invoke(cli_app, ["init", "w", "--cidrs", "10.0.0.0/24"]).exit_code == 0
    return "w"


def _client(workspace: str) -> TestClient:
    from lodan.ui.app import create_app
    return TestClient(create_app(workspace))


# --- config round-trip -------------------------------------------------------

def test_config_dump_preserves_every_field(workspace: str) -> None:
    """A management edit rewrites the whole config.toml, so any field the
    dumper forgets silently reverts to its default."""
    cfg = manage.load(workspace)
    cfg.workspace.authorized_domains = ["corp.example.com"]
    cfg.scan.tls_matrix = False
    cfg.scan.jarm = True
    cfg.scan.snmp = True
    cfg.enrich.device = False
    cfg.enrich.key_posture = False
    cfg.enrich.risk = False

    path = workspace_config(workspace)
    path.write_text(dump_config_toml(cfg))
    reloaded = Config.load(path)

    assert reloaded.workspace.authorized_domains == ["corp.example.com"]
    assert reloaded.scan.tls_matrix is False
    assert reloaded.scan.jarm is True
    assert reloaded.scan.snmp is True
    assert reloaded.enrich.device is False
    assert reloaded.enrich.key_posture is False
    assert reloaded.enrich.risk is False


def test_editing_scan_settings_does_not_drop_domains(workspace: str) -> None:
    manage.add_domains(workspace, ["corp.example.com"])
    manage.update_scan(workspace, {"rate_pps": 500})
    assert manage.load(workspace).workspace.authorized_domains == ["corp.example.com"]


# --- manage helpers ----------------------------------------------------------

def test_add_and_remove_domains(workspace: str) -> None:
    res = manage.add_domains(workspace, ["Corp.Example.COM", "example.net"])
    assert res.added == ["corp.example.com", "example.net"]
    assert manage.load(workspace).workspace.authorized_domains == [
        "corp.example.com", "example.net"
    ]
    assert manage.add_domains(workspace, ["corp.example.com"]).skipped == [
        "corp.example.com"
    ]
    assert manage.remove_domain(workspace, "CORP.example.com") is True
    assert manage.load(workspace).workspace.authorized_domains == ["example.net"]
    assert manage.remove_domain(workspace, "gone.example.net") is False


def test_add_domains_rejects_junk(workspace: str) -> None:
    with pytest.raises(manage.ManageError):
        manage.add_domains(workspace, ["https://example.com"])
    with pytest.raises(manage.ManageError):
        manage.add_domains(workspace, ["*.example.com"])


def test_adding_a_domain_never_touches_authorized_ranges(workspace: str) -> None:
    """Domain scope is computed at scan time and is run-scoped by design."""
    before = manage.load(workspace).workspace.authorized_ranges
    manage.add_domains(workspace, ["corp.example.com"])
    assert manage.load(workspace).workspace.authorized_ranges == before


# --- web UI ------------------------------------------------------------------

def test_manage_page_lists_domains(workspace: str) -> None:
    manage.add_domains(workspace, ["corp.example.com"])
    body = _client(workspace).get("/manage").text
    assert "corp.example.com" in body
    assert "Authorized domains" in body


def test_manage_add_domain_endpoint(workspace: str) -> None:
    client = _client(workspace)
    r = client.post("/manage/domains/add", data={"domains": "corp.example.com"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert manage.load(workspace).workspace.authorized_domains == ["corp.example.com"]


def test_manage_add_domain_rejects_junk(workspace: str) -> None:
    client = _client(workspace)
    r = client.post("/manage/domains/add", data={"domains": "*.example.com"},
                    follow_redirects=False)
    assert r.status_code == 303
    assert "level=err" in r.headers["location"]
    assert manage.load(workspace).workspace.authorized_domains == []


def test_manage_remove_domain_endpoint(workspace: str) -> None:
    manage.add_domains(workspace, ["corp.example.com"])
    client = _client(workspace)
    client.post("/manage/domains/remove", data={"domain": "corp.example.com"},
                follow_redirects=False)
    assert manage.load(workspace).workspace.authorized_domains == []


def test_read_only_instance_refuses_domain_edits(workspace: str) -> None:
    from lodan.ui.app import create_app

    client = TestClient(create_app(workspace, read_only=True))
    r = client.post("/manage/domains/add", data={"domains": "corp.example.com"})
    assert r.status_code in (403, 405)
    assert manage.load(workspace).workspace.authorized_domains == []


def test_domains_page_shows_resolution_and_refusals(workspace: str) -> None:
    conn = sqlite3.connect(workspace_db(workspace))
    conn.execute(
        "INSERT INTO scans (id, started_at, cidrs, workspace, status) VALUES "
        "(1, '2026-07-30T00:00:00', '[]', 'w', 'completed')"
    )
    conn.executemany(
        "INSERT INTO domain_resolutions (scan_id, domain, addresses, cnames, refused, error) "
        "VALUES (1, ?, ?, ?, ?, ?)",
        [
            ("corp.example.com", json.dumps(["10.0.0.5"]), "[]", "[]", None),
            (
                "cdn.example.net", "[]",
                json.dumps([{"from": "cdn.example.net", "to": "x.cloudfront.net"}]),
                json.dumps([{"target": "x.cloudfront.net",
                             "reason": "CNAME points outside the authorized domains"}]),
                None,
            ),
        ],
    )
    conn.commit()
    conn.close()
    manage.add_domains(workspace, ["corp.example.com", "cdn.example.net"])

    body = _client(workspace).get("/domains").text
    assert "10.0.0.5" in body
    assert "x.cloudfront.net" in body
    assert "CNAME points outside" in body


def test_domains_page_lists_subdomains_as_not_scanned(workspace: str) -> None:
    manage.add_domains(workspace, ["corp.example.com"])
    conn = sqlite3.connect(workspace_db(workspace))
    conn.execute(
        "INSERT INTO scans (id, started_at, cidrs, workspace, status) VALUES "
        "(1, '2026-07-30T00:00:00', '[]', 'w', 'completed')"
    )
    conn.execute(
        "INSERT INTO services (scan_id, ip, port, proto, cert_sans) "
        "VALUES (1, '10.0.0.5', 443, 'tcp', ?)",
        (json.dumps(["git.corp.example.com", "elsewhere.evil.test"]),),
    )
    conn.commit()
    conn.close()

    body = _client(workspace).get("/domains").text
    assert "git.corp.example.com" in body
    assert "not scanned" in body
    assert "elsewhere.evil.test" not in body


def test_domains_page_without_any_domains(workspace: str) -> None:
    r = _client(workspace).get("/domains")
    assert r.status_code == 200
    assert "No domains authorized" in r.text
