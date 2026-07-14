from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from lodan.cli import app as cli_app
from lodan.config import Config
from lodan.paths import workspace_config
from lodan.ui.app import create_app
from lodan.ui.jobs import JobManager


class _Summary:
    scan_id = 1
    services_discovered = 3
    services_probed = 2
    hosts_enriched = 1
    vulns_matched = 0
    authz_rejections = 0
    diff_from = None
    diff_total = 0


@pytest.fixture
def ws(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    r = CliRunner().invoke(cli_app, ["init", "w", "--cidrs", "10.0.0.0/24"])
    assert r.exit_code == 0, r.output
    return "w"


def _client(ws: str, read_only: bool = False) -> tuple[TestClient, JobManager]:
    jm = JobManager(runner=lambda w: _Summary())
    return TestClient(create_app(ws, read_only=read_only, job_manager=jm)), jm


def _cfg(ws: str) -> Config:
    return Config.load(workspace_config(ws))


def test_manage_page_lists_scope_and_control(ws: str) -> None:
    c, _ = _client(ws)
    body = c.get("/manage").text
    assert "10.0.0.0/24" in body
    assert "Run a scan" in body
    assert "add to scope" in body


def test_scope_add_and_remove(ws: str) -> None:
    c, _ = _client(ws)
    r = c.post(
        "/manage/scope/add",
        data={"targets": "192.168.1.5, 172.16.0.0/16"},
        follow_redirects=False,
    )
    assert r.status_code == 303
    ranges = _cfg(ws).workspace.authorized_ranges
    assert "192.168.1.5/32" in ranges
    assert "172.16.0.0/16" in ranges

    c.post("/manage/scope/remove", data={"cidr": "10.0.0.0/24"}, follow_redirects=False)
    assert "10.0.0.0/24" not in _cfg(ws).workspace.authorized_ranges


def test_scope_add_bad_input_shows_error_notice(ws: str) -> None:
    c, _ = _client(ws)
    r = c.post("/manage/scope/add", data={"targets": "not-an-ip"}, follow_redirects=True)
    assert "invalid IP/CIDR" in r.text
    assert "not-an-ip" not in "".join(_cfg(ws).workspace.authorized_ranges)


def test_cloud_policy(ws: str) -> None:
    c, _ = _client(ws)
    c.post(
        "/manage/cloud",
        data={"allowed": "true", "justification": "authorized lab"},
        follow_redirects=False,
    )
    cfg = _cfg(ws)
    assert cfg.workspace.cloud_provider_allowed is True
    assert cfg.workspace.cloud_provider_justification == "authorized lab"


def test_scan_settings_saved(ws: str) -> None:
    c, _ = _client(ws)
    r = c.post(
        "/manage/scan",
        data={
            "backend": "scapy", "ports": "top-1000", "rate_pps": "500",
            "concurrency": "50", "per_host_concurrency": "2",
            "probe_timeout_s": "3", "retries": "0", "tcp": "true",
        },
        follow_redirects=False,
    )
    assert r.status_code == 303
    cfg = _cfg(ws)
    assert cfg.scan.backend == "scapy"
    assert cfg.scan.ports == "top-1000"
    assert cfg.scan.tcp is True
    assert cfg.scan.udp is False  # unchecked checkbox omitted -> False


def test_enrich_toggle(ws: str) -> None:
    c, _ = _client(ws)
    c.post("/manage/enrich", data={"rdns": "true"}, follow_redirects=False)
    cfg = _cfg(ws)
    assert cfg.enrich.rdns is True
    assert cfg.enrich.cve is False  # unchecked -> off


def test_retention_saved(ws: str) -> None:
    c, _ = _client(ws)
    c.post(
        "/manage/retention",
        data={"keep_last_n": "7", "keep_monthly": ""},
        follow_redirects=False,
    )
    cfg = _cfg(ws)
    assert cfg.retention.keep_last_n == 7
    assert cfg.retention.keep_monthly is None


def test_scan_run_and_status(ws: str) -> None:
    c, jm = _client(ws)
    assert c.post("/scan/run").status_code == 200
    jm.current(ws).wait(3)
    body = c.get("/scan/status").text
    assert "complete" in body
    assert "#1" in body


def test_favicon_label_set(ws: str) -> None:
    c, _ = _client(ws)
    r = c.post(
        "/favicon-label", data={"mmh3": "-99", "label": "Jenkins"}, follow_redirects=False
    )
    assert r.status_code == 303
    assert r.headers["location"] == "/pivot/favicon/-99"
    assert "Jenkins" in c.get("/pivot/favicon/-99").text


def test_read_only_blocks_writes_and_hides_forms(ws: str) -> None:
    c, _ = _client(ws, read_only=True)
    assert c.post("/manage/scope/add", data={"targets": "1.2.3.4"}).status_code == 403
    assert c.post("/scan/run").status_code == 403
    assert c.post("/favicon-label", data={"mmh3": "1", "label": "x"}).status_code == 403
    body = c.get("/manage").text
    assert "read-only" in body
    assert "add to scope" not in body
    assert "scanning is disabled" in c.get("/").text


def test_cross_origin_write_refused(ws: str) -> None:
    c, _ = _client(ws)
    r = c.post(
        "/manage/scope/add",
        data={"targets": "1.2.3.4"},
        headers={"origin": "http://evil.example", "host": "testserver"},
    )
    assert r.status_code == 403


def test_same_origin_write_allowed(ws: str) -> None:
    c, _ = _client(ws)
    r = c.post(
        "/manage/scope/add",
        data={"targets": "1.2.3.4"},
        headers={"origin": "http://testserver", "host": "testserver"},
        follow_redirects=False,
    )
    assert r.status_code == 303


def test_host_allowlist_blocks_untrusted_host(ws: str) -> None:
    # anti-DNS-rebinding: with a loopback allowlist, a rebound attacker Host is
    # refused even though Origin==Host (the classic same-origin bypass).
    jm = JobManager(runner=lambda w: _Summary())
    app = create_app(ws, allowed_hosts={"127.0.0.1", "localhost", "::1"}, job_manager=jm)
    c = TestClient(app)
    blocked = c.post(
        "/manage/scope/add",
        data={"targets": "1.2.3.4"},
        headers={"host": "attacker.com", "origin": "http://attacker.com"},
    )
    assert blocked.status_code == 403
    allowed = c.post(
        "/manage/scope/add",
        data={"targets": "1.2.3.4"},
        headers={"host": "127.0.0.1:8765"},
        follow_redirects=False,
    )
    assert allowed.status_code == 303
