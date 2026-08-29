"""JSON read API (/api/v1): host, domain, scans."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from lodan.cli import app as cli_app
from lodan.discovery.base import DiscoveryResult
from lodan.discovery.fake import FakeBackend
from lodan.paths import workspace_db, workspace_dir
from lodan.probes import dispatch as probe_dispatch
from lodan.scan import run_scan_sync
from lodan.ui.app import create_app


@pytest.fixture(autouse=True)
def _quiet_scan(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(probe_dispatch, "register_defaults", probe_dispatch.clear_registry)
    probe_dispatch.clear_registry()

    async def _noop(*args, **kwargs):
        return 0

    monkeypatch.setattr("lodan.scan.enrich_hosts", _noop)


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    runner = CliRunner()
    result = runner.invoke(cli_app, ["init", "w", "--cidrs", "10.0.0.0/24"])
    assert result.exit_code == 0
    cfg = workspace_dir("w") / "config.toml"
    cfg.write_text(cfg.read_text().replace('backend = "auto"', 'backend = "fake"'))
    return "w"


def _register_fake(results: list[DiscoveryResult]) -> None:
    from lodan.discovery import dispatch

    class _F(FakeBackend):
        def __init__(self) -> None:
            super().__init__(results)

    dispatch.register("fake", _F)


def _populate(workspace: str) -> int:
    """One scan: two hosts, four services, plus the derived rows a probe run
    would have written."""
    _register_fake([
        DiscoveryResult("10.0.0.5", 22, "tcp"),
        DiscoveryResult("10.0.0.5", 443, "tcp"),
        DiscoveryResult("10.0.0.9", 80, "tcp"),
        DiscoveryResult("10.0.0.9", 443, "tcp"),
    ])
    summary = run_scan_sync(workspace)
    scan_id = summary.scan_id

    conn = sqlite3.connect(workspace_db(workspace))
    conn.execute(
        "UPDATE services SET banner=?, service=?, tech=?, clock_key=? "
        "WHERE scan_id=? AND ip=? AND port=?",
        ("SSH-2.0-OpenSSH_9.3", "ssh", '["openssh"]', "boot-1234", scan_id, "10.0.0.5", 22),
    )
    conn.execute(
        "UPDATE services SET service=?, cert_sans=?, clock_key=? "
        "WHERE scan_id=? AND ip=? AND port=?",
        ("https", '["a.example.com"]', "boot-1234", scan_id, "10.0.0.5", 443),
    )
    # A second address sharing the clock key: same physical machine.
    conn.execute(
        "UPDATE services SET clock_key=? WHERE scan_id=? AND ip=? AND port=?",
        ("boot-1234", scan_id, "10.0.0.9", 80),
    )
    conn.execute(
        "INSERT INTO hosts (scan_id, ip, rdns, asn, asn_org, country, os_family, "
        "device_type, nat_suspected, min_backend_count) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (scan_id, "10.0.0.5", "box.example.com", 64500, "Example Networks", "US",
         "linux", "server", 1, 2),
    )
    conn.execute(
        "INSERT INTO vulns (scan_id, ip, port, cve, cpe, confidence, source, "
        "epss, kev, priority) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (scan_id, "10.0.0.5", 22, "CVE-2023-38408", "cpe:2.3:a:openbsd:openssh",
         0.9, "nvd", 0.42, 1, "critical"),
    )
    conn.execute(
        "INSERT INTO chain_certs (scan_id, ip, port, position, sha256, subject, "
        "issuer, key_bits, not_after, is_ca, self_signed, der) "
        "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
        (scan_id, "10.0.0.5", 443, 0, "ab" * 32, "CN=a.example.com", "CN=Example CA",
         2048, "2027-01-01T00:00:00Z", 0, 0, b"\x30\x82"),
    )
    conn.execute(
        "INSERT INTO findings (scan_id, ip, port, category, severity, title, detail) "
        "VALUES (?,?,?,?,?,?,?)",
        (scan_id, "10.0.0.5", 22, "cleartext-admin", "high", "Telnet open",
         json.dumps({"why": "test"})),
    )
    conn.commit()
    conn.close()
    return scan_id


@pytest.fixture
def client(workspace: str) -> TestClient:
    _populate(workspace)
    return TestClient(create_app(workspace))


def test_host_returns_the_full_picture(client: TestClient) -> None:
    body = client.get("/api/v1/host/10.0.0.5?include=all").json()
    assert body["found"] is True
    assert body["authorized"] is True
    assert body["host"]["asn_org"] == "Example Networks"
    assert [s["port"] for s in body["services"]] == [22, 443]
    assert body["services"][0]["tech"] == ["openssh"]
    assert body["vulns"][0]["cve"] == "CVE-2023-38408"
    assert body["vulns"][0]["kev"] is True
    assert body["certs"][0]["subject"] == "CN=a.example.com"
    assert body["findings"][0]["category"] == "cleartext-admin"
    assert body["findings"][0]["detail"] == {"why": "test"}


def test_default_include_is_services_and_vulns(client: TestClient) -> None:
    body = client.get("/api/v1/host/10.0.0.5").json()
    assert "services" in body and "vulns" in body
    assert "certs" not in body and "findings" not in body and "topology" not in body


def test_unknown_include_is_rejected(client: TestClient) -> None:
    # A typo must not read as an empty section.
    r = client.get("/api/v1/host/10.0.0.5?include=servces")
    assert r.status_code == 400
    assert "servces" in r.json()["detail"]


def test_topology_reports_clock_siblings(client: TestClient) -> None:
    topology = client.get("/api/v1/host/10.0.0.5?include=topology").json()["topology"]
    assert topology["nat_suspected"] is True
    assert topology["min_backend_count"] == 2
    # 10.0.0.9 answered with the same boot-time estimate.
    assert [s["ip"] for s in topology["clock_siblings"]] == ["10.0.0.9"]


def test_raw_and_der_blobs_are_not_shipped(client: TestClient) -> None:
    body = client.get("/api/v1/host/10.0.0.5?include=all").json()
    assert "raw" not in body["services"][0]
    assert "der" not in body["certs"][0]


def test_unseen_address_is_found_false_not_an_error(client: TestClient) -> None:
    body = client.get("/api/v1/host/10.0.0.77").json()
    assert body["found"] is False
    assert body["host"] is None
    assert body["authorized"] is True  # in scope, simply never answered


def test_out_of_scope_address_reports_unauthorized(client: TestClient) -> None:
    body = client.get("/api/v1/host/8.8.8.8").json()
    assert body["authorized"] is False
    assert body["found"] is False


def test_non_ip_is_rejected(client: TestClient) -> None:
    assert client.get("/api/v1/host/not-an-ip").status_code == 400


def test_scans_lists_ids(client: TestClient) -> None:
    scans = client.get("/api/v1/scans").json()["scans"]
    assert scans and scans[0]["status"] == "completed"
    assert scans[0]["cidrs"] == ["10.0.0.0/24"]


def test_no_scans_in_workspace_is_404(workspace: str) -> None:
    empty = TestClient(create_app(workspace))
    assert empty.get("/api/v1/host/10.0.0.5").status_code == 404


def test_domain_reports_resolution_and_scope(client: TestClient, workspace: str) -> None:
    scan_id = client.get("/api/v1/scans").json()["scans"][0]["id"]
    conn = sqlite3.connect(workspace_db(workspace))
    conn.execute(
        "INSERT INTO domain_resolutions (scan_id, domain, addresses, cnames, refused) "
        "VALUES (?,?,?,?,?)",
        (scan_id, "example.com", json.dumps(["10.0.0.5", "10.0.0.77"]),
         json.dumps([{"from": "www.example.com", "to": "example.com"}]),
         json.dumps([{"target": "cdn.vendor.net", "reason": "outside authorized domains"}])),
    )
    conn.commit()
    conn.close()

    body = client.get("/api/v1/domain/example.com").json()
    assert body["found"] is True
    assert [a["ip"] for a in body["addresses"]] == ["10.0.0.5", "10.0.0.77"]
    # 10.0.0.5 was scanned; 10.0.0.77 resolved but answered nothing.
    assert [a["found"] for a in body["addresses"]] == [True, False]
    assert body["refused"][0]["target"] == "cdn.vendor.net"


def test_domain_normalises_and_rejects_junk(client: TestClient) -> None:
    assert client.get("/api/v1/domain/EXAMPLE.com.").json()["domain"] == "example.com"
    # A wildcard is not a name that can be authorized or resolved.
    assert client.get("/api/v1/domain/*.example.com").status_code == 400
    assert client.get("/api/v1/domain/not a domain").status_code == 400


def test_subdomains_come_from_collected_sans(client: TestClient, workspace: str) -> None:
    cfg = workspace_dir(workspace) / "config.toml"
    cfg.write_text(
        cfg.read_text().replace(
            "authorized_domains = []", 'authorized_domains = ["example.com"]'
        )
    )
    body = client.get("/api/v1/domain/example.com?include=subdomains").json()
    assert body["authorized"] is True
    assert [s["subdomain"] for s in body["subdomains"]] == ["a.example.com"]


def test_auth_token_covers_the_api(workspace: str) -> None:
    # The API inherits `serve --auth-token`, which is what a remote client
    # authenticates with; a new surface that skipped it would be a hole.
    from lodan.cli import _install_auth_token

    _populate(workspace)
    app = create_app(workspace)
    _install_auth_token(app, "s3cret")
    c = TestClient(app)
    assert c.get("/api/v1/host/10.0.0.5").status_code == 401
    ok = c.get("/api/v1/host/10.0.0.5", headers={"X-Lodan-Token": "s3cret"})
    assert ok.status_code == 200


def test_the_api_never_writes(client: TestClient) -> None:
    # Every route here is a SELECT; a client cannot widen scope or start work.
    for method in ("post", "put", "patch", "delete"):
        r = getattr(client, method)("/api/v1/host/10.0.0.5")
        assert r.status_code == 405
