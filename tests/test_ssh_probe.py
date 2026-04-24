from __future__ import annotations

import pytest

from lodan.probes.ssh import SSHProbe, parse, parse_banner


def test_parse_openssh_banner() -> None:
    b = parse_banner("SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5")
    assert b is not None
    assert b.version == "2.0"
    assert b.software == "OpenSSH_8.2p1"
    assert b.comment == "Ubuntu-4ubuntu0.5"


def test_parse_banner_without_comment() -> None:
    b = parse_banner("SSH-2.0-dropbear_2019.78")
    assert b is not None
    assert b.software == "dropbear_2019.78"
    assert b.comment is None


def test_parse_banner_with_crlf_stripped_upstream() -> None:
    b = parse_banner("SSH-1.99-Cisco-1.25  ")
    assert b is not None
    assert b.version == "1.99"
    assert b.software == "Cisco-1.25"


@pytest.mark.parametrize("line", [
    "",
    "HTTP/1.1 200 OK",
    "SSH",
    "SSH-2.0",
])
def test_parse_banner_rejects_non_ssh(line: str) -> None:
    assert parse_banner(line) is None


def test_parse_emits_probe_result() -> None:
    result = parse("SSH-2.0-OpenSSH_9.3", host_keys=[("ssh-ed25519", "a" * 64)])
    assert result.service == "ssh"
    assert "OpenSSH_9.3" in (result.banner or "")
    assert "1 host key" in (result.banner or "")
    assert result.raw["host_keys"] == [{"algo": "ssh-ed25519", "sha256": "a" * 64}]
    assert result.raw["parsed"]["software"] == "OpenSSH_9.3"


def test_parse_without_host_keys() -> None:
    result = parse("SSH-2.0-OpenSSH_9.3")
    assert result.raw["host_keys"] == []


def test_parse_unknown_banner_still_captures_raw() -> None:
    result = parse("garbage line")
    assert result.service == "ssh"
    assert result.raw["parsed"] is None
    assert result.raw["banner"] == "garbage line"


def test_default_ports() -> None:
    probe = SSHProbe()
    assert 22 in probe.default_ports
    assert 2022 in probe.default_ports
    assert 2222 in probe.default_ports
