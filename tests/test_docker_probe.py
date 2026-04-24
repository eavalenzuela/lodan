from __future__ import annotations

import json

from lodan.probes.docker import DockerProbe, parse


def test_parse_valid_version_response() -> None:
    body = json.dumps({
        "Version": "24.0.0",
        "ApiVersion": "1.43",
        "MinAPIVersion": "1.12",
        "GoVersion": "go1.20.3",
        "Os": "linux",
        "Arch": "amd64",
        "KernelVersion": "5.15.0",
    })
    result = parse({"status": 200, "headers": {}, "body": body})
    assert result.service == "docker"
    assert "Docker 24.0.0" in (result.banner or "")
    assert "API 1.43" in (result.banner or "")
    assert "linux/amd64" in (result.banner or "")
    assert result.raw["payload"]["Os"] == "linux"


def test_parse_non_docker_json() -> None:
    result = parse({"status": 200, "headers": {}, "body": '{"hello":"world"}'})
    assert "non-Docker" in (result.banner or "")


def test_parse_non_json_body() -> None:
    result = parse({"status": 200, "headers": {}, "body": "<html>nope</html>"})
    assert "non-Docker" in (result.banner or "")


def test_parse_connection_error() -> None:
    result = parse({"_error": "ConnectTimeout"})
    assert "no response" in (result.banner or "")
    assert "ConnectTimeout" in (result.banner or "")


def test_parse_none_capture() -> None:
    result = parse(None)
    assert "no response" in (result.banner or "")


def test_default_ports() -> None:
    assert 2375 in DockerProbe().default_ports
    assert 2376 in DockerProbe().default_ports
