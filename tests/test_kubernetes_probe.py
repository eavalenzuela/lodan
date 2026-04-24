from __future__ import annotations

import json

from lodan.probes.kubernetes import KubernetesProbe, parse


def test_parse_version_payload_wins() -> None:
    payload = {
        "gitVersion": "v1.29.3",
        "platform": "linux/amd64",
        "goVersion": "go1.21.8",
    }
    capture = {
        "/version": {
            "status": 200,
            "body": json.dumps(payload),
            "content_type": "application/json",
        },
        "/healthz": {"status": 200, "body": "ok", "content_type": "text/plain"},
    }
    result = parse(capture)
    assert result.service == "kubernetes"
    assert "v1.29.3" in (result.banner or "")
    assert "linux/amd64" in (result.banner or "")
    assert result.raw["payload"]["goVersion"] == "go1.21.8"


def test_parse_falls_back_to_healthz_ok() -> None:
    capture = {
        "/version": {"status": 404, "body": "", "content_type": ""},
        "/healthz": {"status": 200, "body": "ok", "content_type": "text/plain"},
    }
    result = parse(capture)
    assert "kubelet" in (result.banner or "")


def test_parse_auth_required() -> None:
    capture = {
        "/version": {"status": 401, "body": "Unauthorized", "content_type": ""},
        "/healthz": {"status": 401, "body": "Unauthorized", "content_type": ""},
    }
    result = parse(capture)
    assert "auth required" in (result.banner or "")


def test_parse_nothing_recognizable() -> None:
    capture = {
        "/version": {"status": 200, "body": "nope", "content_type": "text/plain"},
        "/healthz": {"status": 200, "body": "nope", "content_type": "text/plain"},
    }
    result = parse(capture)
    assert "no recognizable endpoint" in (result.banner or "")


def test_default_ports() -> None:
    ports = KubernetesProbe().default_ports
    assert 6443 in ports
    assert 10250 in ports
    assert 10255 in ports
