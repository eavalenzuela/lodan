"""Live probe integration tests against the docker-compose stack.

Opt-in (LODAN_DOCKER_TESTS=1). Each test drives a real probe against a real
container on loopback and asserts the parsed ProbeResult — the end-to-end
counterpart to the offline parser unit tests. We exercise the probe layer
directly rather than the privileged discovery sweep, since masscan/scapy need
CAP_NET_RAW that a test runner usually lacks.
"""
from __future__ import annotations

import asyncio

import pytest

from lodan.probes.http import HTTPProbe
from lodan.probes.mongo import MongoProbe
from lodan.probes.redis import RedisProbe
from lodan.probes.ssh import SSHProbe, parse_banner
from lodan.probes.tls import TLSProbe

pytestmark = pytest.mark.docker

_TIMEOUT = 10.0


def _run(coro):
    return asyncio.run(coro)


def test_http_plain(docker_stack) -> None:
    res = _run(HTTPProbe().probe(docker_stack.host, docker_stack.ports["http"], _TIMEOUT))
    assert res.service == "http"
    server = res.raw.get("headers", {}).get("server", "")
    assert "nginx" in server.lower()


def test_tls_cert_and_fingerprints(docker_stack) -> None:
    res = _run(TLSProbe().probe(docker_stack.host, docker_stack.ports["https"], _TIMEOUT))
    assert res.service == "tls"
    # Self-signed cert is presented in plaintext under our TLS 1.2 hello.
    assert res.cert_fingerprint
    assert res.cert_sans and "lodan-itest" in res.cert_sans
    # All four fingerprints should be populated from the live handshake.
    assert res.ja3 and res.ja3s
    assert res.ja4 and res.ja4s
    assert res.ja4.startswith("t12")      # we advertise TLS 1.2
    assert res.ja4s.startswith("t")
    # Raw (unhashed) and original-order forms are captured in the raw blob.
    for key in ("ja4_r", "ja4_o", "ja4_ro"):
        assert res.raw[key].startswith(res.ja4.split("_")[0] + "_")
    assert res.raw["ja4s_r"].startswith(res.ja4s.split("_")[0] + "_")


def test_redis_unauth_info(docker_stack) -> None:
    res = _run(RedisProbe().probe(docker_stack.host, docker_stack.ports["redis"], _TIMEOUT))
    assert res.service == "redis"
    assert res.raw.get("fields", {}).get("redis_version")
    assert res.banner.startswith("Redis ")


def test_mongo_unauth_hello(docker_stack) -> None:
    res = _run(MongoProbe().probe(docker_stack.host, docker_stack.ports["mongo"], _TIMEOUT))
    assert res.service == "mongo"
    assert res.banner


def test_ssh_banner_and_host_keys(docker_stack) -> None:
    res = _run(SSHProbe().probe(docker_stack.host, docker_stack.ports["ssh"], _TIMEOUT))
    assert res.service == "ssh"
    parsed = parse_banner(res.raw["banner"])
    assert parsed is not None
    assert "openssh" in parsed.software.lower()
    # asyncssh is a dependency, so host-key collection should succeed.
    assert res.raw["host_keys"], "expected at least one SSH host key"
    # The promoted column should match the first collected key's fingerprint.
    assert res.ssh_hostkey == res.raw["host_keys"][0]["sha256"]
