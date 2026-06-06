"""Session fixture that brings the integration stack up and tears it down.

These tests touch the network and require Docker, so they are opt-in: set
`LODAN_DOCKER_TESTS=1` to run them. Without that env var (the default, and
what CI uses) the whole package is skipped and the offline suite is
unaffected.

The fixture generates a throwaway self-signed cert for nginx's TLS server
using `cryptography` (already a runtime dep — no openssl shell-out), runs
`docker compose up -d`, waits for each TCP port to accept connections, and
guarantees `docker compose down -v` on teardown.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

_HERE = Path(__file__).parent
_COMPOSE = _HERE / "docker-compose.yml"
_CERT_DIR = _HERE / "certs"

# (host, port) for each service, matching docker-compose.yml's published ports.
HOST = "127.0.0.1"
PORTS = {
    "http": 18080,
    "https": 18443,
    "redis": 16379,
    "mongo": 17017,
    "ssh": 12222,
}


@dataclass(frozen=True)
class Stack:
    host: str
    ports: dict[str, int]


def _enabled() -> bool:
    return os.environ.get("LODAN_DOCKER_TESTS") == "1"


def _generate_self_signed_cert(dest_dir: Path) -> None:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID

    dest_dir.mkdir(parents=True, exist_ok=True)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "lodan-itest")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.now(UTC) - timedelta(days=1))
        .not_valid_after(datetime.now(UTC) + timedelta(days=365))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("lodan-itest")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    (dest_dir / "key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
    )
    (dest_dir / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def _wait_port(host: str, port: int, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection((host, port), timeout=2):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def _compose(*args: str) -> None:
    subprocess.run(
        ["docker", "compose", "-f", str(_COMPOSE), *args],
        check=True,
        capture_output=True,
    )


@pytest.fixture(scope="session")
def docker_stack() -> Stack:
    if not _enabled():
        pytest.skip("integration tests are opt-in; set LODAN_DOCKER_TESTS=1")
    if shutil.which("docker") is None:
        pytest.skip("docker not on PATH")

    _generate_self_signed_cert(_CERT_DIR)
    _compose("up", "-d", "--remove-orphans")
    try:
        for name, port in PORTS.items():
            # SSH host-key generation in the openssh image can take a while.
            budget = 90 if name == "ssh" else 60
            if not _wait_port(HOST, port, budget):
                raise RuntimeError(f"service {name!r} never came up on {HOST}:{port}")
        # Give Mongo/SSH a moment past the TCP accept to finish initializing.
        time.sleep(2)
        yield Stack(host=HOST, ports=dict(PORTS))
    finally:
        _compose("down", "-v")
        shutil.rmtree(_CERT_DIR, ignore_errors=True)
