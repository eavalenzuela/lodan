"""Map (port, proto) -> Probe.

Probes register themselves via register(). pick_probe() returns the first
probe whose default_ports contains the requested port, or None.

The v1 dispatch is port-based only. Banner sniffing (try-read-256-bytes then
match) lives behind the same interface and lands in a later commit; for now
an unrecognized port is simply not probed.
"""
from __future__ import annotations

from lodan.probes.base import Probe

_REGISTRY: list[tuple[str, type[Probe]]] = []


def register(name: str, cls: type[Probe]) -> None:
    _REGISTRY.append((name, cls))


def clear_registry() -> None:
    """Test hook: drop every registered probe."""
    _REGISTRY.clear()


def register_defaults() -> None:
    from lodan.probes.http import HTTPProbe
    from lodan.probes.mongo import MongoProbe
    from lodan.probes.mqtt import MQTTProbe
    from lodan.probes.rdp import RDPProbe
    from lodan.probes.redis import RedisProbe
    from lodan.probes.smb import SMBProbe
    from lodan.probes.ssh import SSHProbe
    from lodan.probes.tls import TLSProbe

    clear_registry()
    register("tls", TLSProbe)
    register("http", HTTPProbe)
    register("ssh", SSHProbe)
    register("smb", SMBProbe)
    register("rdp", RDPProbe)
    register("mqtt", MQTTProbe)
    register("redis", RedisProbe)
    register("mongo", MongoProbe)


def pick_probes(port: int, proto: str = "tcp") -> list[Probe]:
    """Every probe whose default_ports covers (port, proto).

    HTTPS ports match both TLS and HTTP probes; both results merge into the
    services row via COALESCE so neither clobbers the other.
    """
    if proto != "tcp":
        return []
    picks: list[Probe] = []
    for _name, cls in _REGISTRY:
        probe = cls()  # type: ignore[call-arg]
        if port in probe.default_ports:
            picks.append(probe)
    return picks
