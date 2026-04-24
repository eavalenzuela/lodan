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
    from lodan.probes.tls import TLSProbe

    clear_registry()
    register("tls", TLSProbe)


def pick_probe(port: int, proto: str = "tcp") -> Probe | None:
    if proto != "tcp":
        return None
    for _name, cls in _REGISTRY:
        probe = cls()  # type: ignore[call-arg]
        if port in probe.default_ports:
            return probe
    return None
