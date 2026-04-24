"""Pick a discovery backend from config.

Explicit backend name wins. 'auto' probes masscan -> naabu -> scapy for
availability and returns the first that works. Raises if nothing works.
"""
from __future__ import annotations

from lodan.discovery.base import DiscoveryBackend


class NoBackendAvailable(RuntimeError):
    pass


_REGISTRY: dict[str, type[DiscoveryBackend]] = {}


def register(name: str, cls: type[DiscoveryBackend]) -> None:
    _REGISTRY[name] = cls


def get(name: str) -> DiscoveryBackend:
    if name not in _REGISTRY:
        raise KeyError(f"unknown discovery backend: {name!r}")
    return _REGISTRY[name]()  # type: ignore[call-arg]


def register_defaults() -> None:
    """Register the production backends. Safe to call multiple times."""
    from lodan.discovery.masscan import MasscanBackend
    from lodan.discovery.scapy_backend import ScapyBackend

    register("masscan", MasscanBackend)
    register("scapy", ScapyBackend)


def pick(requested: str) -> DiscoveryBackend:
    """Return a usable backend. `requested` may be 'auto' or a registered name."""
    if requested != "auto":
        backend = get(requested)
        if not backend.available():
            raise NoBackendAvailable(f"backend {requested!r} is registered but not available")
        return backend

    for name in ("masscan", "naabu", "scapy"):
        if name not in _REGISTRY:
            continue
        backend = _REGISTRY[name]()  # type: ignore[call-arg]
        if backend.available():
            return backend
    raise NoBackendAvailable("no discovery backend available (install masscan/naabu or run as root for scapy)")
