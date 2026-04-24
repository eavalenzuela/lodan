"""Deterministic no-network discovery backend, used by tests.

Yields a fixed set of results regardless of the spec. Install one with a
precomputed result list:

    FakeBackend(results=[DiscoveryResult("10.0.0.5", 22, "tcp"), ...])
"""
from __future__ import annotations

from collections.abc import AsyncIterator

from lodan.discovery.base import DiscoveryResult, DiscoverySpec


class FakeBackend:
    name = "fake"

    def __init__(self, results: list[DiscoveryResult]) -> None:
        self._results = list(results)

    def available(self) -> bool:
        return True

    async def run(self, spec: DiscoverySpec) -> AsyncIterator[DiscoveryResult]:
        for r in self._results:
            yield r
