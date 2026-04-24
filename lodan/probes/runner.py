"""Probe phase orchestration.

Bounded fan-out over every (ip, port, proto) discovery recorded for the
scan. Each probe is gated by two semaphores (scan-wide + per-host) so we
don't hammer a single target.

Failures land in scan_errors and never crash the phase; the scan row stays
'running' (or 'completed' when the final phase closes it) regardless.
"""
from __future__ import annotations

import asyncio
import sqlite3
from collections import defaultdict
from dataclasses import dataclass

from lodan.probes.base import Probe
from lodan.probes.dispatch import pick_probe
from lodan.store import writer
from lodan.store.writer import ScanHandle


@dataclass(frozen=True)
class ProbeBudget:
    concurrency: int = 100
    per_host_concurrency: int = 4
    timeout_s: float = 5.0
    retries: int = 1


async def run_probes(
    conn: sqlite3.Connection,
    handle: ScanHandle,
    budget: ProbeBudget,
) -> int:
    """Probe every discovered service for the scan. Returns the count probed."""
    tuples = writer.discovered_tuples(conn, handle)
    sem_global = asyncio.Semaphore(budget.concurrency)
    sem_per_host: dict[str, asyncio.Semaphore] = defaultdict(
        lambda: asyncio.Semaphore(budget.per_host_concurrency)
    )
    tasks = [
        asyncio.create_task(
            _run_one(conn, handle, ip, port, proto, sem_global, sem_per_host, budget)
        )
        for (ip, port, proto) in tuples
    ]
    if not tasks:
        return 0
    results = await asyncio.gather(*tasks, return_exceptions=False)
    return sum(1 for r in results if r)


async def _run_one(
    conn: sqlite3.Connection,
    handle: ScanHandle,
    ip: str,
    port: int,
    proto: str,
    sem_global: asyncio.Semaphore,
    sem_per_host: dict[str, asyncio.Semaphore],
    budget: ProbeBudget,
) -> bool:
    probe: Probe | None = pick_probe(port, proto)
    if probe is None:
        return False

    attempts = budget.retries + 1
    last_err: Exception | None = None
    for _ in range(attempts):
        try:
            async with sem_global, sem_per_host[ip]:
                result = await probe.probe(ip, port, budget.timeout_s)
            writer.update_service_from_probe(conn, handle, ip, port, proto, result)
            return True
        except Exception as e:  # noqa: BLE001 — probes can fail in many ways
            last_err = e
    if last_err is not None:
        writer.record_error(
            conn, handle,
            stage=f"probe:{probe.name}",
            error=repr(last_err),
            ip=ip, port=port,
        )
    return False
