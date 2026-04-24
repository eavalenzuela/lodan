"""Scan orchestrator. Ties authz + discovery + writer together.

The v1 M1 pipeline is intentionally narrow: load config, guard the targets,
open a scan row, run discovery, stream results to the services table, close
the scan row. Probes and enrichment land in later milestones.
"""
from __future__ import annotations

import asyncio
from ipaddress import IPv4Network

from lodan import authz
from lodan.config import Config
from lodan.discovery.base import DiscoveryBackend, DiscoverySpec
from lodan.discovery.dispatch import pick, register_defaults
from lodan.discovery.ports import parse_ports
from lodan.enrich.hosts import enrich_hosts
from lodan.paths import workspace_config, workspace_db
from lodan.probes import dispatch as probe_dispatch
from lodan.probes.runner import ProbeBudget, run_probes
from lodan.store import writer
from lodan.store.db import connect


class ScanSummary:
    def __init__(self, scan_id: int) -> None:
        self.scan_id = scan_id
        self.services_discovered = 0
        self.authz_rejections = 0
        self.services_probed = 0
        self.hosts_enriched = 0


async def run_scan(
    workspace: str,
    backend: DiscoveryBackend | None = None,
    probes: bool = True,
) -> ScanSummary:
    """Run one scan cycle for `workspace`.

    `backend` lets tests inject a deterministic backend; in normal operation
    the config's `scan.backend` picks one via the dispatch registry.
    """
    cfg = Config.load(workspace_config(workspace))
    authz.check_workspace(cfg.workspace)

    nets: list[IPv4Network] = authz.authorized_networks(cfg.workspace)
    ports = parse_ports(cfg.scan.ports)
    spec = DiscoverySpec(
        targets=nets,
        ports=ports,
        tcp=cfg.scan.tcp,
        udp=cfg.scan.udp,
        rate_pps=cfg.scan.rate_pps,
    )

    if backend is None:
        register_defaults()
        backend = pick(cfg.scan.backend)

    conn = connect(workspace_db(workspace))
    try:
        handle = writer.open_scan(
            conn,
            workspace=workspace,
            cidrs=cfg.workspace.authorized_ranges,
            cloud_justification=(
                cfg.workspace.cloud_provider_justification
                if cfg.workspace.cloud_provider_allowed
                else None
            ),
        )
        summary = ScanSummary(handle.scan_id)

        try:
            async for result in backend.run(spec):
                try:
                    authz.check_target(result.ip, nets)
                except authz.AuthorizationError as e:
                    writer.record_error(
                        conn, handle, stage="discovery", error=str(e),
                        ip=result.ip, port=result.port,
                    )
                    summary.authz_rejections += 1
                    continue
                writer.upsert_discovered_service(
                    conn, handle, result.ip, result.port, result.proto,
                )
                summary.services_discovered += 1
            if probes:
                probe_dispatch.register_defaults()
                summary.services_probed = await run_probes(
                    conn, handle,
                    ProbeBudget(
                        concurrency=cfg.scan.concurrency,
                        per_host_concurrency=cfg.scan.per_host_concurrency,
                        timeout_s=cfg.scan.probe_timeout_s,
                        retries=cfg.scan.retries,
                    ),
                )
            if cfg.enrich.rdns or cfg.enrich.asn:
                summary.hosts_enriched = await enrich_hosts(
                    conn, handle,
                    do_rdns=cfg.enrich.rdns,
                    do_asn=cfg.enrich.asn,
                )
            writer.finish_scan(conn, handle, status="completed")
        except Exception as e:
            writer.record_error(conn, handle, stage="discovery", error=repr(e))
            writer.finish_scan(conn, handle, status="failed")
            raise
        return summary
    finally:
        conn.close()


def run_scan_sync(
    workspace: str,
    backend: DiscoveryBackend | None = None,
    probes: bool = True,
) -> ScanSummary:
    return asyncio.run(run_scan(workspace, backend=backend, probes=probes))
