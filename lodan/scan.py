"""Scan orchestrator. Ties authz + discovery + writer together.

The v1 M1 pipeline is intentionally narrow: load config, guard the targets,
open a scan row, run discovery, stream results to the services table, close
the scan row. Probes and enrichment land in later milestones.
"""
from __future__ import annotations

import asyncio
import contextlib
import sqlite3

from lodan import audit, authz, findings, normalize, notify
from lodan.config import Config, NotifyBlock
from lodan.diff import resolver as diff_resolver
from lodan.diff.scanner import DiffCounts, compute_and_store
from lodan.discovery.base import DiscoveryBackend, DiscoverySpec
from lodan.discovery.dispatch import pick, register_defaults
from lodan.discovery.ports import parse_ports
from lodan.enrich import cve as cve_enrich
from lodan.enrich import cve_data
from lodan.enrich.device import enrich_devices
from lodan.enrich.hosts import enrich_hosts
from lodan.enrich.topology import enrich_topology
from lodan.paths import workspace_config, workspace_db, workspace_scan_log
from lodan.probes import dispatch as probe_dispatch
from lodan.probes.runner import ProbeBudget, run_probes
from lodan.store import writer
from lodan.store.db import connect, ensure_schema

# How many discovery rows to accumulate per write transaction. Large enough to
# amortize commit/fsync overhead on wide ranges, small enough that a killed scan
# loses at most this many un-flushed rows and other writers aren't starved long.
_DISCOVERY_BATCH = 1000


def _commit_pending(conn: sqlite3.Connection) -> None:
    """Commit the open discovery transaction, tolerating an already-closed one."""
    with contextlib.suppress(sqlite3.OperationalError):
        conn.execute("COMMIT")


class ScanSummary:
    def __init__(self, scan_id: int) -> None:
        self.scan_id = scan_id
        self.services_discovered = 0
        self.authz_rejections = 0
        self.services_probed = 0
        self.hosts_fingerprinted = 0
        self.hosts_enriched = 0
        self.devices_classified = 0
        self.nat_suspected = 0
        self.vulns_matched = 0
        self.findings = 0
        self.diff_total = 0
        self.diff_from: int | None = None


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

    nets: list[authz.Network] = authz.authorized_networks(cfg.workspace)
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

    operator = audit.operator()
    conn = connect(workspace_db(workspace))
    try:
        ensure_schema(conn)
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
        alog = audit.open_scan_log(
            workspace_scan_log(workspace),
            operator=operator,
            workspace=workspace,
            scan_id=handle.scan_id,
        )

        try:
            alog.event(
                "scan_started",
                backend=getattr(backend, "name", type(backend).__name__),
                cidrs=cfg.workspace.authorized_ranges,
                ports=cfg.scan.ports,
                port_count=len(ports),
                tcp=cfg.scan.tcp,
                udp=cfg.scan.udp,
                rate_pps=cfg.scan.rate_pps,
                cloud_provider_allowed=cfg.workspace.cloud_provider_allowed,
                probes=probes,
            )
            _ledger_authorized_scope(conn, handle, operator, cfg)
            # Discovery can stream tens of thousands of rows on a wide range.
            # In autocommit mode that is one fsync per row; batch the inserts
            # (and the interleaved authz-reject bookkeeping) into transactions
            # of _DISCOVERY_BATCH rows instead. The final commit in `finally`
            # flushes the tail — and preserves the pre-batching behavior of
            # keeping partial results if discovery raises midway.
            pending = 0
            conn.execute("BEGIN")
            try:
                async for result in backend.run(spec):
                    # Canonicalize the address (compresses/lowercases IPv6) so it
                    # stores, diffs, and pivots consistently regardless of how the
                    # backend rendered it.
                    ip = normalize.ip(result.ip) or result.ip
                    try:
                        authz.check_target(ip, nets)
                    except authz.AuthorizationError as e:
                        writer.record_error(
                            conn, handle, stage="discovery", error=str(e),
                            ip=ip, port=result.port,
                        )
                        writer.record_authz_decision(
                            conn,
                            scan_id=handle.scan_id, workspace=workspace, operator=operator,
                            decision="refused", scope_kind="target",
                            target=ip, port=result.port, proto=result.proto,
                            reason=str(e),
                        )
                        summary.authz_rejections += 1
                        alog.event(
                            "authz_rejected",
                            ip=ip, port=result.port, proto=result.proto,
                            reason=str(e),
                        )
                    else:
                        writer.upsert_discovered_service(
                            conn, handle, ip, result.port, result.proto,
                            stack=result.stack,
                        )
                        summary.services_discovered += 1
                    pending += 1
                    if pending >= _DISCOVERY_BATCH:
                        conn.execute("COMMIT")
                        conn.execute("BEGIN")
                        pending = 0
            finally:
                _commit_pending(conn)
            # Roll the per-port passive fingerprints up to a host consensus.
            # Cheap read-modify-write over rows we just wrote; no traffic.
            summary.hosts_fingerprinted = writer.record_host_stack(conn, handle)
            alog.event(
                "discovery_completed",
                services_discovered=summary.services_discovered,
                authz_rejections=summary.authz_rejections,
                hosts_fingerprinted=summary.hosts_fingerprinted,
            )
            if probes:
                probe_dispatch.register_defaults()
                summary.services_probed = await run_probes(
                    conn, handle,
                    ProbeBudget(
                        concurrency=cfg.scan.concurrency,
                        per_host_concurrency=cfg.scan.per_host_concurrency,
                        timeout_s=cfg.scan.probe_timeout_s,
                        retries=cfg.scan.retries,
                        tls_matrix=cfg.scan.tls_matrix,
                        jarm=cfg.scan.jarm,
                    ),
                )
                alog.event("probes_completed", services_probed=summary.services_probed)
            if cfg.enrich.rdns or cfg.enrich.asn or cfg.enrich.geoip:
                summary.hosts_enriched = await enrich_hosts(
                    conn, handle,
                    do_rdns=cfg.enrich.rdns,
                    do_asn=cfg.enrich.asn,
                    do_geoip=cfg.enrich.geoip,
                )
            if cfg.enrich.cve:
                summary.vulns_matched = _run_cve_enrichment(conn, handle.scan_id)
            if cfg.enrich.favicon:
                writer.record_favicons(conn, handle)
            if cfg.enrich.device:
                # Last enrichment step: fuses probe banners, the passive stack
                # fingerprint and the (just-recorded) favicon labels, so it
                # needs every other enrichment to have landed first.
                summary.devices_classified = enrich_devices(conn, handle.scan_id)
                # Backend correlation reads the same per-port fingerprints; it
                # runs after device classification so both land on `hosts` in
                # one pass over the scan.
                summary.nat_suspected = enrich_topology(conn, handle.scan_id)
            if summary.hosts_enriched or cfg.enrich.cve or summary.devices_classified:
                alog.event(
                    "enrichment_completed",
                    hosts_enriched=summary.hosts_enriched,
                    vulns_matched=summary.vulns_matched,
                    devices_classified=summary.devices_classified,
                    nat_suspected=summary.nat_suspected,
                )
            summary.findings = findings.run_findings(conn, handle.scan_id)
            if summary.findings:
                alog.event("findings_detected", findings=summary.findings)
            writer.finish_scan(conn, handle, status="completed")
            prev = diff_resolver.previous_completed(conn, handle.scan_id)
            if prev is not None:
                counts = compute_and_store(conn, prev, handle.scan_id)
                summary.diff_from = prev
                summary.diff_total = counts.total
                alog.event("diff_computed", diff_from=prev, diff_total=counts.total)
                if counts.total > 0 and cfg.notify.enabled:
                    await _notify_changes(conn, handle, cfg.notify, prev, counts, alog)
            alog.event(
                "scan_finished",
                status="completed",
                services_discovered=summary.services_discovered,
                services_probed=summary.services_probed,
                hosts_enriched=summary.hosts_enriched,
                vulns_matched=summary.vulns_matched,
                findings=summary.findings,
                authz_rejections=summary.authz_rejections,
                diff_from=summary.diff_from,
                diff_total=summary.diff_total,
            )
        except Exception as e:
            writer.record_error(conn, handle, stage="discovery", error=repr(e))
            writer.finish_scan(conn, handle, status="failed")
            alog.event("scan_failed", status="failed", error=repr(e))
            raise
        finally:
            alog.close()
        return summary
    finally:
        conn.close()


def _diff_examples(conn, from_id: int, to_id: int, limit: int = 10) -> list[dict]:
    rows = conn.execute(
        "SELECT kind, ip, port FROM scan_diffs WHERE from_scan_id = ? AND to_scan_id = ? "
        "ORDER BY kind, ip, port LIMIT ?",
        (from_id, to_id, limit),
    ).fetchall()
    return [{"kind": k, "ip": ip, "port": port} for k, ip, port in rows]


async def _notify_changes(
    conn, handle, notify_cfg: NotifyBlock, diff_from: int, counts: DiffCounts, alog
) -> None:
    """Push a diff summary to the configured sinks. Never raises — a broken
    webhook / mail server is logged (audit + scan_errors) but the scan, already
    completed by this point, stays completed."""
    summary = notify.build_summary(
        handle.workspace, handle.scan_id, diff_from, counts,
        _diff_examples(conn, diff_from, handle.scan_id),
    )
    try:
        results = await notify.send(notify_cfg, summary)
    except Exception as e:  # noqa: BLE001 — defensive; send() already swallows sink errors
        alog.event("notify_failed", error=repr(e))
        writer.record_error(conn, handle, stage="notify", error=repr(e))
        return
    for r in results:
        alog.event(
            "notify_sent" if r.ok else "notify_failed", sink=r.sink, detail=r.detail,
        )
        if not r.ok:
            writer.record_error(
                conn, handle, stage=f"notify:{r.sink}", error=r.detail,
            )


def _ledger_authorized_scope(conn, handle, operator: str, cfg: Config) -> None:
    """Record the authorized scope in the ledger at scan start.

    One 'authorized' row per authorized CIDR, plus a 'cloud' row for any CIDR
    that overlaps a well-known cloud prefix (only reachable because the operator
    set `cloud_provider_allowed` + a justification, both captured here). This is
    the durable "what were we cleared to touch" half of the ledger.
    """
    from ipaddress import ip_network

    justification = cfg.workspace.cloud_provider_justification.strip()
    for cidr in cfg.workspace.authorized_ranges:
        writer.record_authz_decision(
            conn,
            scan_id=handle.scan_id, workspace=handle.workspace, operator=operator,
            decision="authorized", scope_kind="cidr", target=cidr,
        )
        if not cfg.workspace.cloud_provider_allowed:
            continue
        hits = authz.cloud_overlaps(ip_network(cidr, strict=False))
        if not hits:
            continue
        providers = ", ".join(sorted({h.provider for h in hits}))
        writer.record_authz_decision(
            conn,
            scan_id=handle.scan_id, workspace=handle.workspace, operator=operator,
            decision="authorized", scope_kind="cloud", target=cidr,
            reason=f"cloud-opt-in [{providers}]: {justification}",
        )


def _run_cve_enrichment(workspace_conn, scan_id: int) -> int:
    """Open the shared CVE DB if it exists; noop if the operator hasn't
    run `lodan update --cves` yet."""
    from lodan.paths import nvd_db

    if not nvd_db().exists():
        return 0
    cve_conn = cve_data.connect()
    try:
        return cve_enrich.enrich_cves(workspace_conn, cve_conn, scan_id)
    finally:
        cve_conn.close()


def run_scan_sync(
    workspace: str,
    backend: DiscoveryBackend | None = None,
    probes: bool = True,
) -> ScanSummary:
    return asyncio.run(run_scan(workspace, backend=backend, probes=probes))
