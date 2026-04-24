"""lodan CLI entry point.

Subcommand bodies for scan / diff / query / serve / export / update / prune
land in follow-up commits. This scaffold implements `init` end-to-end so that
a workspace can be created and inspected by downstream features.
"""
from __future__ import annotations

import sys
from ipaddress import ip_network
from typing import Annotated

import typer
from rich.console import Console

from lodan import __version__
from lodan.authz import AuthorizationError
from lodan.config import default_config_toml
from lodan.discovery.dispatch import NoBackendAvailable
from lodan.paths import workspace_config, workspace_db, workspace_dir
from lodan.scan import run_scan_sync
from lodan.store.db import bootstrap

app = typer.Typer(
    add_completion=False,
    no_args_is_help=False,
    invoke_without_command=True,
    help="lodan — local Shodan for ranges you own.",
)
console = Console()
err = Console(stderr=True)

NOT_IMPL = 2


def _not_implemented(name: str) -> None:
    err.print(f"[yellow]lodan {name}[/]: not implemented yet")
    raise typer.Exit(NOT_IMPL)


def _version_cb(value: bool) -> None:
    if value:
        console.print(f"lodan {__version__}")
        raise typer.Exit(0)


@app.callback()
def _root(
    ctx: typer.Context,
    version: Annotated[
        bool,
        typer.Option(
            "--version",
            callback=_version_cb,
            is_eager=True,
            help="Show version and exit.",
        ),
    ] = False,
) -> None:
    if ctx.invoked_subcommand is None:
        console.print(ctx.get_help())
        raise typer.Exit(0)


@app.command("init")
def init_cmd(
    workspace: Annotated[str, typer.Argument(help="Workspace name.")],
    cidrs: Annotated[
        str,
        typer.Option(
            "--cidrs",
            help="Comma-separated CIDRs this workspace is authorized to scan.",
        ),
    ],
) -> None:
    """Create a new workspace under ~/.lodan/workspaces/<name>/."""
    cidr_list = [c.strip() for c in cidrs.split(",") if c.strip()]
    if not cidr_list:
        err.print("[red]--cidrs must list at least one CIDR[/]")
        raise typer.Exit(1)
    for c in cidr_list:
        try:
            ip_network(c, strict=False)
        except ValueError as e:
            err.print(f"[red]invalid CIDR[/] {c!r}: {e}")
            raise typer.Exit(1) from None

    wdir = workspace_dir(workspace)
    if wdir.exists():
        err.print(f"[red]workspace already exists:[/] {wdir}")
        raise typer.Exit(1)

    wdir.mkdir(parents=True)
    workspace_config(workspace).write_text(default_config_toml(workspace, cidr_list))
    bootstrap(workspace_db(workspace))
    console.print(f"[green]created workspace[/] {wdir}")


@app.command("update")
def update_cmd(
    cves: Annotated[bool, typer.Option("--cves", help="Refresh the NVD 2.0 CVE snapshot.")] = False,
    ip2location: Annotated[
        bool, typer.Option("--ip2location", help="Check the IP2Location LITE DB status.")
    ] = False,
    max_pages: Annotated[
        int | None,
        typer.Option("--max-pages", help="Cap pages for a quick refresh."),
    ] = None,
) -> None:
    """Refresh NVD + IP2Location snapshots under ~/.lodan/data/."""
    if not (cves or ip2location):
        err.print("[yellow]nothing to do[/]: pass --cves and/or --ip2location")
        raise typer.Exit(1)

    if cves:
        import asyncio

        from lodan.enrich.cve_data import UpdateStats, bootstrap_dirs, connect, update

        bootstrap_dirs()
        conn = connect()

        def _tick(s: UpdateStats) -> None:
            console.print(
                f"  page {s.pages}: {s.cves_seen} CVEs, {s.rows_upserted} rows upserted"
            )

        stats = asyncio.run(update(conn, max_pages=max_pages, progress=_tick))
        console.print(
            f"[green]NVD update complete[/]: "
            f"{stats.pages} pages, {stats.cves_seen} CVEs, "
            f"{stats.rows_upserted} rows upserted"
        )

    if ip2location:
        from lodan.paths import ip2location_asn_bin, ip2location_dir

        bin_path = ip2location_asn_bin()
        ip2location_dir().mkdir(parents=True, exist_ok=True)
        if bin_path.exists():
            size_mb = bin_path.stat().st_size / (1024 * 1024)
            console.print(
                f"[green]IP2Location LITE DB-ASN present[/] at {bin_path} ({size_mb:.1f} MB)"
            )
        else:
            err.print(
                f"[yellow]IP2Location LITE DB-ASN not found at {bin_path}[/]\n"
                f"Register for a free account at https://lite.ip2location.com/, "
                f"download IP2LOCATION-LITE-ASN.BIN, and place it at that path. "
                f"Automated download lands in a later commit."
            )
            raise typer.Exit(1)


@app.command("scan")
def scan_cmd(
    workspace: Annotated[str, typer.Argument(help="Workspace name.")],
) -> None:
    """Run a scan for the given workspace."""
    if not workspace_config(workspace).exists():
        err.print(f"[red]no such workspace:[/] {workspace} (try `lodan init`)")
        raise typer.Exit(1)
    try:
        summary = run_scan_sync(workspace)
    except AuthorizationError as e:
        err.print(f"[red]authorization:[/] {e}")
        raise typer.Exit(1) from None
    except NoBackendAvailable as e:
        err.print(f"[red]{e}[/]")
        raise typer.Exit(1) from None
    console.print(
        f"[green]scan {summary.scan_id} complete[/]: "
        f"{summary.services_discovered} services, "
        f"{summary.services_probed} probed, "
        f"{summary.hosts_enriched} hosts enriched, "
        f"{summary.vulns_matched} CVE matches, "
        f"{summary.authz_rejections} authz-rejected"
    )
    if summary.diff_from is not None:
        console.print(
            f"  diff vs scan {summary.diff_from}: {summary.diff_total} findings"
        )


@app.command("diff")
def diff_cmd(
    workspace: Annotated[str, typer.Argument(help="Workspace name.")],
    from_: Annotated[
        str | None,
        typer.Option("--from", help="Source scan: id, 'prev', 'latest', or ISO date."),
    ] = None,
    to_: Annotated[
        str | None,
        typer.Option("--to", help="Target scan: id, 'prev', 'latest', or ISO date."),
    ] = None,
) -> None:
    """Diff two scans within a workspace."""
    if not workspace_config(workspace).exists():
        err.print(f"[red]no such workspace:[/] {workspace}")
        raise typer.Exit(1)

    from lodan.config import Config
    from lodan.diff import resolver as diff_resolver
    from lodan.diff.scanner import compute_and_store
    from lodan.store.db import connect

    cfg = Config.load(workspace_config(workspace))
    from_token = from_ or cfg.diff.default_from
    to_token = to_ or "latest"

    conn = connect(workspace_db(workspace))
    try:
        try:
            from_id = diff_resolver.resolve(conn, from_token)
            to_id = diff_resolver.resolve(conn, to_token)
        except diff_resolver.ResolveError as e:
            err.print(f"[red]{e}[/]")
            raise typer.Exit(1) from None
        if from_id == to_id:
            err.print(f"[red]from and to resolve to the same scan ({from_id})[/]")
            raise typer.Exit(1)
        counts = compute_and_store(conn, from_id, to_id)
    finally:
        conn.close()

    console.print(
        f"[green]diff {from_id} -> {to_id}[/]: "
        f"{counts.new_service} new, {counts.gone_service} gone, "
        f"{counts.changed} changed, {counts.new_cert} new certs, "
        f"{counts.new_host} new hosts ({counts.total} total)"
    )


@app.command("query")
def query_cmd(
    workspace: Annotated[str, typer.Argument(help="Workspace name.")],
    expression: Annotated[str, typer.Argument(help="DSL expression.")],
    scan: Annotated[
        int | None,
        typer.Option("--scan", help="Limit to one scan id (default: every scan)."),
    ] = None,
    limit: Annotated[int, typer.Option("--limit")] = 200,
    as_json: Annotated[
        bool,
        typer.Option("--json", help="Emit JSONL instead of a table."),
    ] = False,
) -> None:
    """Run a mini-DSL query across services.

    Examples:
        lodan query w "port:443 AND sans:*.corp.example.com"
        lodan query w "tech:nginx OR tech:apache"
        lodan query w "banner:OpenSSH*"
    """
    if not workspace_config(workspace).exists():
        err.print(f"[red]no such workspace:[/] {workspace}")
        raise typer.Exit(1)

    import json

    from lodan.store.db import connect
    from lodan.store.query import QueryError, run_query

    conn = connect(workspace_db(workspace))
    try:
        rows = run_query(conn, expression, scan_id=scan, limit=limit)
    except QueryError as e:
        err.print(f"[red]query error:[/] {e}")
        raise typer.Exit(1) from None
    finally:
        conn.close()

    if as_json:
        # Bypass rich so line wrapping doesn't split JSON records.
        for row in rows:
            sys.stdout.write(json.dumps(row, default=str) + "\n")
        return

    if not rows:
        console.print("[yellow]no matches[/]")
        return
    from rich.table import Table

    table = Table(show_lines=False)
    for col in ("scan", "ip", "port", "proto", "service", "banner"):
        table.add_column(col)
    for row in rows:
        banner = (row.get("banner") or "")[:80]
        table.add_row(
            str(row["scan_id"]), row["ip"], str(row["port"]),
            row["proto"], row.get("service") or "", banner,
        )
    console.print(table)
    console.print(f"[green]{len(rows)} match(es)[/]")


@app.command("serve")
def serve_cmd(
    workspace: Annotated[str, typer.Argument(help="Workspace name.")],
    addr: Annotated[
        str,
        typer.Option("--addr", help="[host]:port. Default 127.0.0.1:8765."),
    ] = "127.0.0.1:8765",
    auth_token: Annotated[
        str | None,
        typer.Option("--auth-token", help="Required when binding non-loopback."),
    ] = None,
) -> None:
    """Serve the web UI for the given workspace."""
    if not workspace_config(workspace).exists():
        err.print(f"[red]no such workspace:[/] {workspace}")
        raise typer.Exit(1)

    host, _, port_s = addr.rpartition(":")
    host = host or "127.0.0.1"
    try:
        port = int(port_s)
    except ValueError:
        err.print(f"[red]invalid --addr:[/] {addr!r}")
        raise typer.Exit(1) from None

    if host not in ("127.0.0.1", "localhost", "::1") and not auth_token:
        err.print(
            "[red]refusing to bind non-loopback without --auth-token[/] "
            "(token is checked against the X-Lodan-Token header)"
        )
        raise typer.Exit(1)

    import uvicorn

    from lodan.ui.app import create_app

    fastapi_app = create_app(workspace)
    if auth_token:
        _install_auth_token(fastapi_app, auth_token)
    console.print(f"[green]serving[/] http://{host}:{port} (workspace={workspace})")
    uvicorn.run(fastapi_app, host=host, port=port, log_level="warning")


def _install_auth_token(fastapi_app, token: str) -> None:
    from fastapi import Request
    from fastapi.responses import PlainTextResponse

    @fastapi_app.middleware("http")
    async def _auth(request: Request, call_next):
        if request.headers.get("X-Lodan-Token") != token:
            return PlainTextResponse("unauthorized", status_code=401)
        return await call_next(request)


@app.command("export")
def export_cmd(workspace: str) -> None:
    """Export scan data as JSONL."""
    _not_implemented("export")


@app.command("prune")
def prune_cmd(workspace: str) -> None:
    """Apply the workspace's [retention] policy."""
    _not_implemented("prune")


def main() -> None:
    app()


if __name__ == "__main__":
    sys.exit(main())
