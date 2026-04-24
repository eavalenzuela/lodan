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
def update_cmd() -> None:
    """Refresh NVD + IP2Location snapshots under ~/.lodan/data/."""
    _not_implemented("update")


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
        f"{summary.authz_rejections} authz-rejected"
    )


@app.command("diff")
def diff_cmd(workspace: str) -> None:
    """Diff two scans within a workspace."""
    _not_implemented("diff")


@app.command("query")
def query_cmd(expression: str) -> None:
    """Run a mini-DSL query (sans:*.corp.example.com AND port:443)."""
    _not_implemented("query")


@app.command("serve")
def serve_cmd(workspace: str) -> None:
    """Serve the web UI for the given workspace."""
    _not_implemented("serve")


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
