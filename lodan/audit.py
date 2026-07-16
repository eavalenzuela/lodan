"""Structured, append-only JSON audit log for scans.

PLAN.md mandates `structlog`: a JSON audit record per scan written to a
per-workspace `scan.log`, so every run is reconstructable after the fact —
what was in scope, which targets were authorized or refused, what the probes
found, and who ran it when.

The logger here is deliberately *self-contained per scan*: it does not call the
process-global ``structlog.configure()``. A scan builds one ``AuditLog`` bound
to its workspace's ``scan.log`` and closes it when done. Two scans in different
workspaces (the web UI can run them concurrently) therefore never share global
logging state or cross-contaminate each other's files. Each event renders to a
single JSON object on its own line (JSONL): append-only and trivially greppable.
"""
from __future__ import annotations

import getpass
import os
from pathlib import Path
from types import TracebackType
from typing import Any

import structlog


def operator() -> str:
    """Best-effort identity of whoever launched the scan, for the audit trail.

    ``$LODAN_OPERATOR`` wins so shared service accounts / cron jobs can name a
    real person or ticket; otherwise the OS login name. Never raises — some
    sandboxes have no resolvable login, and an audit logger must not be the
    thing that fails a scan, so it falls back to ``"unknown"``.
    """
    env = os.environ.get("LODAN_OPERATOR")
    if env and env.strip():
        return env.strip()
    try:
        return getpass.getuser()
    except Exception:
        return "unknown"


class AuditLog:
    """A per-scan JSON audit logger appending to one workspace ``scan.log``.

    Open it, emit events with :meth:`event`, and :meth:`close` it (or use it as
    a context manager) to flush and release the file handle. All events share
    the bound fields passed at construction (operator, workspace, scan_id).
    """

    def __init__(self, log_path: Path, **bound: Any) -> None:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        # Line-buffered append: each JSON line hits disk as it is written, so a
        # scan killed mid-run still leaves a readable, truncation-free trail.
        self._fh = log_path.open("a", encoding="utf-8", buffering=1)
        self._log = structlog.wrap_logger(
            structlog.PrintLogger(file=self._fh),
            processors=[
                structlog.processors.add_log_level,
                structlog.processors.TimeStamper(fmt="iso", utc=True),
                structlog.processors.JSONRenderer(sort_keys=True),
            ],
        ).bind(**bound)

    def event(self, event: str, **fields: Any) -> None:
        """Append one audit event. ``fields`` must be JSON-serializable."""
        self._log.info(event, **fields)

    def close(self) -> None:
        try:
            self._fh.flush()
        finally:
            self._fh.close()

    def __enter__(self) -> AuditLog:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()


class _NullAuditLog:
    """No-op audit log for callers that want to disable the trail (tests, or a
    scan run without a workspace directory). Same surface as :class:`AuditLog`."""

    def event(self, event: str, **fields: Any) -> None:  # noqa: D102
        pass

    def close(self) -> None:  # noqa: D102
        pass

    def __enter__(self) -> _NullAuditLog:
        return self

    def __exit__(self, *exc: object) -> None:
        pass


def open_scan_log(log_path: Path | None, **bound: Any) -> AuditLog | _NullAuditLog:
    """Open an :class:`AuditLog` at ``log_path``, or a no-op log if ``None``."""
    if log_path is None:
        return _NullAuditLog()
    return AuditLog(log_path, **bound)
