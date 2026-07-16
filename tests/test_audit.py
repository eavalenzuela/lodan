"""Audit-log unit tests: JSONL shape, append-only, operator resolution."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from lodan import audit


def _lines(path: Path) -> list[dict]:
    return [json.loads(ln) for ln in path.read_text().splitlines() if ln.strip()]


def test_event_writes_one_json_line_with_bound_fields(tmp_path: Path) -> None:
    log = tmp_path / "scan.log"
    a = audit.AuditLog(log, operator="alice", workspace="w", scan_id=7)
    a.event("scan_started", cidrs=["10.0.0.0/24"], port_count=100)
    a.close()

    rows = _lines(log)
    assert len(rows) == 1
    ev = rows[0]
    assert ev["event"] == "scan_started"
    assert ev["operator"] == "alice"
    assert ev["workspace"] == "w"
    assert ev["scan_id"] == 7
    assert ev["cidrs"] == ["10.0.0.0/24"]
    assert ev["port_count"] == 100
    assert ev["level"] == "info"
    # Timestamp is ISO-8601 UTC (trailing Z), machine-parseable.
    assert ev["timestamp"].endswith("Z")


def test_log_is_append_only_across_reopens(tmp_path: Path) -> None:
    log = tmp_path / "scan.log"
    with audit.AuditLog(log, scan_id=1) as a:
        a.event("scan_started")
    with audit.AuditLog(log, scan_id=2) as a:
        a.event("scan_started")

    rows = _lines(log)
    assert [r["scan_id"] for r in rows] == [1, 2]


def test_creates_parent_directory(tmp_path: Path) -> None:
    log = tmp_path / "nested" / "workspace" / "scan.log"
    with audit.AuditLog(log) as a:
        a.event("scan_started")
    assert log.exists()


def test_operator_prefers_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LODAN_OPERATOR", "  ops-ticket-42  ")
    assert audit.operator() == "ops-ticket-42"


def test_operator_falls_back_to_login(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LODAN_OPERATOR", raising=False)
    monkeypatch.setattr(audit.getpass, "getuser", lambda: "loginname")
    assert audit.operator() == "loginname"


def test_operator_never_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LODAN_OPERATOR", raising=False)

    def _boom() -> str:
        raise OSError("no login")

    monkeypatch.setattr(audit.getpass, "getuser", _boom)
    assert audit.operator() == "unknown"


def test_null_log_is_noop(tmp_path: Path) -> None:
    a = audit.open_scan_log(None, operator="x")
    a.event("scan_started", anything=1)
    a.close()  # must not raise
