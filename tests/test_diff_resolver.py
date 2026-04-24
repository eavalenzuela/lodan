from __future__ import annotations

from pathlib import Path

import pytest

from lodan.diff.resolver import ResolveError, previous_completed, resolve
from lodan.store import writer
from lodan.store.db import bootstrap, connect


@pytest.fixture
def db(tmp_path: Path):
    dbp = tmp_path / "l.db"
    bootstrap(dbp)
    conn = connect(dbp)
    yield conn
    conn.close()


def _make_scans(conn, count: int, *, mark_last_running: bool = False) -> list[int]:
    ids = []
    for i in range(count):
        h = writer.open_scan(conn, "w", ["10.0.0.0/24"])
        ids.append(h.scan_id)
        if i == count - 1 and mark_last_running:
            continue
        writer.finish_scan(conn, h)
    return ids


def test_resolve_integer(db) -> None:
    [a, b] = _make_scans(db, 2)
    assert resolve(db, str(a)) == a
    assert resolve(db, str(b)) == b


def test_resolve_unknown_integer_raises(db) -> None:
    _make_scans(db, 1)
    with pytest.raises(ResolveError):
        resolve(db, "999")


def test_resolve_latest_and_prev(db) -> None:
    [a, b, c] = _make_scans(db, 3)
    assert resolve(db, "latest") == c
    assert resolve(db, "prev") == b


def test_resolve_skips_non_completed(db) -> None:
    # Three scans, the newest still 'running' → latest should be the second newest.
    [a, b, c] = _make_scans(db, 3, mark_last_running=True)
    assert resolve(db, "latest") == b
    assert resolve(db, "prev") == a


def test_resolve_by_iso_date(db) -> None:
    # Insert two scans with hand-controlled started_at timestamps.
    db.execute(
        "INSERT INTO scans (id, started_at, cidrs, workspace, status) VALUES (?, ?, '[]', 'w', 'completed')",
        (1, "2026-04-10T12:00:00"),
    )
    db.execute(
        "INSERT INTO scans (id, started_at, cidrs, workspace, status) VALUES (?, ?, '[]', 'w', 'completed')",
        (2, "2026-04-20T12:00:00"),
    )
    assert resolve(db, "2026-04-20") == 2
    assert resolve(db, "2026-04-15") == 1


def test_resolve_iso_no_match(db) -> None:
    _make_scans(db, 1)
    with pytest.raises(ResolveError):
        resolve(db, "1900-01-01")


def test_resolve_garbage_raises(db) -> None:
    _make_scans(db, 1)
    with pytest.raises(ResolveError):
        resolve(db, "yesterday")


def test_previous_completed_skips_running(db) -> None:
    [a, b, c] = _make_scans(db, 3, mark_last_running=True)
    # c is running; previous_completed(c) should be b.
    assert previous_completed(db, c) == b
    assert previous_completed(db, b) == a
    assert previous_completed(db, a) is None
