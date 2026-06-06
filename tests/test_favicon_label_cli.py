from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from lodan.cli import app
from lodan.paths import workspace_db
from lodan.store import writer
from lodan.store.db import connect


@pytest.fixture
def workspace(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> str:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    result = CliRunner().invoke(app, ["init", "w", "--cidrs", "10.0.0.0/24"])
    assert result.exit_code == 0
    return "w"


def test_favicon_label_sets_label(workspace: str) -> None:
    result = CliRunner().invoke(
        app, ["favicon-label", workspace, "12345", "Jenkins login"]
    )
    assert result.exit_code == 0, result.output
    conn = connect(workspace_db(workspace))
    try:
        assert writer.favicon_label(conn, 12345) == "Jenkins login"
    finally:
        conn.close()


def test_favicon_label_unknown_workspace() -> None:
    result = CliRunner().invoke(app, ["favicon-label", "nope", "1", "x"])
    assert result.exit_code == 1
