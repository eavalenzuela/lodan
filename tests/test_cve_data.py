from __future__ import annotations

import asyncio
import json
from pathlib import Path

import httpx
import pytest

from lodan.enrich.cve_data import (
    CVERecord,
    connect,
    fetch_pages,
    load_state,
    parse_record,
    save_state,
    update,
    upsert,
)

_APACHE_VULN = {
    "cve": {
        "id": "CVE-2023-00001",
        "published": "2023-10-01T00:00:00.000",
        "lastModified": "2024-01-01T00:00:00.000",
        "metrics": {
            "cvssMetricV31": [{"cvssData": {"baseScore": 7.5}}],
            "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}],
        },
        "configurations": [
            {
                "nodes": [
                    {
                        "cpeMatch": [
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*",
                            },
                            {
                                "vulnerable": True,
                                "criteria": "cpe:2.3:a:apache:http_server:2.4.55:*:*:*:*:*:*:*",
                            },
                        ]
                    }
                ]
            }
        ],
    }
}


def test_parse_record_emits_one_row_per_cpe() -> None:
    rows = parse_record(_APACHE_VULN)
    assert len(rows) == 2
    assert {r.cpe.split(":")[5] for r in rows} == {"2.4.54", "2.4.55"}
    assert {r.cve for r in rows} == {"CVE-2023-00001"}


def test_parse_prefers_v31_cvss_over_v2() -> None:
    (row,) = parse_record(
        {
            "cve": {
                "id": "CVE-x",
                "metrics": {
                    "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}],
                    "cvssMetricV2": [{"cvssData": {"baseScore": 5.0}}],
                },
                "configurations": [
                    {"nodes": [{"cpeMatch": [{"vulnerable": True, "criteria": "cpe:x"}]}]}
                ],
            }
        }
    )
    assert row.cvss == 9.8


def test_parse_drops_non_vulnerable_entries() -> None:
    rows = parse_record(
        {
            "cve": {
                "id": "CVE-y",
                "metrics": {},
                "configurations": [
                    {
                        "nodes": [
                            {
                                "cpeMatch": [
                                    {"vulnerable": False, "criteria": "cpe:x"},
                                    {"vulnerable": True, "criteria": "cpe:y"},
                                ]
                            }
                        ]
                    }
                ],
            }
        }
    )
    assert [r.cpe for r in rows] == ["cpe:y"]


def test_parse_without_id_returns_empty() -> None:
    assert parse_record({"cve": {}}) == []


def test_upsert_is_idempotent(tmp_path: Path) -> None:
    conn = connect(tmp_path / "c.db")
    rows = [
        CVERecord("cpe:a", "CVE-1", 5.0, "2023", "2023"),
        CVERecord("cpe:a", "CVE-1", 9.0, "2023", "2024"),  # same PK, new cvss
        CVERecord("cpe:a", "CVE-2", 7.5, "2023", "2023"),
    ]
    upsert(conn, rows)
    got = conn.execute("SELECT cpe, cve, cvss FROM cve_cpe ORDER BY cve").fetchall()
    assert got == [("cpe:a", "CVE-1", 9.0), ("cpe:a", "CVE-2", 7.5)]


def test_state_round_trip(tmp_path: Path) -> None:
    p = tmp_path / "s.json"
    assert load_state(p) == {}
    save_state({"last_modified": "2026-04-24"}, p)
    assert load_state(p) == {"last_modified": "2026-04-24"}


def test_fetch_pages_paginates() -> None:
    pages = [
        {
            "resultsPerPage": 2000,
            "totalResults": 3000,
            "vulnerabilities": [{"cve": {"id": f"CVE-{i}"}} for i in range(2000)],
        },
        {
            "resultsPerPage": 1000,
            "totalResults": 3000,
            "vulnerabilities": [{"cve": {"id": f"CVE-{i}"}} for i in range(2000, 3000)],
        },
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        idx = int(request.url.params.get("startIndex", "0"))
        return httpx.Response(200, json=pages[0 if idx == 0 else 1])

    transport = httpx.MockTransport(handler)

    async def _run() -> list[dict]:
        async with httpx.AsyncClient(transport=transport) as client:
            return [p async for p in fetch_pages(client, {})]

    got = asyncio.run(_run())
    assert len(got) == 2


def test_update_writes_rows_and_state(tmp_path: Path) -> None:
    conn = connect(tmp_path / "c.db")
    state_path = tmp_path / "state.json"

    page = {
        "resultsPerPage": 1,
        "totalResults": 1,
        "vulnerabilities": [_APACHE_VULN],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=page)

    transport = httpx.MockTransport(handler)

    async def _run():
        async with httpx.AsyncClient(transport=transport) as client:
            return await update(conn, state_path=state_path, _client=client)

    stats = asyncio.run(_run())
    assert stats.pages == 1
    assert stats.cves_seen == 1
    assert stats.rows_upserted == 2  # two CPEs for the one CVE
    assert state_path.exists()
    saved = json.loads(state_path.read_text())
    assert "last_modified" in saved
    (count,) = conn.execute("SELECT COUNT(*) FROM cve_cpe").fetchone()
    assert count == 2


def test_update_passes_since_on_subsequent_runs(tmp_path: Path) -> None:
    conn = connect(tmp_path / "c.db")
    state_path = tmp_path / "state.json"
    save_state({"last_modified": "2026-01-01T00:00:00"}, state_path)

    seen_params: list[dict] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_params.append(dict(request.url.params))
        return httpx.Response(
            200,
            json={"resultsPerPage": 0, "totalResults": 0, "vulnerabilities": []},
        )

    transport = httpx.MockTransport(handler)

    async def _run():
        async with httpx.AsyncClient(transport=transport) as client:
            await update(conn, state_path=state_path, _client=client)

    asyncio.run(_run())
    assert seen_params, "expected at least one request"
    assert seen_params[0].get("lastModStartDate") == "2026-01-01T00:00:00"
    assert "lastModEndDate" in seen_params[0]


def test_cli_update_requires_flag(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("LODAN_HOME", str(tmp_path))
    from typer.testing import CliRunner

    from lodan.cli import app

    result = CliRunner().invoke(app, ["update"])
    assert result.exit_code == 1
    assert "--cves" in result.output
