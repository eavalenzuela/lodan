"""Tests for the IP2Location LITE DB-ASN download path.

The unzip logic is pure; the download path is exercised through an
httpx.MockTransport so no real account token or network is needed.
"""
from __future__ import annotations

import asyncio
import io
import zipfile
from pathlib import Path

import httpx
import pytest

from lodan.enrich.ip2location_data import (
    ASN_LITE_FILE_CODE,
    COUNTRY_LITE_FILE_CODE,
    IP2LocationDownloadError,
    download_asn,
    download_country,
    extract_bin,
    token_from_env,
)


def _zip_with(members: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        for name, data in members.items():
            zf.writestr(name, data)
    return buf.getvalue()


def test_extract_bin_pulls_the_bin_member(tmp_path: Path) -> None:
    payload = b"\x00BINARY-ASN-DB\x01"
    zip_bytes = _zip_with(
        {"README_LITE.TXT": b"license", "IP2LOCATION-LITE-ASN.BIN": payload}
    )
    dest = tmp_path / "out" / "IP2LOCATION-LITE-ASN.BIN"
    written = extract_bin(zip_bytes, dest)
    assert written == dest
    assert dest.read_bytes() == payload


def test_extract_bin_rejects_non_zip_with_error_text(tmp_path: Path) -> None:
    dest = tmp_path / "x.bin"
    with pytest.raises(IP2LocationDownloadError, match="NO PERMISSION"):
        extract_bin(b"NO PERMISSION", dest)
    assert not dest.exists()


def test_extract_bin_rejects_zip_without_bin(tmp_path: Path) -> None:
    zip_bytes = _zip_with({"README.TXT": b"nope"})
    with pytest.raises(IP2LocationDownloadError, match="no .BIN"):
        extract_bin(zip_bytes, tmp_path / "x.bin")


def test_download_asn_writes_bin(tmp_path: Path) -> None:
    payload = b"ASN-DB-CONTENTS"
    zip_bytes = _zip_with({"IP2LOCATION-LITE-ASN.BIN": payload})
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["file"] = request.url.params.get("file")
        seen["token"] = request.url.params.get("token")
        return httpx.Response(200, content=zip_bytes)

    transport = httpx.MockTransport(handler)
    dest = tmp_path / "IP2LOCATION-LITE-ASN.BIN"

    async def run() -> Path:
        async with httpx.AsyncClient(transport=transport) as client:
            return await download_asn("tok123", dest=dest, _client=client)

    written = asyncio.run(run())
    assert written == dest
    assert dest.read_bytes() == payload
    assert seen == {"file": ASN_LITE_FILE_CODE, "token": "tok123"}


def test_download_country_uses_db1_file_code(tmp_path: Path) -> None:
    payload = b"COUNTRY-DB"
    zip_bytes = _zip_with({"IP2LOCATION-LITE-DB1.BIN": payload})
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["file"] = request.url.params.get("file")
        return httpx.Response(200, content=zip_bytes)

    transport = httpx.MockTransport(handler)
    dest = tmp_path / "IP2LOCATION-LITE-DB1.BIN"

    async def run() -> Path:
        async with httpx.AsyncClient(transport=transport) as client:
            return await download_country("tok", dest=dest, _client=client)

    written = asyncio.run(run())
    assert written.read_bytes() == payload
    assert seen["file"] == COUNTRY_LITE_FILE_CODE


def test_download_asn_surfaces_bad_token(tmp_path: Path) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b"INVALID TOKEN")

    transport = httpx.MockTransport(handler)

    async def run() -> None:
        async with httpx.AsyncClient(transport=transport) as client:
            await download_asn("bad", dest=tmp_path / "x.bin", _client=client)

    with pytest.raises(IP2LocationDownloadError, match="INVALID TOKEN"):
        asyncio.run(run())


def test_token_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("LODAN_IP2LOCATION_TOKEN", raising=False)
    assert token_from_env() is None
    monkeypatch.setenv("LODAN_IP2LOCATION_TOKEN", "  abc  ")
    assert token_from_env() == "abc"
