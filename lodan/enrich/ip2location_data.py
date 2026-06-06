"""IP2Location LITE DB-ASN download.

The LITE database is free but gated behind a (no-charge) account token. The
download endpoint hands back a ZIP containing the .BIN plus a license/readme;
we extract just the BIN into `~/.lodan/data/ip2location/`.

Token sources, in order: the `--token` CLI option, then `$LODAN_IP2LOCATION_TOKEN`.
Without a token the CLI stays in status-only mode (see cli.update_cmd).

Two layers so the network path and the unzip path test independently:

    download_asn(token, dest=..., _client=...) -> Path   # hits the endpoint
    extract_bin(zip_bytes, dest)               -> Path   # pure, no I/O beyond dest
"""
from __future__ import annotations

import io
import os
import shutil
import zipfile
from pathlib import Path

import httpx

from lodan.paths import ip2location_asn_bin, ip2location_dir

# The LITE download endpoint. `file` is IP2Location's product code; DBASNLITEBIN
# is the IPv4 LITE DB-ASN binary.
IP2LOCATION_DOWNLOAD_URL = "https://www.ip2location.com/download/"
ASN_LITE_FILE_CODE = "DBASNLITEBIN"


class IP2LocationDownloadError(RuntimeError):
    """Raised when the endpoint returns something other than a usable ZIP."""


def token_from_env() -> str | None:
    tok = os.environ.get("LODAN_IP2LOCATION_TOKEN")
    return tok.strip() if tok and tok.strip() else None


async def download_asn(
    token: str,
    *,
    dest: Path | None = None,
    _client: httpx.AsyncClient | None = None,
) -> Path:
    """Fetch and unpack the LITE DB-ASN BIN. Returns the path written."""
    dest = dest or ip2location_asn_bin()
    dest.parent.mkdir(parents=True, exist_ok=True)

    client = _client or httpx.AsyncClient(timeout=300, follow_redirects=True)
    try:
        resp = await client.get(
            IP2LOCATION_DOWNLOAD_URL,
            params={"token": token, "file": ASN_LITE_FILE_CODE},
        )
        resp.raise_for_status()
        content = resp.content
    finally:
        if _client is None:
            await client.aclose()

    return extract_bin(content, dest)


def extract_bin(zip_bytes: bytes, dest: Path) -> Path:
    """Pull the single .BIN member out of the download ZIP into `dest`.

    On a bad token the endpoint replies 200 with a short plaintext error
    (e.g. "NO PERMISSION", "INVALID TOKEN") rather than a ZIP — surface that
    as a clear error instead of a cryptic BadZipFile.
    """
    if zip_bytes[:2] != b"PK":
        msg = zip_bytes[:200].decode("utf-8", "replace").strip() or "(empty response)"
        raise IP2LocationDownloadError(f"endpoint did not return a ZIP: {msg!r}")

    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as zf:
        member = _find_bin_member(zf)
        if member is None:
            names = ", ".join(zf.namelist()) or "(none)"
            raise IP2LocationDownloadError(f"no .BIN file inside ZIP; members: {names}")
        with zf.open(member) as src, open(dest, "wb") as out:
            shutil.copyfileobj(src, out)
    return dest


def _find_bin_member(zf: zipfile.ZipFile) -> str | None:
    for name in zf.namelist():
        if name.upper().endswith(".BIN"):
            return name
    return None


def bootstrap_dirs() -> None:
    ip2location_dir().mkdir(parents=True, exist_ok=True)
