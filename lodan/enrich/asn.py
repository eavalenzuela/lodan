"""ASN lookup via IP2Location LITE DB-ASN.

The LITE DB is free but requires a (no-charge) account to download. v1
expects the operator to drop `IP2LOCATION-LITE-ASN.BIN` into
`~/.lodan/data/ip2location/` manually; automated download is deferred.

`lookup` returns `(asn:int, asn_org:str) | None`. Any failure — missing
DB, unreadable record, unknown IP — returns None. Callers are expected
to degrade gracefully.
"""
from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from lodan.paths import ip2location_asn_bin


@dataclass(frozen=True)
class ASNRecord:
    asn: int | None
    asn_org: str | None


class ASNResolver:
    """Thin wrapper over IP2Location's Python binding.

    We keep the BIN file open for the life of the scan so per-IP lookups
    don't reopen it. IP2Location() is not async-aware; lookups are CPU-
    bound so they run inline.
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self._path = db_path or ip2location_asn_bin()
        self._db: Any = None

    @property
    def available(self) -> bool:
        return self._path.exists()

    def _open(self) -> Any:
        if self._db is None:
            import IP2Location  # type: ignore

            self._db = IP2Location.IP2Location(str(self._path))
        return self._db

    def lookup(self, ip: str) -> ASNRecord | None:
        if not self.available:
            return None
        try:
            db = self._open()
            rec = db.get_all(ip)
        except Exception:
            return None
        asn = _coerce_asn(getattr(rec, "asn", None))
        org = _coerce_org(getattr(rec, "as_name", None) or getattr(rec, "as", None))
        if asn is None and org is None:
            return None
        return ASNRecord(asn=asn, asn_org=org)


def _coerce_asn(value: Any) -> int | None:
    if value is None:
        return None
    try:
        n = int(value)
    except (TypeError, ValueError):
        return None
    return n if n > 0 else None


def _coerce_org(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    return s or None
