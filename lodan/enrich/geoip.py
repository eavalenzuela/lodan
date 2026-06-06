"""Country lookup via IP2Location LITE DB1.

DB-ASN carries ASN/org only, so country needs the separate LITE DB1 file
(`IP2LOCATION-LITE-DB1.BIN`). `lodan update --ip2location --token <T>`
fetches both; operators can also drop the BIN in by hand.

`lookup(ip)` returns the 2-letter ISO country code, or None on any failure
(missing DB, unknown IP, IP2Location's "-" / "Not_Supported" sentinels).
Callers degrade gracefully — country is best-effort enrichment.
"""
from __future__ import annotations

from pathlib import Path
from typing import Any

from lodan.paths import ip2location_country_bin

# IP2Location returns these when it has no real answer for an address.
_SENTINELS = {"-", "", "Not_Supported", "Invalid IP address."}


class CountryResolver:
    """Thin wrapper over IP2Location's binding, kept open for the scan.

    Mirrors ASNResolver: lookups are CPU-bound so they run inline, and a
    missing DB just makes the resolver report unavailable.
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self._path = db_path or ip2location_country_bin()
        self._db: Any = None

    @property
    def available(self) -> bool:
        return self._path.exists()

    def _open(self) -> Any:
        if self._db is None:
            import IP2Location  # type: ignore

            self._db = IP2Location.IP2Location(str(self._path))
        return self._db

    def lookup(self, ip: str) -> str | None:
        if not self.available:
            return None
        try:
            rec = self._open().get_all(ip)
        except Exception:
            return None
        return _coerce_country(getattr(rec, "country_short", None))


def _coerce_country(value: Any) -> str | None:
    if value is None:
        return None
    s = str(value).strip()
    if s in _SENTINELS:
        return None
    return s or None
