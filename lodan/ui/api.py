"""JSON read API, versioned under /api/v1.

The HTML surface is HTMX-shaped — partial templates, form posts, redirects —
which a programmatic client cannot consume without scraping. This module is
the machine-readable half: the same rows, as JSON, for tools that want to do
something with a scan rather than look at one. It exists for the graph
integration (node_mapper turns hosts/services/CVEs into an investigation
graph), but nothing here is specific to that client.

Two properties hold by construction and are the reason this is a separate
module rather than more routes in app.py:

**Every endpoint is a SELECT.** Nothing here starts a scan, resolves a name,
or writes to the workspace. Adding scope is a deliberate operator act
performed through `lodan manage`; an integration that could widen scope on
demand would make `authorized_ranges` decorative, so the read API cannot.

**`authorized` is informational.** A host row exists only because the address
was authorized when it was scanned, and withholding stored rows from a client
that can read the DB anyway protects nothing. The flag answers a different
question — "could a future scan legitimately cover this address?" — which is
what a client needs in order to say "authorize it first" instead of "no data".
"""
# Like app.py, this module deliberately does NOT use
# `from __future__ import annotations`: FastAPI resolves handler signatures at
# registration time via get_type_hints(), which cannot see local aliases when
# every annotation is a forward-ref string.
import json
import sqlite3
from ipaddress import ip_address

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query

from lodan import domains as lodan_domains
from lodan.authz import authorized_networks, is_authorized
from lodan.config import Config
from lodan.paths import workspace_config

API_PREFIX = "/api/v1"

# Optional sections of a host response. Everything outside this set is a 400
# rather than a silent no-op, so a typo in `include` is not mistaken for an
# empty result.
HOST_INCLUDES = frozenset({"services", "vulns", "certs", "findings", "topology"})
DOMAIN_INCLUDES = frozenset({"subdomains"})
DEFAULT_HOST_INCLUDES = ("services", "vulns")


def register_api(app: FastAPI, workspace: str, db_dep) -> None:
    """Mount the JSON router onto an app built by `create_app`.

    `db_dep` is create_app's per-request connection dependency, passed in
    rather than rebuilt so both surfaces share one connection policy.
    """
    router = APIRouter(prefix=API_PREFIX, tags=["api"])

    @router.get("/scans")
    def list_scans(
        db: sqlite3.Connection = Depends(db_dep),  # noqa: B008
        limit: int = Query(20, ge=1, le=200),
    ) -> dict:
        """Recent scans, newest first — the ids the other endpoints accept."""
        rows = db.execute(
            "SELECT id, started_at, finished_at, status, cidrs FROM scans "
            "ORDER BY id DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return {
            "workspace": workspace,
            "scans": [
                {
                    "id": r[0],
                    "started_at": r[1],
                    "finished_at": r[2],
                    "status": r[3],
                    "cidrs": _json_list(r[4]),
                }
                for r in rows
            ],
        }

    @router.get("/host/{ip}")
    def host(
        ip: str,
        db: sqlite3.Connection = Depends(db_dep),  # noqa: B008
        scan: int | None = None,
        include: str = ",".join(DEFAULT_HOST_INCLUDES),
    ) -> dict:
        """Everything one scan knows about one address."""
        address = _valid_ip(ip)
        wanted = _parse_include(include, HOST_INCLUDES)
        scan_id = _resolve_scan(db, scan)

        from lodan.ui.app import _host_row  # see register_api's caller

        row = _host_row(db, scan_id, address)
        body = {
            "workspace": workspace,
            "scan_id": scan_id,
            "ip": address,
            "authorized": _authorized_address(workspace, address),
            "found": row is not None,
            "host": row,
        }
        if row is None:
            # In scope or not, this scan never saw it. Distinguishing that from
            # "no scans exist" (a 404) is the whole point of `found`.
            return body

        if "services" in wanted:
            body["services"] = _services(db, scan_id, address)
        if "vulns" in wanted:
            body["vulns"] = _vulns(db, scan_id, address)
        if "certs" in wanted:
            body["certs"] = _certs(db, scan_id, address)
        if "findings" in wanted:
            body["findings"] = _findings(db, scan_id, address)
        if "topology" in wanted:
            body["topology"] = {
                "nat_suspected": row["nat_suspected"],
                "min_backend_count": row["min_backend_count"],
                "backend_evidence": row["backend_evidence"],
                "clock_siblings": _clock_siblings(db, scan_id, address),
            }
        return body

    @router.get("/domain/{name}")
    def domain(
        name: str,
        db: sqlite3.Connection = Depends(db_dep),  # noqa: B008
        scan: int | None = None,
        include: str = "",
    ) -> dict:
        """What a scan resolved a name to, and what it refused to follow."""
        try:
            domain_name = lodan_domains.normalize_domain(name)
        except lodan_domains.DomainError as exc:
            raise HTTPException(400, detail=str(exc)) from None
        wanted = _parse_include(include, DOMAIN_INCLUDES)
        scan_id = _resolve_scan(db, scan)
        authorized_domains = _workspace_block(workspace).authorized_domains

        row = db.execute(
            "SELECT addresses, cnames, refused, error FROM domain_resolutions "
            "WHERE scan_id = ? AND domain = ?",
            (scan_id, domain_name),
        ).fetchone()

        addresses = _json_list(row[0]) if row else []
        body = {
            "workspace": workspace,
            "scan_id": scan_id,
            "domain": domain_name,
            "authorized": lodan_domains.is_within(domain_name, authorized_domains),
            "found": row is not None,
            # Stubs rather than full host bodies: a name can fan out to a lot of
            # addresses, and a client that wants detail asks /host per address.
            "addresses": [_address_stub(db, scan_id, a) for a in addresses],
            "cnames": _json_list(row[1]) if row else [],
            # Addresses deliberately NOT followed — a CNAME onto a domain the
            # workspace does not own. Worth surfacing: it names third-party
            # infrastructure the domain depends on.
            "refused": _json_list(row[2]) if row else [],
            "error": row[3] if row else None,
        }
        if "subdomains" in wanted:
            # From certificate SANs already collected. Enumerated, never
            # scanned: seeing a name is not permission to touch it.
            body["subdomains"] = lodan_domains.enumerate_subdomains(
                db, authorized_domains, scan_id=scan_id
            )
        return body

    app.include_router(router)


# --- request helpers --------------------------------------------------------

def _valid_ip(raw: str) -> str:
    try:
        return str(ip_address(raw.strip()))
    except ValueError:
        raise HTTPException(400, detail=f"not an IP address: {raw!r}") from None


def _parse_include(raw: str, allowed: frozenset) -> set:
    """Parse `include=a,b`. 'all' expands; an unknown name is a 400."""
    parts = {p.strip() for p in (raw or "").split(",") if p.strip()}
    if "all" in parts:
        return set(allowed)
    unknown = parts - allowed
    if unknown:
        raise HTTPException(
            400,
            detail=f"unknown include(s): {', '.join(sorted(unknown))} "
            f"(known: {', '.join(sorted(allowed))})",
        )
    return parts


def _resolve_scan(db: sqlite3.Connection, scan: int | None) -> int:
    from lodan.ui.app import _latest_scan_id

    scan_id = scan if scan is not None else _latest_scan_id(db)
    if scan_id is None:
        raise HTTPException(404, detail="no completed scans in this workspace")
    return scan_id


def _workspace_block(workspace: str):
    return Config.load(workspace_config(workspace)).workspace


def _authorized_address(workspace: str, address: str) -> bool:
    """Whether a future scan of this workspace could legitimately cover `address`.

    Domain-derived scope is deliberately not consulted: it is resolved per run
    and never persisted, so a name that pointed here last week does not
    authorize the address today.
    """
    return is_authorized(address, authorized_networks(_workspace_block(workspace)))


# --- row loaders ------------------------------------------------------------

def _json_list(raw) -> list:
    parsed = _json_obj(raw)
    return parsed if isinstance(parsed, list) else []


def _json_obj(raw):
    if not raw:
        return None
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return None


def _services(db: sqlite3.Connection, scan_id: int, ip: str) -> list[dict]:
    # `raw` is excluded on purpose: it is a per-probe blob that can run to
    # megabytes (full HTTP bodies, LDAP rootDSE dumps) and no graph client
    # wants it inline. `lodan export` remains the way to get it.
    rows = db.execute(
        "SELECT port, proto, service, banner, tech, cert_fingerprint, cert_sans, "
        "ja3, ja3s, ja4, ja4s, jarm, ssh_hostkey, favicon_mmh3, stack_sig, "
        "os_family, os_guess, clock_key, netbios_name, mac_oui, ike_vendor, "
        "amplification "
        "FROM services WHERE scan_id = ? AND ip = ? ORDER BY port, proto",
        (scan_id, ip),
    ).fetchall()
    return [
        {
            "port": r[0], "proto": r[1], "service": r[2], "banner": r[3],
            "tech": _json_list(r[4]), "cert_fingerprint": r[5],
            "cert_sans": _json_list(r[6]),
            "ja3": r[7], "ja3s": r[8], "ja4": r[9], "ja4s": r[10], "jarm": r[11],
            "ssh_hostkey": r[12], "favicon_mmh3": r[13], "stack_sig": r[14],
            "os_family": r[15], "os_guess": r[16], "clock_key": r[17],
            "netbios_name": r[18], "mac_oui": r[19], "ike_vendor": r[20],
            "amplification": r[21],
        }
        for r in rows
    ]


def _vulns(db: sqlite3.Connection, scan_id: int, ip: str) -> list[dict]:
    rows = db.execute(
        "SELECT port, cve, cpe, confidence, source, epss, epss_percentile, "
        "kev, kev_date_added, ransomware, priority "
        "FROM vulns WHERE scan_id = ? AND ip = ? ORDER BY port, cve",
        (scan_id, ip),
    ).fetchall()
    return [
        {
            "port": r[0], "cve": r[1], "cpe": r[2], "confidence": r[3], "source": r[4],
            "epss": r[5], "epss_percentile": r[6],
            "kev": bool(r[7]), "kev_date_added": r[8], "ransomware": bool(r[9]),
            "priority": r[10],
        }
        for r in rows
    ]


def _certs(db: sqlite3.Connection, scan_id: int, ip: str) -> list[dict]:
    # `der` is excluded: it is the raw certificate, useful for offline key
    # analysis inside lodan and pure weight over the wire.
    rows = db.execute(
        "SELECT port, position, sha256, subject, issuer, serial, key_type, "
        "key_bits, curve, sig_algo, not_before, not_after, is_ca, self_signed "
        "FROM chain_certs WHERE scan_id = ? AND ip = ? ORDER BY port, position",
        (scan_id, ip),
    ).fetchall()
    return [
        {
            "port": r[0], "position": r[1], "sha256": r[2], "subject": r[3],
            "issuer": r[4], "serial": r[5], "key_type": r[6], "key_bits": r[7],
            "curve": r[8], "sig_algo": r[9], "not_before": r[10],
            "not_after": r[11], "is_ca": bool(r[12]), "self_signed": bool(r[13]),
        }
        for r in rows
    ]


def _findings(db: sqlite3.Connection, scan_id: int, ip: str) -> list[dict]:
    rows = db.execute(
        "SELECT port, category, severity, title, detail FROM findings "
        "WHERE scan_id = ? AND ip = ? ORDER BY severity, category, port",
        (scan_id, ip),
    ).fetchall()
    return [
        {
            "port": r[0], "category": r[1], "severity": r[2], "title": r[3],
            "detail": _json_obj(r[4]),
        }
        for r in rows
    ]


def _clock_siblings(db: sqlite3.Connection, scan_id: int, ip: str) -> list[dict]:
    """Other addresses in this scan whose TCP-timestamp clock matches this one.

    A shared clock_key means the two addresses answered with the same boot-time
    estimate, which clusters them onto one physical machine. It is a strong
    hint and not a proof — the name says what was observed, and the caller
    decides how hard to draw the line.
    """
    rows = db.execute(
        "SELECT DISTINCT other.ip, other.clock_key "
        "FROM services mine JOIN services other "
        "  ON other.scan_id = mine.scan_id AND other.clock_key = mine.clock_key "
        "WHERE mine.scan_id = ? AND mine.ip = ? AND mine.clock_key IS NOT NULL "
        "  AND other.ip != mine.ip "
        "ORDER BY other.ip",
        (scan_id, ip),
    ).fetchall()
    return [{"ip": r[0], "clock_key": r[1]} for r in rows]


def _address_stub(db: sqlite3.Connection, scan_id: int, address) -> dict:
    """Minimal per-address record for a domain response."""
    ip = str(address)
    count = db.execute(
        "SELECT COUNT(*) FROM services WHERE scan_id = ? AND ip = ?", (scan_id, ip)
    ).fetchone()[0]
    return {"ip": ip, "found": count > 0, "service_count": count}
