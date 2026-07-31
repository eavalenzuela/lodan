"""Authorized-domain scope: resolution, CNAME containment, subdomain listing.

A domain is a *convenient way to name targets you own*, and it grants scope
under three deliberate constraints:

1. **Run-scoped only.** Resolved addresses authorize targets for the scan that
   resolved them and are never written back into `authorized_ranges`. Next
   scan re-resolves; nothing accumulates in the permanent allowlist, so a
   record that pointed somewhere last week does not still authorize it today.

2. **A/AAAA only, no CNAME indirection.** If a name is a CNAME onto a domain
   you did not authorize, its addresses belong to that third party — a CDN, a
   SaaS tenant, someone else's load balancer. Those are refused and ledgered.
   A CNAME *within* your authorized domains is fine, because you asserted
   ownership of both ends.

3. **Subdomains are enumerated, never scanned.** They are listed for the
   operator from certificate SANs already collected, so you can see what
   exists and decide to authorize it explicitly. Discovering a name is not
   permission to touch it.
"""
from __future__ import annotations

import json
import re
import sqlite3
from dataclasses import dataclass, field
from ipaddress import ip_network

from lodan import dnsq

# RFC 1123 hostname, plus a leading wildcard so cert SANs parse.
_DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$"
)


class DomainError(ValueError):
    """An operator-supplied domain was rejected."""


def normalize_domain(raw: str) -> str:
    """Canonicalize an operator-supplied domain, or raise."""
    text = (raw or "").strip().lower().rstrip(".")
    if not text:
        raise DomainError("empty domain")
    if "://" in text or "/" in text:
        raise DomainError(f"expected a bare domain, got {raw!r}")
    if text.startswith("*."):
        raise DomainError(
            f"wildcard domains cannot be authorized directly: {raw!r} "
            "(authorize the concrete names you own)"
        )
    try:
        text = text.encode("idna").decode("ascii") if not text.isascii() else text
    except UnicodeError as e:
        raise DomainError(f"invalid internationalized domain {raw!r}: {e}") from None
    if not _DOMAIN_RE.match(text):
        raise DomainError(f"invalid domain {raw!r}")
    return text


def is_within(candidate: str, authorized: list[str]) -> bool:
    """Is `candidate` one of the authorized domains, or a subdomain of one?"""
    name = (candidate or "").strip().lower().rstrip(".")
    if not name:
        return False
    for domain in authorized:
        base = domain.strip().lower().rstrip(".")
        if not base:
            continue
        if name == base or name.endswith("." + base):
            return True
    return False


@dataclass
class DomainScope:
    """What one authorized domain contributed to a scan."""

    domain: str
    addresses: list[str] = field(default_factory=list)
    cnames: list[tuple[str, str]] = field(default_factory=list)
    refused: list[tuple[str, str]] = field(default_factory=list)   # (what, why)
    error: str | None = None

    @property
    def authorized(self) -> bool:
        return bool(self.addresses)

    def as_dict(self) -> dict:
        return {
            "domain": self.domain,
            "addresses": list(self.addresses),
            "cnames": [{"from": a, "to": b} for a, b in self.cnames],
            "refused": [{"target": a, "reason": b} for a, b in self.refused],
            "error": self.error,
        }


def evaluate(resolution: dnsq.Resolution, authorized: list[str]) -> DomainScope:
    """Turn a resolution into run-scoped addresses, applying the CNAME rule.

    Pure: no I/O, so the containment decision is testable on its own.
    """
    scope = DomainScope(domain=resolution.domain, error=resolution.error)
    out_of_scope = [
        target for target in resolution.cname_targets
        if not is_within(target, authorized)
    ]
    scope.cnames = list(resolution.cnames)
    if out_of_scope:
        # The addresses in this answer are reached through somebody else's
        # name, so they are somebody else's addresses. Refuse the whole thing
        # rather than trying to guess which records came from where.
        for target in out_of_scope:
            scope.refused.append(
                (target, "CNAME points outside the authorized domains")
            )
        return scope
    scope.addresses = list(resolution.addresses)
    return scope


async def resolve_scope(
    authorized_domains: list[str],
    *,
    timeout: float = 3.0,
    resolver=None,
) -> list[DomainScope]:
    """Resolve every authorized domain into run-scoped addresses."""
    resolve = resolver or dnsq.resolve
    scopes: list[DomainScope] = []
    for domain in authorized_domains:
        try:
            normalized = normalize_domain(domain)
        except DomainError as e:
            scopes.append(DomainScope(domain=domain, error=str(e)))
            continue
        resolution = await resolve(normalized, timeout=timeout)
        scopes.append(evaluate(resolution, authorized_domains))
    return scopes


def scope_networks(scopes: list[DomainScope]) -> list:
    """Host networks (/32, /128) for every authorized address."""
    nets = []
    for scope in scopes:
        for address in scope.addresses:
            suffix = "/128" if ":" in address else "/32"
            try:
                nets.append(ip_network(f"{address}{suffix}", strict=False))
            except ValueError:
                continue
    return nets


# --- persistence -------------------------------------------------------------


def record_resolutions(
    conn: sqlite3.Connection, scan_id: int, scopes: list[DomainScope]
) -> int:
    """Persist what each domain resolved to for this scan."""
    if not scopes:
        return 0
    conn.execute("DELETE FROM domain_resolutions WHERE scan_id = ?", (scan_id,))
    conn.executemany(
        "INSERT INTO domain_resolutions "
        "(scan_id, domain, addresses, cnames, refused, error) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [
            (
                scan_id, scope.domain,
                json.dumps(scope.addresses),
                json.dumps([{"from": a, "to": b} for a, b in scope.cnames]),
                json.dumps([{"target": a, "reason": b} for a, b in scope.refused]),
                scope.error,
            )
            for scope in scopes
        ],
    )
    return len(scopes)


def enumerate_subdomains(
    conn: sqlite3.Connection, authorized_domains: list[str], *, scan_id: int | None = None
) -> list[dict]:
    """Subdomains observed in collected certificate SANs.

    Offline by construction: these come from certificates hosts already
    presented during a scan, not from a wordlist or a third-party dataset.
    Listed so an operator can see what exists — they are explicitly NOT
    scanned, and nothing here feeds authorization.
    """
    if not authorized_domains:
        return []
    query = "SELECT ip, port, cert_sans FROM services WHERE cert_sans IS NOT NULL"
    params: list = []
    if scan_id is not None:
        query += " AND scan_id = ?"
        params.append(scan_id)

    found: dict[str, dict] = {}
    for ip, port, sans_json in conn.execute(query, params):
        try:
            sans = json.loads(sans_json)
        except (ValueError, TypeError):
            continue
        if not isinstance(sans, list):
            continue
        for san in sans:
            if not isinstance(san, str):
                continue
            name = san.strip().lower().lstrip("*.").rstrip(".")
            if not name or not is_within(name, authorized_domains):
                continue
            if name in authorized_domains:
                continue                 # the domain itself, not a subdomain
            entry = found.setdefault(
                name, {"subdomain": name, "seen_on": [], "wildcard": san.startswith("*.")}
            )
            location = f"{ip}:{port}"
            if location not in entry["seen_on"]:
                entry["seen_on"].append(location)
    return sorted(found.values(), key=lambda e: e["subdomain"])
