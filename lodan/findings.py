"""Exposure / misconfiguration findings, derived from probe results.

Detection-only: nothing here talks to a host. Each detector is a pure function
over a probed service row — its `service` name and the structured `raw` blob the
probe already captured — and emits zero or more `Finding`s. This is the
"broaden the surfaced finding types" half of the coverage work: the probes see
*what* is running; the detectors label *what's wrong or exposed* about it.

Categories, roughly by what they flag:

- cleartext-admin   an administrative protocol exposed without encryption (telnet)
- no-tls            a protocol that offered no STARTTLS/SSL upgrade (smtp, ftp, db, ...)
- unauth-service    a data/management service reachable without authentication
- tls-cert          certificate problems (expired, expiring soon, self-signed)
- tls-version       a deprecated TLS protocol version negotiated or accepted
- tls-chain         chain-shape problems (out of order, no issuing chain)
- weak-crypto       deprecated signature hashes, weak accepted TLS ciphers,
                    key exchange without forward secrecy, or deprecated SSH
                    KEX/cipher/MAC/host-key algorithms still on offer
- weak-key          undersized or deprecated public keys, and ROCA-fingerprint
                    matches (written by enrich.keyposture, which also files
                    the ROCA CVE into `vulns`)
- http-headers      missing security headers (graded), permissive CORS, cookies
                    without Secure / HttpOnly / SameSite
- directory-listing an autoindex page is reachable
- default-page      a stock nginx / Apache / IIS install page is serving
- debug-page        a debugger, traceback or phpinfo() is reachable
- admin-open        an admin UI answered with its interface rather than a 401
- amplification     the service can be used as a DDoS reflector against others
- eol               software past its end-of-support date (enrich.risk)
"""
from __future__ import annotations

import contextlib
import json
import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
_EXPIRING_SOON = timedelta(days=30)


@dataclass(frozen=True)
class Finding:
    category: str
    severity: str
    title: str
    detail: dict[str, Any]


@dataclass(frozen=True)
class ServiceRow:
    ip: str
    port: int
    service: str | None
    banner: str | None
    raw: dict[str, Any]


# --- individual detectors: (row, now) -> list[Finding] ---------------------


def _cleartext_admin(row: ServiceRow, now: datetime) -> list[Finding]:
    if row.service == "telnet":
        return [Finding(
            "cleartext-admin", "high",
            "Telnet exposes remote administration in cleartext.",
            {"service": "telnet"},
        )]
    return []


_NO_TLS_SIGNALS = {
    # service -> (raw key that is False when TLS upgrade is absent, human protocol)
    "smtp": ("starttls", "SMTP"),
    "imap": ("starttls", "IMAP"),
    "pop3": ("stls", "POP3"),
    "ftp": ("auth_tls", "FTP"),
    "mysql": ("ssl", "MySQL"),
    "postgresql": ("ssl", "PostgreSQL"),
}


def _no_tls(row: ServiceRow, now: datetime) -> list[Finding]:
    spec = _NO_TLS_SIGNALS.get(row.service or "")
    if spec is None:
        return []
    key, proto = spec
    if row.raw.get(key) is False:
        return [Finding(
            "no-tls", "medium",
            f"{proto} offers no TLS upgrade — credentials and data cross the network in cleartext.",
            {"service": row.service},
        )]
    return []


def _unauth_service(row: ServiceRow, now: datetime) -> list[Finding]:
    svc = row.service
    banner = row.banner or ""
    # VNC advertising the "None" security type.
    if svc == "vnc" and row.raw.get("no_auth"):
        return [Finding("unauth-service", "high",
                        "VNC accepts connections with no authentication.", {"service": "vnc"})]
    # Elasticsearch answering cluster info on an unauthenticated GET /.
    if svc == "elasticsearch" and row.raw.get("unauthenticated"):
        return [Finding("unauth-service", "high",
                        "Elasticsearch is reachable without authentication.", {"service": "elasticsearch"})]
    # Redis returning INFO (parsed fields) means no AUTH was required.
    if svc == "redis" and "fields" in row.raw:
        return [Finding("unauth-service", "high",
                        "Redis served INFO without authentication.", {"service": "redis"})]
    # mongo / docker return real data (banner not prefixed with "<svc>:") only unauth.
    if svc in ("mongo", "docker") and not banner.startswith(f"{svc}:"):
        return [Finding("unauth-service", "high",
                        f"{svc} management/data interface reachable without authentication.",
                        {"service": svc})]
    return []


def _tls_findings(row: ServiceRow, now: datetime) -> list[Finding]:
    if row.service != "tls":
        return []
    out: list[Finding] = []
    version = row.raw.get("tls_version")
    if isinstance(version, int) and version < 0x0303:  # below TLS 1.2
        label = row.raw.get("tls_version_label") or f"0x{version:04x}"
        out.append(Finding("tls-version", "medium",
                           f"Server negotiated deprecated {label}.", {"tls_version": version}))

    not_after = _parse_dt(row.raw.get("cert_not_valid_after"))
    if not_after is not None:
        if not_after < now:
            out.append(Finding("tls-cert", "high", "TLS certificate has expired.",
                               {"not_after": row.raw.get("cert_not_valid_after")}))
        elif not_after < now + _EXPIRING_SOON:
            out.append(Finding("tls-cert", "low", "TLS certificate expires within 30 days.",
                               {"not_after": row.raw.get("cert_not_valid_after")}))

    subject = row.raw.get("cert_subject")
    issuer = row.raw.get("cert_issuer")
    if subject and issuer and subject == issuer:
        out.append(Finding("tls-cert", "low", "TLS certificate is self-signed.",
                           {"subject": subject}))
    return out


def _chain_findings(row: ServiceRow, now: datetime) -> list[Finding]:
    """Hygiene verdicts over the full certificate chain.

    Complements `_tls_findings`, which only ever saw the leaf. Note the
    deliberate omission: `san_mismatch` is computed and stored but never
    surfaced here — lodan dials by IP, so a name-based cert legitimately fails
    to cover the address, and reporting it would fire on almost every host.
    """
    hygiene = row.raw.get("chain_hygiene")
    if not isinstance(hygiene, dict):
        return []
    out: list[Finding] = []
    chain = row.raw.get("chain")
    depth = len(chain) if isinstance(chain, list) else None

    if hygiene.get("not_yet_valid"):
        out.append(Finding("tls-cert", "medium", "TLS certificate is not yet valid.",
                           {"chain_depth": depth}))
    if hygiene.get("out_of_order"):
        out.append(Finding("tls-chain", "low",
                           "TLS certificate chain is out of order or broken.",
                           {"chain_depth": depth}))
    if hygiene.get("incomplete_chain"):
        out.append(Finding("tls-chain", "low",
                           "Server sent a leaf certificate with no issuing chain.",
                           {"chain_depth": depth}))
    for reason in hygiene.get("weak_key") or ():
        out.append(Finding("weak-crypto", "high",
                           f"Weak certificate key: {reason}.", {"detail": reason}))
    for reason in hygiene.get("weak_signature") or ():
        out.append(Finding("weak-crypto", "medium",
                           f"Deprecated certificate signature hash: {reason}.",
                           {"detail": reason}))
    return out


def _tls_matrix_findings(row: ServiceRow, now: datetime) -> list[Finding]:
    """Posture verdicts from the protocol/cipher acceptance matrix."""
    matrix = row.raw.get("tls_matrix")
    if not isinstance(matrix, dict):
        return []
    out: list[Finding] = []
    for label in matrix.get("accepted_versions") or ():
        if label in ("TLS 1.0", "TLS 1.1"):
            out.append(Finding("tls-version", "medium",
                               f"Server still accepts deprecated {label}.",
                               {"version": label}))
    weak = matrix.get("weak_cipher")
    if weak:
        families = matrix.get("weak_families") or []
        severity = "high" if {"null", "export", "anon"} & set(families) else "medium"
        out.append(Finding("weak-crypto", severity,
                           f"Server accepts weak cipher suite {weak}.",
                           {"cipher": weak, "families": families}))
    if matrix.get("accepts_static_rsa"):
        out.append(Finding("weak-crypto", "low",
                           "Server accepts static-RSA key exchange (no forward secrecy).",
                           {}))
    return out


def _ssh_algorithm_findings(row: ServiceRow, now: datetime) -> list[Finding]:
    """Deprecated algorithms in the server's SSH_MSG_KEXINIT offer.

    This is where weak SSH crypto actually hides: a current OpenSSH version
    string tells you nothing about whether hmac-md5 is still on the menu.
    """
    if row.service != "ssh":
        return []
    weak = row.raw.get("weak_algorithms")
    if not isinstance(weak, list):
        return []
    out: list[Finding] = []
    for entry in weak:
        if not isinstance(entry, dict):
            continue
        algorithm = entry.get("algorithm")
        reason = entry.get("reason")
        severity = entry.get("severity") or "low"
        if severity not in SEVERITY_ORDER or not algorithm:
            continue
        out.append(Finding(
            "weak-crypto", severity,
            f"SSH offers deprecated {entry.get('category', 'algorithm')} "
            f"{algorithm} ({reason}).",
            {"category": entry.get("category"), "algorithm": algorithm},
        ))
    return out


def _headers_of(row: ServiceRow) -> dict[str, str] | None:
    """Lower-cased response headers, or None if the probe captured none.

    None and {} mean different things: no `headers` key at all is "we didn't
    get a response to grade", while an empty dict is a server that genuinely
    sent no headers — which is itself a failing grade, not a reason to skip.
    """
    headers = row.raw.get("headers")
    if not isinstance(headers, dict):
        return None
    return {str(k).lower(): v for k, v in headers.items() if isinstance(v, str)}


# Security headers, with the grade weight each one carries. Absence is what
# gets scored; a present-but-weak value is checked separately below.
_SECURITY_HEADERS = {
    "strict-transport-security": "HSTS",
    "content-security-policy": "CSP",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
    "referrer-policy": "Referrer-Policy",
}


def _http_header_findings(row: ServiceRow, now: datetime) -> list[Finding]:
    """Security-header grade, permissive CORS, and cookie attributes."""
    if row.service not in ("http", "https"):
        return []
    headers = _headers_of(row)
    if headers is None:
        return []
    out: list[Finding] = []

    missing = [label for key, label in _SECURITY_HEADERS.items() if key not in headers]
    if missing:
        # Graded rather than one finding per header: five separate rows for one
        # unhardened site is noise, and the grade is the actionable summary.
        grade = _header_grade(len(_SECURITY_HEADERS) - len(missing))
        severity = "medium" if grade in ("D", "F") else "low"
        out.append(Finding(
            "http-headers", severity,
            f"Missing security headers ({', '.join(missing)}) — grade {grade}.",
            {"missing": missing, "grade": grade},
        ))

    cors = headers.get("access-control-allow-origin")
    if cors == "*":
        credentials = headers.get("access-control-allow-credentials", "").lower()
        out.append(Finding(
            "http-headers",
            # Wildcard origin plus credentials is the combination browsers
            # refuse — a server sending both is misconfigured, not just lax.
            "high" if credentials == "true" else "low",
            "Permissive CORS policy (Access-Control-Allow-Origin: *"
            + (" with credentials)." if credentials == "true" else ")."),
            {"cors": cors, "credentials": credentials or None},
        ))

    for problem in _cookie_problems(row):
        out.append(Finding("http-headers", "low", problem, {}))
    return out


def _header_grade(present: int) -> str:
    return {5: "A", 4: "B", 3: "C", 2: "D", 1: "E"}.get(present, "F")


def _cookie_problems(row: ServiceRow) -> list[str]:
    raw_cookies = row.raw.get("set_cookie") or row.raw.get("cookies")
    cookies: list[str] = []
    if isinstance(raw_cookies, str):
        cookies = [raw_cookies]
    elif isinstance(raw_cookies, list):
        cookies = [c for c in raw_cookies if isinstance(c, str)]
    else:
        header = (_headers_of(row) or {}).get("set-cookie")
        if header:
            cookies = [header]
    out: list[str] = []
    for cookie in cookies:
        lowered = cookie.lower()
        name = cookie.split("=", 1)[0].strip()
        missing = [
            flag for flag, token in (
                ("Secure", "secure"), ("HttpOnly", "httponly"), ("SameSite", "samesite")
            )
            if token not in lowered
        ]
        if missing:
            out.append(f"Cookie {name!r} missing {', '.join(missing)}.")
    return out


# Body signatures for pages that should never be reachable in production.
_DEBUG_PAGES: tuple[tuple[str, str, str], ...] = (
    ("directory-listing", "high", r"<title>Index of /"),
    ("default-page", "low", r"Welcome to nginx!|Apache2 (Ubuntu|Debian) Default Page"),
    ("default-page", "low", r"IIS Windows Server|Test Page for the Apache HTTP Server"),
    ("debug-page", "high", r"Werkzeug Debugger|Django.*DEBUG = True|Traceback \(most recent"),
    ("debug-page", "high", r"phpinfo\(\)|<title>phpinfo"),
    ("debug-page", "medium", r"Whoops, looks like something went wrong|Symfony Exception"),
)

# Admin interfaces answering with their UI instead of a login/401.
_ADMIN_PAGES: tuple[tuple[str, str], ...] = (
    ("Grafana", r"grafana"),
    ("Jenkins", r"jenkins|Dashboard \[Jenkins\]"),
    ("phpMyAdmin", r"phpmyadmin"),
    ("Kibana", r"kibana"),
    ("Adminer", r"adminer"),
    ("Portainer", r"portainer"),
    ("Traefik dashboard", r"traefik"),
)


def _http_page_findings(row: ServiceRow, now: datetime) -> list[Finding]:
    """Directory listings, default/debug pages, and open admin panels.

    Pure post-hoc analysis of the single GET / body the HTTP probe already
    fetched — no additional request is made, and no login form is submitted.
    """
    if row.service not in ("http", "https"):
        return []
    body = row.raw.get("body")
    title = row.raw.get("title")
    status = row.raw.get("status")
    haystack = " ".join(
        part for part in (
            body if isinstance(body, str) else "",
            title if isinstance(title, str) else "",
        ) if part
    )
    if not haystack:
        return []
    out: list[Finding] = []
    for category, severity, pattern in _DEBUG_PAGES:
        if re.search(pattern, haystack, re.IGNORECASE):
            out.append(Finding(
                category, severity,
                f"Reachable {category.replace('-', ' ')} detected.",
                {"pattern": pattern},
            ))
            break   # one page can only be one kind of page

    # An admin UI is only "open" if it answered with the app rather than an
    # auth challenge. A 401/403 means the gate is doing its job.
    if isinstance(status, int) and status in (401, 403):
        return out
    for label, pattern in _ADMIN_PAGES:
        if re.search(pattern, haystack, re.IGNORECASE):
            out.append(Finding(
                "admin-open", "medium",
                f"{label} admin interface answered without authentication.",
                {"product": label, "status": status},
            ))
            break
    return out


def _amplification_findings(row: ServiceRow, now: datetime) -> list[Finding]:
    """A host of yours usable as a DDoS reflector against someone else."""
    amplification = row.raw.get("amplification")
    if not isinstance(amplification, int | float) or amplification < 5:
        return []
    return [Finding(
        "amplification",
        "high" if amplification >= 20 else "medium",
        f"{row.service or 'service'} amplifies {amplification}x — usable as a "
        f"reflector in a DDoS against third parties.",
        {"factor": amplification, "service": row.service},
    )]


def _snmp_findings(row: ServiceRow, now: datetime) -> list[Finding]:
    """Default-community SNMP is itself the misconfiguration."""
    if row.service != "snmp" or not row.raw.get("community_accepted"):
        return []
    return [Finding(
        "unauth-service", "high",
        "SNMP answers the default 'public' community — full device inventory "
        "readable without authentication.",
        {"community": row.raw.get("community_accepted"),
         "sys_descr": row.raw.get("sys_descr")},
    )]


def _ike_findings(row: ServiceRow, now: datetime) -> list[Finding]:
    if row.service != "ike":
        return []
    weak = row.raw.get("weak_transform")
    if not weak:
        return []
    return [Finding(
        "weak-crypto", "medium",
        f"VPN gateway accepted a weak IKE transform ({', '.join(weak)}).",
        {"transform": row.raw.get("selected_transform")},
    )]


def _ldap_findings(row: ServiceRow, now: datetime) -> list[Finding]:
    if row.service != "ldap" or not row.raw.get("rootdse"):
        return []
    return [Finding(
        "unauth-service", "low",
        "LDAP rootDSE readable anonymously (directory layout disclosed).",
        {"naming_contexts": row.raw.get("naming_contexts")},
    )]


_DETECTORS = (
    _cleartext_admin, _no_tls, _unauth_service, _tls_findings,
    _chain_findings, _tls_matrix_findings, _ssh_algorithm_findings,
    _http_header_findings, _http_page_findings, _amplification_findings,
    _snmp_findings, _ike_findings, _ldap_findings,
)


def _parse_dt(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def detect(row: ServiceRow, now: datetime) -> list[Finding]:
    out: list[Finding] = []
    for detector in _DETECTORS:
        out.extend(detector(row, now))
    return out


# --- persistence -----------------------------------------------------------


def _load_service_rows(conn: sqlite3.Connection, scan_id: int) -> list[ServiceRow]:
    rows: list[ServiceRow] = []
    for ip, port, service, banner, raw in conn.execute(
        "SELECT ip, port, service, banner, raw FROM services WHERE scan_id = ?", (scan_id,)
    ):
        parsed: Any = {}
        if raw is not None:
            text = raw.decode("utf-8", "replace") if isinstance(raw, (bytes, bytearray)) else raw
            with contextlib.suppress(ValueError, TypeError):
                parsed = json.loads(text)
        rows.append(ServiceRow(ip=ip, port=port, service=service, banner=banner,
                               raw=parsed if isinstance(parsed, dict) else {}))
    return rows


def run_findings(conn: sqlite3.Connection, scan_id: int, now: datetime | None = None) -> int:
    """Detect and store findings for `scan_id`. Returns the count written."""
    stamp = now or datetime.now(UTC)
    rows = _load_service_rows(conn, scan_id)
    to_insert: list[tuple] = []
    for row in rows:
        for f in detect(row, stamp):
            to_insert.append((scan_id, row.ip, row.port, f.category, f.severity,
                              f.title, json.dumps(f.detail, sort_keys=True)))
    if to_insert:
        conn.executemany(
            "INSERT INTO findings (scan_id, ip, port, category, severity, title, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            to_insert,
        )
    return len(to_insert)


_FINDING_COLS = ("ip", "port", "category", "severity", "title", "detail")


def iter_findings(
    conn: sqlite3.Connection,
    *,
    scan_id: int | None = None,
    severity: str | None = None,
    limit: int | None = None,
) -> list[dict]:
    sql = f"SELECT {', '.join(_FINDING_COLS)} FROM findings"
    clauses: list[str] = []
    params: list[object] = []
    if scan_id is not None:
        clauses.append("scan_id = ?")
        params.append(scan_id)
    if severity is not None:
        clauses.append("severity = ?")
        params.append(severity)
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    # Order by severity (high first), then location.
    sql += (
        " ORDER BY CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 "
        "WHEN 'low' THEN 2 ELSE 3 END, ip, port"
    )
    if limit is not None:
        sql += " LIMIT ?"
        params.append(limit)
    out = []
    for row in conn.execute(sql, params):
        rec = dict(zip(_FINDING_COLS, row, strict=True))
        detail = rec.get("detail")
        if isinstance(detail, (bytes, bytearray, str)):
            with contextlib.suppress(ValueError, TypeError):
                rec["detail"] = json.loads(detail)
        out.append(rec)
    return out
