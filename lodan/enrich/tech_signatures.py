"""Hand-rolled tech fingerprint signatures.

Primary source for tech detection. Each signature matches on one or more
of: response headers (case-insensitive key + regex value), set-cookie
names, response body (regex). Any match contributes the signature's label
to the result set.

The webappanalyzer fork is loaded on top of this in a later commit; where
both fire, self-rolled wins so we aren't hostage to upstream relicensing.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass(frozen=True)
class TechSig:
    label: str
    header_patterns: tuple[tuple[str, re.Pattern[str]], ...] = ()
    body_patterns: tuple[re.Pattern[bytes], ...] = ()
    cookie_names: frozenset[str] = field(default_factory=frozenset)


def _h(name: str, pattern: str) -> tuple[str, re.Pattern[str]]:
    return (name.lower(), re.compile(pattern, re.IGNORECASE))


def _b(pattern: bytes) -> re.Pattern[bytes]:
    return re.compile(pattern, re.IGNORECASE)


SIGNATURES: tuple[TechSig, ...] = (
    TechSig("nginx", header_patterns=(_h("server", r"nginx(/\S+)?"),)),
    TechSig("apache", header_patterns=(_h("server", r"apache(/\S+)?"),)),
    TechSig("IIS", header_patterns=(_h("server", r"Microsoft-IIS/?\S*"),)),
    TechSig("caddy", header_patterns=(_h("server", r"Caddy"),)),
    TechSig("tomcat", header_patterns=(_h("server", r"Apache-Coyote|Tomcat"),)),
    TechSig("cloudflare", header_patterns=(_h("server", r"cloudflare"), _h("cf-ray", r".+"))),
    TechSig("haproxy", header_patterns=(_h("x-haproxy", r".+"),)),
    TechSig("traefik", header_patterns=(_h("x-traefik", r".+"),)),
    TechSig(
        "GitLab",
        header_patterns=(_h("x-gitlab-meta", r".+"),),
        body_patterns=(_b(rb"GitLab(\.com)?"),),
    ),
    TechSig(
        "Jenkins",
        header_patterns=(_h("x-jenkins", r".+"),),
        body_patterns=(_b(rb"<title>[^<]*Jenkins"),),
    ),
    TechSig(
        "Grafana",
        body_patterns=(_b(rb"<title>Grafana"), _b(rb"grafana-app")),
        cookie_names=frozenset({"grafana_session"}),
    ),
    TechSig(
        "WordPress",
        body_patterns=(_b(rb"/wp-(content|includes)/"), _b(rb"wp-emoji-release")),
    ),
    TechSig(
        "Drupal",
        header_patterns=(_h("x-generator", r"Drupal"),),
        body_patterns=(_b(rb'name="generator"[^>]*content="Drupal'),),
    ),
    TechSig(
        "phpMyAdmin",
        body_patterns=(_b(rb"phpMyAdmin"),),
        cookie_names=frozenset({"phpMyAdmin", "pma_lang"}),
    ),
    TechSig(
        "Keycloak",
        body_patterns=(_b(rb"<title>[^<]*Keycloak"),),
        cookie_names=frozenset({"KEYCLOAK_IDENTITY", "KC_RESTART"}),
    ),
    TechSig(
        "kubernetes-dashboard",
        body_patterns=(_b(rb"kubernetesDashboard"), _b(rb"<title>Kubernetes Dashboard")),
    ),
)


def match(headers: dict[str, str], body: bytes, set_cookie_names: set[str] | None = None) -> list[str]:
    """Return the labels of every signature that fires against the capture.

    Deterministic ordering: the iteration order of SIGNATURES.
    """
    cookie_names = {c.lower() for c in (set_cookie_names or set())}
    hits: list[str] = []
    lower_headers = {k.lower(): v for k, v in headers.items()}
    body_window = body[:131072]  # 128KB is plenty for title/generator/marker detection
    for sig in SIGNATURES:
        if _header_match(sig, lower_headers):
            hits.append(sig.label)
            continue
        if _body_match(sig, body_window):
            hits.append(sig.label)
            continue
        if sig.cookie_names and any(c.lower() in cookie_names for c in sig.cookie_names):
            hits.append(sig.label)
    return hits


def _header_match(sig: TechSig, headers: dict[str, str]) -> bool:
    for name, pat in sig.header_patterns:
        value = headers.get(name)
        if value is not None and pat.search(value):
            return True
    return False


def _body_match(sig: TechSig, body: bytes) -> bool:
    return any(pat.search(body) for pat in sig.body_patterns)
