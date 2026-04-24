"""Mini-DSL for pivot queries over services.

Grammar (all case-insensitive operators; bare tokens and quoted values):

    query   := term (WS (AND|OR) WS term)*
    term    := NOT? key ':' value
    key     := banner | tech | sans | port | service | ip
             | favicon_mmh3 | ja3 | ja3s | cve
    value   := bareword | '"' quoted '"' (may contain * as a wildcard)

Compiles to a parameterized SQL WHERE clause over the services table,
plus scan-scoped joins for cve. AND binds tighter than OR; no
parentheses in v1. Wildcards translate to SQL LIKE % for exact columns,
and to FTS5 prefix search for banner / tech / sans when possible.

`compile(expr) -> (sql, params)` returns the WHERE fragment only so the
caller can drop it into any SELECT against services.
"""
from __future__ import annotations

import re
import shlex
from dataclasses import dataclass
from typing import Any


class QueryError(ValueError):
    pass


_VALID_KEYS = {
    "banner", "tech", "sans",
    "port", "service", "ip",
    "favicon_mmh3", "ja3", "ja3s",
    "cve",
}
_FTS_KEYS = {"banner": "banner", "tech": "tech", "sans": "cert_sans"}
_LIKE_COLUMNS = {"banner": "banner", "tech": "tech", "sans": "cert_sans"}


@dataclass(frozen=True)
class Term:
    key: str
    value: str
    negated: bool


@dataclass(frozen=True)
class AndGroup:
    terms: list[Term]


@dataclass(frozen=True)
class OrQuery:
    groups: list[AndGroup]


def parse(expr: str) -> OrQuery:
    tokens = _tokenize(expr)
    if not tokens:
        raise QueryError("empty query")
    return _parse_or(tokens)


def compile(expr: str) -> tuple[str, list[Any]]:
    tree = parse(expr)
    return _emit(tree)


def _tokenize(expr: str) -> list[str]:
    """Shell-style split so quoted values stay together."""
    try:
        return shlex.split(expr, posix=True)
    except ValueError as e:
        raise QueryError(f"could not tokenize: {e}") from e


def _parse_or(tokens: list[str]) -> OrQuery:
    groups = [_parse_and(tokens)]
    while tokens and tokens[0].upper() == "OR":
        tokens.pop(0)
        groups.append(_parse_and(tokens))
    if tokens:
        raise QueryError(f"unexpected trailing token: {tokens[0]!r}")
    return OrQuery(groups=groups)


def _parse_and(tokens: list[str]) -> AndGroup:
    terms: list[Term] = []
    terms.append(_parse_term(tokens))
    while tokens and tokens[0].upper() != "OR":
        if tokens[0].upper() == "AND":
            tokens.pop(0)
        terms.append(_parse_term(tokens))
    return AndGroup(terms=terms)


def _parse_term(tokens: list[str]) -> Term:
    if not tokens:
        raise QueryError("expected term")
    negated = False
    if tokens[0].upper() == "NOT":
        negated = True
        tokens.pop(0)
        if not tokens:
            raise QueryError("NOT must be followed by a term")
    tok = tokens.pop(0)
    if ":" not in tok:
        raise QueryError(f"term must be key:value, got {tok!r}")
    key, _, value = tok.partition(":")
    key = key.strip().lower()
    value = value.strip()
    if key not in _VALID_KEYS:
        raise QueryError(f"unknown key: {key!r}")
    if not value:
        raise QueryError(f"{key}: needs a value")
    return Term(key=key, value=value, negated=negated)


def _emit(tree: OrQuery) -> tuple[str, list[Any]]:
    or_sqls: list[str] = []
    params: list[Any] = []
    for group in tree.groups:
        and_parts: list[str] = []
        for term in group.terms:
            sql, term_params = _emit_term(term)
            and_parts.append(sql)
            params.extend(term_params)
        or_sqls.append("(" + " AND ".join(and_parts) + ")")
    return " OR ".join(or_sqls), params


_INT_KEYS = {"port", "favicon_mmh3"}


def _emit_term(term: Term) -> tuple[str, list[Any]]:
    sql, params = _emit_positive(term.key, term.value)
    if term.negated:
        sql = f"NOT ({sql})"
    return sql, params


def _emit_positive(key: str, value: str) -> tuple[str, list[Any]]:
    if key in _INT_KEYS:
        if "*" in value:
            raise QueryError(f"{key} does not accept wildcards")
        try:
            n = int(value)
        except ValueError as e:
            raise QueryError(f"{key}: integer expected, got {value!r}") from e
        return (f"services.{key} = ?", [n])

    if key in _FTS_KEYS:
        return _emit_text(key, value)

    if key == "service":
        if "*" in value:
            return ("services.service LIKE ?", [value.replace("*", "%")])
        return ("services.service = ?", [value])

    if key == "ip":
        if "*" in value:
            return ("services.ip LIKE ?", [value.replace("*", "%")])
        return ("services.ip = ?", [value])

    if key in ("ja3", "ja3s"):
        return (f"services.{key} = ?", [value])

    if key == "cve":
        return (
            "(services.scan_id, services.ip, services.port) IN "
            "(SELECT scan_id, ip, port FROM vulns WHERE cve = ?)",
            [value],
        )

    raise QueryError(f"unhandled key: {key}")  # pragma: no cover


def _emit_text(key: str, value: str) -> tuple[str, list[Any]]:
    """banner / tech / sans: prefer FTS5 prefix search; fall back to LIKE
    when there's a leading wildcard (which FTS5 cannot handle)."""
    col = _LIKE_COLUMNS[key]
    if value.startswith("*"):
        like = value.replace("*", "%")
        if not like.endswith("%"):
            like = like + "%"
        return (f"COALESCE(services.{col},'') LIKE ?", [like])

    if "*" in value[:-1]:
        # interior wildcard — LIKE is the only option
        like = value.replace("*", "%")
        return (f"COALESCE(services.{col},'') LIKE ?", [like])

    fts_expr = _to_fts_prefix(value)
    return (
        f"services.rowid IN ("
        f"SELECT rowid FROM services_fts WHERE {col} MATCH ?)",
        [fts_expr],
    )


def _to_fts_prefix(value: str) -> str:
    # Trailing * becomes FTS5 prefix. Otherwise wrap the value in quotes so
    # special characters (dots, slashes) don't get reinterpreted by the
    # FTS5 query grammar.
    if value.endswith("*"):
        core = value[:-1]
        return f'"{_escape(core)}"*'
    return f'"{_escape(value)}"'


def _escape(s: str) -> str:
    return s.replace('"', '""')


SERVICE_COLUMNS = (
    "scan_id", "ip", "port", "proto", "service", "banner",
    "cert_fingerprint", "cert_sans", "ja3", "ja3s",
    "favicon_mmh3", "tech",
)
_VALID_COLS = set(SERVICE_COLUMNS)
_SAFE_NAME = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")


def run_query(
    conn,
    expr: str,
    *,
    scan_id: int | None = None,
    limit: int = 200,
) -> list[dict]:
    """Convenience: compile expr and execute against services.

    When scan_id is given the results are scoped to that scan; otherwise
    every scan in the workspace is searched.
    """
    where_sql, params = compile(expr)
    sql = f"SELECT {', '.join(SERVICE_COLUMNS)} FROM services WHERE {where_sql}"
    if scan_id is not None:
        sql += " AND services.scan_id = ?"
        params = params + [scan_id]
    sql += " ORDER BY services.scan_id DESC, services.ip, services.port LIMIT ?"
    params = params + [limit]
    rows = conn.execute(sql, params).fetchall()
    return [dict(zip(SERVICE_COLUMNS, r, strict=True)) for r in rows]
