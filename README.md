# lodan

Local Shodan. Point it at a CIDR you own, get a Shodan-style report —
offline, free, with diff-over-time as the killer feature.

See [PLAN.md](PLAN.md) for the full design and decision log.

## Status

Feature-complete against PLAN.md's M1–M8 plus the JA3/JA3S and JA4/JA4S
follow-ups (M9). 320+ tests, ruff-clean. The pieces below all work
end-to-end:

- Port discovery via masscan / naabu / scapy (auto-pick).
- 14 protocol probes: TLS (with JA3/JA3S and JA4/JA4S), HTTP (headers,
  title, favicon mmh3, tech fingerprinting), SSH (banner + host keys),
  SMB (SMB2 NEGOTIATE), RDP (X.224 NEG_REQ), MQTT, Redis, MongoDB,
  Elasticsearch, DNS, FTP, SMTP, Docker, Kubernetes. All
  detection-only — no credentials, no auth attempts.
- Offline enrichment: rDNS, ASN/org + country via IP2Location LITE
  (token-based auto-download of both DB-ASN and DB1), CVE matching
  against the NVD 2.0 snapshot.
- Scan-to-scan diff: `new_service`, `gone_service`, `changed`,
  `new_cert` (workspace-scoped), `new_host`; auto-computed after every
  scan.
- FTS5-backed mini-DSL: `port:443 AND sans:*.corp.example.com`,
  `tech:nginx OR tech:apache`, `banner:OpenSSH*`, with the full
  grammar documented under [Query DSL](#query-dsl).
- Web UI (FastAPI + HTMX, no JS framework, no build step): dashboard,
  hosts / services tables with filtering, pivot views
  (cert / favicon / JA3S / JA4S / SSH host-key / SAN), operator-labelled
  favicons, diff timeline + detail, DSL query box.
- In-browser management (`/manage`): add/remove authorized ranges, edit
  scan + enrichment + retention settings, set the cloud-provider policy,
  label favicons, and launch a scan with live status — all sharing the same
  authz guards as the CLI. Gate it off with `serve --read-only` to hand a
  viewer a browse-only instance.

See [SCANNING_FEATURES.md](SCANNING_FEATURES.md) for the next round of
core-scanning capabilities on the roadmap (passive stack fingerprinting,
TLS/SSH crypto-posture audits, UDP probe fleet, exposure findings, …).

## Install

```
python3.12 -m venv .venv
.venv/bin/pip install -e ".[dev]"
.venv/bin/lodan --version
```

Runtime-only install (no dev tools):

```
pip install -e .
```

## Quick start

```
# Declare a workspace and the CIDRs you're authorized to scan.
lodan init home-lab --cidrs 10.0.0.0/24,192.168.1.0/24

# Pull the NVD snapshot into ~/.lodan/data/nvd/cve.db. Idempotent;
# subsequent runs are incremental via lastModStartDate.
lodan update --cves

# Optional — pull IP2Location LITE DB-ASN (ASN/org) and DB1 (country) with
# a free account token for host enrichment. Token also read from
# $LODAN_IP2LOCATION_TOKEN. Without a token this just reports BIN presence
# + manual-download instructions.
lodan update --ip2location --token <YOUR_TOKEN>

# Run a scan. Produces services / hosts / vulns / scan_diffs rows.
lodan scan home-lab

# Pivot queries.
lodan query home-lab "port:443 AND sans:*.corp.example.com"
lodan query home-lab "tech:nginx OR tech:apache" --json
lodan query home-lab "hostkey:<sha256>"        # rogue-rebuild pivot

# Tag a favicon hash so the pivot views show a human label.
lodan favicon-label home-lab -1234567890 "Jenkins login"

# Diff.
lodan diff home-lab                  # prev -> latest by default
lodan diff home-lab --from 3 --to 7
lodan diff home-lab --from 2026-04-17 --to latest

# Browse + manage (add ranges, tweak settings, launch scans at /manage).
lodan serve home-lab                 # http://127.0.0.1:8765
lodan serve home-lab --read-only     # browse-only; management disabled

# Export and prune.
lodan export home-lab --include services,hosts --output scan.jsonl
lodan prune home-lab --dry-run
```

## CLI surface

| Command | Purpose |
|---|---|
| `lodan init <ws> --cidrs …`    | create workspace, bootstrap SQLite schema |
| `lodan update --cves`           | NVD 2.0 snapshot refresh (incremental) |
| `lodan update --ip2location [--token T]` | download IP2Location LITE DB-ASN + DB1 (with token) or report status |
| `lodan scan <ws>`               | discover + probe + enrich + auto-diff |
| `lodan query <ws> "expr"`       | run a mini-DSL query; `--json` for JSONL |
| `lodan diff <ws>`               | scan-to-scan diff; `--from`/`--to` accept id / `prev` / `latest` / ISO date |
| `lodan serve <ws>`              | FastAPI UI + management; localhost-only unless `--auth-token`; `--read-only` for a browse-only instance |
| `lodan export <ws>`             | JSONL or JSON array dump; `--include`, `--scan`, `--output` |
| `lodan prune <ws>`              | apply `[retention]` from config; `--dry-run` |
| `lodan favicon-label <ws> <mmh3> "<label>"` | tag a favicon hash for the pivot views |

## Query DSL

```
query   := term (WS (AND|OR) WS term)*
term    := NOT? key ':' value
key     := banner | tech | sans | port | service | ip
         | favicon_mmh3 | ja3 | ja3s | ja4 | ja4s | hostkey | cve
value   := bareword | "quoted string" (may contain * as a wildcard)
```

- `banner`, `tech`, `sans` go through FTS5 when the wildcard is trailing
  (or absent); leading/interior wildcards fall back to SQL `LIKE`.
- `port` and `favicon_mmh3` require integers and reject wildcards.
- `cve:CVE-2023-1234` joins through the `vulns` table on
  `(scan_id, ip, port)`.
- `hostkey:<sha256>` matches the server's default SSH host key — the
  "find every host presenting this key" / rogue-rebuild pivot.
- Operators are case-insensitive. AND binds tighter than OR; adjacent
  terms without an operator are implicit AND. No parentheses in v1.

Examples:

```
port:443 AND sans:*.corp.example.com
tech:nginx OR tech:apache
banner:OpenSSH* AND NOT service:http
favicon_mmh3:-1234567890
ip:10.0.0.*
```

## Workspace layout on disk

```
~/.lodan/
  data/
    nvd/cve.db                 # shared CVE store (workspace-agnostic)
    ip2location/                # LITE BINs (DB-ASN + DB1 country)
  workspaces/<name>/
    config.toml                # authorized_ranges + knobs
    lodan.db                   # one DB per workspace (portable)
    scan.log
```

## Scan what you own

lodan is reconnaissance, not attack tooling, and it is only for ranges
you operate. Every workspace's `config.toml` declares an
`authorized_ranges` allowlist; the scanner refuses targets outside it,
both at config load and per-batch during the scan loop.

Well-known public cloud prefixes (AWS, GCP, Azure, OCI, DigitalOcean)
are blocked unless the workspace flips `cloud_provider_allowed = true`
*and* fills in a non-empty `cloud_provider_justification`, which is
copied into the scan row's metadata for audit.

Every probe is strictly detection-only:

- No credentials sent. Ever.
- No SSH login, no SMB session setup, no RDP Cookie: mstshash, no
  MQTT Username/Password, no Redis AUTH, no Docker container listing,
  no Kubernetes pod listing.
- A deliberately-empty HTTP `GET /` and `GET /favicon.ico` with a
  `User-Agent: lodan/<version>` header is the maximum active behavior
  against a web endpoint.

The web UI binds to `127.0.0.1` by default. Non-loopback binds require
`--auth-token`, which the UI then checks against the `X-Lodan-Token`
header on every request.

The management endpoints (add/remove scope, edit settings, launch a scan,
label favicons) sit behind the same posture, plus two guards of their own:

- **Read-only mode.** `lodan serve <ws> --read-only` disables every mutation
  endpoint (they return `403`) and hides the write forms, so a workspace can
  be shared browse-only.
- **Host-pinned writes.** On the default loopback bind, mutation requests must
  carry a loopback `Host` header (and any `Origin` must match), so a malicious
  page — even one using DNS rebinding to `127.0.0.1` — can't drive a scan or
  edit scope through your browser. Non-loopback binds rely on `--auth-token`
  instead, which gates every request.
- **Authz still owns scanning.** Adding a range only edits `authorized_ranges`;
  the cloud-prefix guard and the per-target allowlist still run at scan time,
  so nothing added through the UI is scanned unless it also clears authz.

## uvt NVD snapshot share

lodan owns `~/.lodan/data/nvd/cve.db` as the canonical bulk NVD CPE
snapshot. The sibling `uvt_universal_vuln_tracker` project does **not**
maintain an equivalent snapshot file: it queries the NVD 2.0 REST API
per-CVE on demand and stores normalized results in its own application
DB (`instance/uvt.db`). There is therefore nothing to symlink between
the two today.

If uvt later grows a bulk-feed plugin that wants lodan's snapshot, point
it at the canonical path (read-only):

```
ln -s ~/.lodan/data/nvd/cve.db /path/to/uvt/instance/nvd-cve.db
```

lodan never reads from uvt, so the link is always lodan → uvt.

## Known deferred items

- **IP2Location LITE IPv6** — `lodan update --ip2location --token <T>`
  fetches the IPv4 LITE DB-ASN (`DBASNLITEBIN`). The IPv6 variant isn't
  wired since v1 is IPv4-only.

## Contributing

- `pytest` keeps the test suite green (320+ tests, most parser-only and
  offline). The Docker-backed integration tests under `tests/docker/`
  are opt-in — they spin up nginx (plain + TLS), Redis, MongoDB and
  OpenSSH on loopback and drive the real probes against them:

  ```
  LODAN_DOCKER_TESTS=1 pytest tests/docker/        # needs docker + compose
  ```

  Without that env var they skip, so the default run stays fully offline.
- `ruff check .` is the lint gate; matches what CI runs.
- Follow the feature-sized commit style visible in `git log` — one
  logical change per commit with a message that says *why* alongside
  *what*.
