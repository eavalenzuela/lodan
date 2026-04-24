# lodan

Local Shodan. Point it at a CIDR you own, get a Shodan-style report —
offline, free, with diff-over-time as the killer feature.

See [PLAN.md](PLAN.md) for the full design and decision log.

## Status

Feature-complete against PLAN.md's M1–M8 plus the JA3/JA3S follow-up
(M9). 300+ tests, ruff-clean. The pieces below all work end-to-end:

- Port discovery via masscan / naabu / scapy (auto-pick).
- 10 protocol probes: TLS (with JA3/JA3S), HTTP (headers, title, favicon
  mmh3, tech fingerprinting), SSH (banner + host keys), SMB (SMB2
  NEGOTIATE), RDP (X.224 NEG_REQ), MQTT, Redis, MongoDB, Docker,
  Kubernetes. All detection-only — no credentials, no auth attempts.
- Offline enrichment: rDNS, ASN/GeoIP via IP2Location LITE, CVE matching
  against the NVD 2.0 snapshot.
- Scan-to-scan diff: `new_service`, `gone_service`, `changed`,
  `new_cert` (workspace-scoped), `new_host`; auto-computed after every
  scan.
- FTS5-backed mini-DSL: `port:443 AND sans:*.corp.example.com`,
  `tech:nginx OR tech:apache`, `banner:OpenSSH*`, with the full
  grammar documented under [Query DSL](#query-dsl).
- Web UI (FastAPI + HTMX, no JS framework, no build step): dashboard,
  hosts / services tables with filtering, pivot views
  (cert / favicon / JA3S / SAN), diff timeline + detail, DSL query box.

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

# Optional — drop IP2Location LITE DB-ASN into ~/.lodan/data/ip2location/
# if you want ASN / org on hosts.
lodan update --ip2location

# Run a scan. Produces services / hosts / vulns / scan_diffs rows.
lodan scan home-lab

# Pivot queries.
lodan query home-lab "port:443 AND sans:*.corp.example.com"
lodan query home-lab "tech:nginx OR tech:apache" --json

# Diff.
lodan diff home-lab                  # prev -> latest by default
lodan diff home-lab --from 3 --to 7
lodan diff home-lab --from 2026-04-17 --to latest

# Browse.
lodan serve home-lab                 # http://127.0.0.1:8765

# Export and prune.
lodan export home-lab --include services,hosts --output scan.jsonl
lodan prune home-lab --dry-run
```

## CLI surface

| Command | Purpose |
|---|---|
| `lodan init <ws> --cidrs …`    | create workspace, bootstrap SQLite schema |
| `lodan update --cves`           | NVD 2.0 snapshot refresh (incremental) |
| `lodan update --ip2location`    | IP2Location LITE DB-ASN status / instructions |
| `lodan scan <ws>`               | discover + probe + enrich + auto-diff |
| `lodan query <ws> "expr"`       | run a mini-DSL query; `--json` for JSONL |
| `lodan diff <ws>`               | scan-to-scan diff; `--from`/`--to` accept id / `prev` / `latest` / ISO date |
| `lodan serve <ws>`              | FastAPI UI; localhost-only unless `--auth-token` |
| `lodan export <ws>`             | JSONL or JSON array dump; `--include`, `--scan`, `--output` |
| `lodan prune <ws>`              | apply `[retention]` from config; `--dry-run` |

## Query DSL

```
query   := term (WS (AND|OR) WS term)*
term    := NOT? key ':' value
key     := banner | tech | sans | port | service | ip
         | favicon_mmh3 | ja3 | ja3s | cve
value   := bareword | "quoted string" (may contain * as a wildcard)
```

- `banner`, `tech`, `sans` go through FTS5 when the wildcard is trailing
  (or absent); leading/interior wildcards fall back to SQL `LIKE`.
- `port` and `favicon_mmh3` require integers and reject wildcards.
- `cve:CVE-2023-1234` joins through the `vulns` table on
  `(scan_id, ip, port)`.
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
    ip2location/…              # operator-dropped LITE BIN
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

## Known deferred items

- **IP2Location LITE auto-download** — the LITE DB-ASN download needs
  a free-account token; `lodan update --ip2location` currently reports
  BIN presence and points at the manual-download URL. PRs welcome.
- **uvt NVD snapshot share** — lodan owns `~/.lodan/data/nvd/` as the
  canonical path; the symlink to / from `uvt_universal_vuln_tracker`
  is a docs task once uvt's layout is pinned.
- **JA4 / JA4S** — the raw-handshake plumbing is already in place; a
  JA4 pass can build on the same ClientHello / ServerHello parser.

## Contributing

- `pytest` keeps the test suite green (300+ tests, most parser-only and
  offline).
- `ruff check .` is the lint gate; matches what CI runs.
- Follow the feature-sized commit style visible in `git log` — one
  logical change per commit with a message that says *why* alongside
  *what*.
