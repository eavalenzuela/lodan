# lodan

Local Shodan. Point it at a CIDR you own, get a Shodan-style report —
offline, free, with diff-over-time as the killer feature.

See [PLAN.md](PLAN.md) for the full design and decision log.

## Status

Feature-complete against PLAN.md's M1–M8 plus the JA3/JA3S and JA4/JA4S
follow-ups (M9). 580+ tests, ruff-clean. The pieces below all work
end-to-end:

- Port discovery via masscan / naabu / scapy (auto-pick).
- 22 protocol probes, all detection-only — no credentials, no auth attempts:
  TLS (with JA3/JA3S and JA4/JA4S), HTTP (headers, title, favicon mmh3, tech
  fingerprinting), SSH (banner + host keys), SMB (SMB2 NEGOTIATE), RDP (X.224
  NEG_REQ), MQTT, Redis, MongoDB, Docker, Kubernetes, SMTP, FTP, DNS
  (version.bind), Elasticsearch, IMAP, POP3, PostgreSQL (SSLRequest), MySQL /
  MariaDB (handshake), VNC (RFB security types), Telnet, rsync, and AMQP.
- Exposure / misconfiguration findings derived from the probe results:
  cleartext-admin (Telnet), no-TLS (SMTP/IMAP/POP3/FTP/MySQL/PostgreSQL),
  unauthenticated services (VNC no-auth, open Elasticsearch/Redis/Docker/Mongo),
  and TLS certificate problems (expired / expiring-soon / self-signed /
  deprecated protocol version). Browse them with `lodan findings`.
- Offline enrichment: rDNS, ASN/org + country via IP2Location LITE
  (token-based auto-download of both DB-ASN and DB1), CVE matching
  against the NVD 2.0 snapshot.
- Passive TCP/IP stack fingerprinting off the discovery SYN-ACK — no extra
  packet: a canonical `stack_sig` (initial-TTL guess, window, MSS, window
  scale, TCP option order), an `os_family` guess, `hop_count`, and a
  TCP-timestamp `clock_key` that clusters several IPs onto one physical
  machine. Only the scapy backend sees the raw packet; masscan and naabu
  leave every derived column NULL.
- Scan-to-scan diff: `new_service`, `gone_service`, `changed`,
  `new_cert` (workspace-scoped), `new_host`, `path_changed` (stack
  signature or hop count moved under a service that looks unchanged on the
  wire); auto-computed after every scan.
- FTS5-backed mini-DSL: `port:443 AND sans:*.corp.example.com`,
  `tech:nginx OR tech:apache`, `banner:OpenSSH*`, with the full
  grammar documented under [Query DSL](#query-dsl).
- Web UI (FastAPI + HTMX, no JS framework, no build step): dashboard,
  hosts / services tables with filtering, pivot views
  (cert / favicon / JA3S / JA4S / SSH host-key / SAN / stack signature /
  boot-time cluster), operator-labelled favicons, diff timeline + detail,
  DSL query box.
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
| `lodan findings <ws>`           | exposure / misconfiguration findings; `--severity`, `--scan`, `--json` |
| `lodan diff <ws>`               | scan-to-scan diff; `--from`/`--to` accept id / `prev` / `latest` / ISO date |
| `lodan serve <ws>`              | FastAPI UI + management; localhost-only unless `--auth-token`; `--read-only` for a browse-only instance |
| `lodan export <ws>`             | JSONL or JSON array dump; `--include`, `--scan`, `--output` |
| `lodan report <ws>`             | self-contained report bundle (HTML + CSV + SARIF + checksummed manifest); `--scan`, `--output` |
| `lodan prune <ws>`              | apply `[retention]` from config; `--dry-run` |
| `lodan favicon-label <ws> <mmh3> "<label>"` | tag a favicon hash for the pivot views |
| `lodan authz-ledger <ws>`       | show the immutable authorization ledger; `--decision`, `--scan`, `--json` |

## Query DSL

```
query   := term (WS (AND|OR) WS term)*
term    := NOT? key ':' value
key     := banner | tech | sans | port | service | ip
         | favicon_mmh3 | ja3 | ja3s | ja4 | ja4s | hostkey | cve
         | stack_sig | os_family | hop_count | clock_key
value   := bareword | "quoted string" (may contain * as a wildcard)
```

- `banner`, `tech`, `sans` go through FTS5 when the wildcard is trailing
  (or absent); leading/interior wildcards fall back to SQL `LIKE`.
- `port`, `favicon_mmh3` and `hop_count` require integers and reject
  wildcards.
- `cve:CVE-2023-1234` joins through the `vulns` table on
  `(scan_id, ip, port)`.
- `hostkey:<sha256>` matches the server's default SSH host key — the
  "find every host presenting this key" / rogue-rebuild pivot.
- `stack_sig`, `os_family` and `clock_key` accept wildcards, so
  `stack_sig:128:*` groups every port whose SYN-ACK implies an initial TTL
  of 128. These are populated only by the scapy discovery backend.
- Operators are case-insensitive. AND binds tighter than OR; adjacent
  terms without an operator are implicit AND. No parentheses in v1.

Examples:

```
port:443 AND sans:*.corp.example.com
tech:nginx OR tech:apache
banner:OpenSSH* AND NOT service:http
favicon_mmh3:-1234567890
ip:10.0.0.*
os_family:windows AND port:3389
stack_sig:64:* AND NOT os_family:linux
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
    scan.log                   # append-only JSONL audit log (see Audit trail)
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
  no Kubernetes pod listing. Likewise for the newer probes: no SMTP/IMAP/POP3
  login, no FTP USER/PASS, no VNC security-type selection or challenge response,
  no MySQL/PostgreSQL startup or auth packet — only the pre-auth handshake,
  greeting, or capability query each protocol answers without credentials.
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

## Audit trail

Every scan leaves two independent, reconstructable records. See
[SECURITY.md](SECURITY.md) for how they fit the responsible-use contract.

**`scan.log`** — an append-only JSONL audit log in the workspace directory. One
JSON object per line, each with `event`, `level`, an ISO-8601 UTC `timestamp`,
and the bound `operator` / `workspace` / `scan_id`:

```json
{"event":"scan_started","operator":"alice","workspace":"home-lab","scan_id":7,"cidrs":["10.0.0.0/24"],"backend":"masscan","port_count":100,"timestamp":"2026-07-15T21:04:11Z","level":"info"}
{"event":"authz_rejected","operator":"alice","workspace":"home-lab","scan_id":7,"ip":"8.8.8.8","port":53,"reason":"target 8.8.8.8 is not in authorized_ranges","timestamp":"2026-07-15T21:04:12Z","level":"info"}
{"event":"scan_finished","operator":"alice","workspace":"home-lab","scan_id":7,"status":"completed","services_discovered":42,"authz_rejections":1,"timestamp":"2026-07-15T21:05:02Z","level":"info"}
```

Events: `scan_started`, `authz_rejected`, `discovery_completed`,
`probes_completed`, `enrichment_completed`, `diff_computed`, `scan_finished`,
`scan_failed`. The operator is `$LODAN_OPERATOR` if set, else the OS login name.

**Authorization ledger** — an immutable, append-only `authz_ledger` table
recording every authorization *decision*, independent of scan bookkeeping (a
retention prune erases a scan's results but **not** its ledger record). Each row
is `decision` (`authorized` / `refused`), `scope_kind` (`cidr` / `cloud` /
`target`), `target`, optional `port` / `proto` / `reason`, plus `operator`,
`scan_id`, and `ts`. Query it:

```
lodan authz-ledger home-lab                    # full ledger
lodan authz-ledger home-lab --decision refused # only what we declined to touch
lodan authz-ledger home-lab --scan 7 --json    # one scan, as JSONL
```

## Scheduled rescans & change notifications

`lodan scan` is idempotent per workspace and auto-diffs against the previous
scan, so scheduling a rescan turns "what changed since last time" into a
push-free, always-current view. A sample systemd user service + timer ships in
[`contrib/`](contrib/) (a cron entry works too).

To make drift *push*-driven, add an opt-in `[notify]` block to the workspace
`config.toml`. After a rescan, lodan fires a diff summary **only when the diff is
non-empty** — a quiet rescan stays quiet. Both sinks are off until set, and a
failing sink is logged (audit + `scan_errors`) without failing the scan:

```toml
[notify]
webhook_url = "https://hooks.example.com/lodan"   # POSTs the diff summary as JSON
email_to = "team@example.com"                      # comma-separated; omit to disable
email_from = "lodan@localhost"
smtp_host = "localhost"
smtp_port = 25
smtp_starttls = false          # SMTP creds via $LODAN_SMTP_USERNAME / $LODAN_SMTP_PASSWORD
```

The webhook payload carries `workspace`, `scan_id`, `diff_from`, per-kind
`counts`, a few example findings, and a ready-made `text` line.

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

## IPv6

Dual-stack: `authorized_ranges`, the cloud-prefix guard, discovery, probing,
and result storage all handle IPv4 and IPv6. Addresses are stored canonically
(IPv6 compressed + lower-cased) so a host never splits a pivot or shows a
spurious diff. Membership and cloud-overlap checks are family-guarded, so a v6
target against a v4-only allowlist is a clean "not authorized", never an error.

One enrichment gap remains: ASN/geoip come from the **IPv4** IP2Location LITE
DBs, so IPv6 hosts get rDNS and CVE matching but no ASN/country until the LITE
IPv6 DB is wired (`lodan update --ip2location` fetches the IPv4 `DBASNLITEBIN`
today). v6 enrichment degrades silently — it never fails a scan.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for dev setup, the test/lint gates
(including the opt-in Docker integration suite), the codebase invariants to
preserve, and commit style — and [SECURITY.md](SECURITY.md) for the
responsible-use contract every change must keep. In short: `pytest` stays green
and offline by default, `ruff check .` is the lint gate, and one logical change
per commit with a message that says *why*.
