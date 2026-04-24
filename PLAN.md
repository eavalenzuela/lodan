# lodan

A local Shodan. Point it at a CIDR you own, get a Shodan-style report — offline, free, with diff-over-time as the killer feature.

## Scope

**In scope**: port discovery, protocol fingerprinting, TLS cert enrichment, offline CVE matching, favicon-hash pivoting, periodic rescans with diff, web UI.

**Out of scope**: exploitation, credential testing, active attacks. lodan is reconnaissance only.

## Non-negotiables

- Runs entirely offline after initial data pulls (NVD snapshot, MaxMind GeoLite2 ASN).
- Scoped to operator-declared CIDRs. Refuses to scan ranges not listed in the config.
- Results stored in SQLite (file-per-scan-workspace) so they're portable and scriptable.
- Rescans are first-class: the whole point is "what changed since last time".

## Architecture

```
lodan/
  cli.py              # typer
  discovery/
    ports.py          # masscan/naabu wrapper or native TCP SYN via scapy
  probes/              # one module per protocol
    http.py           # headers, title, favicon hash, tech detection
    tls.py            # cert chain, SAN, JA3/JA3S
    ssh.py            # banner, host keys, kex algs
    smb.py
    rdp.py
    mqtt.py
    redis.py
    mongo.py
    elastic.py
    docker.py         # Docker remote API (unauth detection only)
    kubernetes.py     # /version, /healthz (unauth detection only)
    dns.py
    ftp.py
    smtp.py
  enrich/
    rdns.py
    asn.py            # offline MaxMind lookup
    geoip.py
    cve.py            # offline NVD JSON lookup by CPE or banner heuristics
    favicon.py        # mmh3 hash, local database of known panels
    tech.py           # Wappalyzer-style signatures
  store/
    schema.sql
    writer.py
    query.py
  diff/
    scanner.py        # compare two scan snapshots → new/changed/gone
  ui/
    app.py            # FastAPI + HTMX, single-page dashboard
    templates/
```

## Pipeline

```
declare CIDRs → port discovery → per-port probe → enrich → store → diff vs prior → UI
```

Each stage writes to SQLite so you can resume/inspect mid-run.

## Schema (sketch)

```sql
CREATE TABLE scans (
  id INTEGER PRIMARY KEY,
  started_at TEXT,
  finished_at TEXT,
  cidrs TEXT,        -- JSON array
  workspace TEXT,
  seed INTEGER
);

CREATE TABLE hosts (
  scan_id INTEGER,
  ip TEXT,
  rdns TEXT,
  asn INTEGER,
  asn_org TEXT,
  country TEXT,
  PRIMARY KEY (scan_id, ip)
);

CREATE TABLE services (
  scan_id INTEGER,
  ip TEXT,
  port INTEGER,
  proto TEXT,        -- tcp/udp
  service TEXT,      -- http, ssh, etc
  banner TEXT,
  cert_fingerprint TEXT,
  cert_sans TEXT,    -- JSON array
  ja3 TEXT,
  ja3s TEXT,
  favicon_mmh3 INTEGER,
  tech TEXT,         -- JSON array of detected technologies
  raw JSONB,         -- probe-specific full response
  PRIMARY KEY (scan_id, ip, port, proto)
);

CREATE TABLE vulns (
  scan_id INTEGER,
  ip TEXT,
  port INTEGER,
  cve TEXT,
  cpe TEXT,
  confidence REAL,
  source TEXT
);

CREATE VIRTUAL TABLE services_fts USING fts5(
  banner, tech, cert_sans, content='services'
);
```

## Pivot queries (the killer feature)

Shodan's real value is pivoting. lodan should answer these one-liners:

- "all hosts whose TLS cert mentions `*.corp.example.com`" → SAN search
- "all hosts serving the same admin panel as 10.0.1.5:443" → favicon-mmh3 equals
- "all hosts with the same JA3S signature" → fingerprint match (find servers running the same stack)
- "all hosts with an SSH host key matching a known prod key" → host-key pivot (spot rogue rebuilds)
- "new services since last Tuesday" → diff between scans

Exposed via CLI (`lodan query`) and UI.

## Offline CVE matching

Pragmatic, not perfect:
1. Grab NVD JSON feeds (`lodan update`). Store CPE → [CVE, CVSS].
2. Map banners → CPE with a curated table (`Apache/2.4.54` → `cpe:2.3:a:apache:http_server:2.4.54`).
3. Confidence score: exact CPE match = high; regex banner → CPE = medium; version guess = low.
4. Surface results with confidence so operator knows what to trust.

(This is what uvt already does — pull the same offline NVD snapshot if possible.)

## Diff (the killer feature, again)

```
lodan diff <workspace> --from 2026-04-17 --to 2026-04-24
```

Output:
- **new services** — new (ip, port, service) tuples
- **gone services** — disappeared from last scan
- **changed** — same (ip, port) but banner/cert/tech differs
- **new certs** — cert fingerprints never seen before in this workspace
- **new hosts** — IPs that came online

Web UI renders this as a timeline. Each finding links to the full service record.

## Web UI

FastAPI + HTMX + SQLite. No JS framework, no build step. Views:

- **Dashboard** — per-workspace summary, last scan, deltas.
- **Hosts table** — sort/filter, click-through to host detail.
- **Services table** — port/service/banner, FTS search.
- **Pivot** — pick a cert/favicon/JA3S → list all matches.
- **Diff** — scan-to-scan comparison.

## CLI surface

```
lodan init <workspace> --cidrs "10.0.0.0/8,192.168.0.0/16"
lodan update                    # pull NVD + MaxMind
lodan scan <workspace> [--fast | --deep]
lodan diff <workspace> --from <scan-id> --to <scan-id>
lodan query "sans:*.corp.example.com"
lodan query "favicon_mmh3:-1234567890"
lodan serve <workspace> --addr :8080
lodan export <workspace> --format jsonl
```

## Implementation details

### Tech stack

- **Python 3.12**, packaged with `pyproject.toml`; plain `pip` + `requirements.txt` (+ `requirements-dev.txt`). No `uv` / `poetry`.
- **CLI**: `typer` + `rich` (progress bars, tables).
- **Config**: TOML via stdlib `tomllib`, validated with `pydantic`.
- **Concurrency**: `asyncio` throughout. Blocking libs (scapy, impacket) wrapped in `asyncio.to_thread`.
- **HTTP probe**: `httpx` (async, HTTP/1.1 + HTTP/2, custom SSL context so we still fingerprint bad certs).
- **TLS probe**: raw `asyncio.open_connection` + `cryptography` for cert parsing. JA3/JA3S via `tlsfingerprint` (or hand-rolled — the algorithm is small).
- **SSH probe**: `asyncssh` for banner + host keys + kex algorithms; never authenticates.
- **SMB/RDP**: `impacket` (sync, threaded off).
- **Favicon hash**: `mmh3` on the base64-encoded favicon bytes (Shodan-compatible).
- **Tech detection**: two-layer. A hand-rolled minimal signature set in-repo (`enrich/tech_signatures.py`) is the primary source; a trimmed `enthec/webappanalyzer` fingerprint JSON is loaded on top for breadth. Matches from both are merged; self-rolled wins on conflict so we aren't hostage to upstream relicensing.
- **Storage**: stdlib `sqlite3` in WAL mode, one DB per workspace. No ORM — write SQL by hand and keep it greppable.
- **Search**: SQLite FTS5 (`services_fts`) mirroring banner/tech/cert_sans.
- **GeoIP/ASN**: IP2Location LITE DB-ASN (free, CC-BY-SA) via the `IP2Location` Python package. No license key required; `lodan update` fetches the latest LITE bin. MaxMind deliberately avoided to keep the stack fully free/FOSS.
- **CVE**: NVD 2.0 REST API during `lodan update`; shard into a `cve_cpe` table keyed by CPE vendor+product. Optional API key via `LODAN_NVD_KEY` for the higher rate limit. No legacy JSON 1.1 feed support.
- **Web UI**: FastAPI + Jinja2 + HTMX + a hand-written stylesheet. No bundler, no npm.
- **Logging**: `structlog`; JSON to `scan.log` in the workspace, pretty to stderr.

### Workspace layout on disk

```
~/.lodan/
  data/                         # shared, populated by `lodan update`
    nvd/                        # CPE → [CVE, CVSS] index + raw feeds
    ip2location/IP2LOCATION-LITE-ASN.BIN
    favicons/seed.json          # curated hash → label map
    wappalyzer/                 # fingerprint JSON
  workspaces/<name>/
    config.toml
    lodan.db                    # all scans for this workspace
    raw/<scan-id>/              # optional per-probe raw captures (opt-in)
    scan.log
```

One DB per workspace (portability is a non-negotiable); sibling workspaces never share a DB. The `data/` dir is shared across workspaces. For the uvt ↔ lodan NVD share, lodan owns `~/.lodan/data/nvd/` by default and exposes it as the canonical path; uvt can symlink to it. If uvt prefers to own the snapshot, the inverse symlink is documented in README. (Exact uvt path TBD — tracked below.)

### Config file (TOML)

```toml
[workspace]
name = "home-lab"
authorized_ranges = ["10.0.0.0/24", "192.168.1.0/24"]
cloud_provider_allowed = false        # flip + set justification to scan public cloud space
cloud_provider_justification = ""

[scan]
backend = "masscan"                   # "masscan" | "naabu" | "scapy"
rate_pps = 1000                       # global cap
ports = "top-1000"                    # "top-N" | "1-65535" | "22,80,443,..."  (operator-sized; no guard rails)
tcp = true
udp = true
# ipv6 not supported in v1
concurrency = 100                     # max in-flight probes scan-wide
per_host_concurrency = 4              # max in-flight probes per IP
probe_timeout_s = 5
retries = 1

[enrich]
rdns = true
asn = true
geoip = true
cve = true
favicon = true
tech = true
keep_raw = false                      # write raw/<scan-id>/ captures

[diff]
# Defaults for `lodan diff`; overridable per invocation.
default_from = "prev"                 # "prev" | scan-id | ISO date

[retention]
# User-configurable prune policy. Unset/omitted => keep everything.
keep_last_n = 24                      # always retain the N most recent scans
keep_monthly = 12                     # plus first-of-month scans for this many months
# `lodan prune <workspace>` applies the policy; never runs automatically.
```

### Pipeline in detail

1. **Load + validate config**. Assert every `authorized_ranges` CIDR parses; refuse the scan if any target lies outside. Emit a warning (not an error) if a range is in RFC6598/public space and `cloud_provider_allowed=false`; hard-fail if it's in a well-known cloud prefix.
2. **Open scan row** in `scans` with `status='running'`. All subsequent writes carry this `scan_id`.
3. **Port discovery**. Shell out to `masscan` by default (detect `CAP_NET_RAW`; fall back to `naabu`, then `scapy`). Runs TCP and, if `scan.udp=true`, a UDP sweep alongside (masscan `--ports U:...`, naabu `-sU`, scapy `sr1` with protocol-specific payloads for common UDP services — DNS/53, SNMP/161, NTP/123, NetBIOS/137, IKE/500, SSDP/1900, mDNS/5353). Stream stdout line-by-line into the `services` table with `service='unknown'`, `banner=NULL`, `proto` set. masscan's own `--rate` handles PPS; for scapy we implement a token-bucket.
4. **Probe dispatch**. For each (ip, port) row, pick a probe by:
   - explicit port→probe map (22→ssh, 80/8080/8000/8443→http, 443→tls+http, 3389→rdp, ...),
   - else banner-sniff: 256-byte read on TCP connect; match against a small signature table; fall back to the "generic" probe that just records the banner.
5. **Probe execution**. Bounded by global + per-host semaphores. Each probe is `async def run(ip, port) -> ProbeResult`. Results are upserted via `INSERT ... ON CONFLICT(scan_id, ip, port, proto) DO UPDATE`.
6. **Enrichment**. Runs after probes finish (rDNS/ASN/GeoIP are per-host; CVE/favicon/tech are per-service). Separate table writes, same scan_id.
7. **Diff against prior**. After a successful scan, compute the delta vs. the previous completed scan in this workspace and store it in `scan_diffs` (denormalized for the UI).
8. **Close scan row**: `status='completed'`, `finished_at=now()`.

Resume: if `lodan scan` is re-run while a scan row is `running`, skip (ip, port) tuples already recorded for that scan_id.

### Schema additions

```sql
-- append to schema.sql

CREATE TABLE scan_errors (
  scan_id INTEGER,
  ip TEXT,
  port INTEGER,
  stage TEXT,         -- discovery | probe:<name> | enrich:<name>
  error TEXT,
  ts TEXT
);

CREATE TABLE cve_cpe (
  cpe TEXT,           -- cpe:2.3:a:apache:http_server:2.4.54
  cve TEXT,
  cvss REAL,
  published TEXT,
  PRIMARY KEY (cpe, cve)
);
CREATE INDEX cve_cpe_vendor_product ON cve_cpe(substr(cpe, 1, 40));

CREATE TABLE scan_diffs (
  from_scan_id INTEGER,
  to_scan_id INTEGER,
  kind TEXT,          -- new_service | gone_service | changed | new_cert | new_host
  ip TEXT,
  port INTEGER,
  detail JSONB,
  PRIMARY KEY (from_scan_id, to_scan_id, kind, ip, port)
);

ALTER TABLE scans ADD COLUMN status TEXT DEFAULT 'pending';
ALTER TABLE scans ADD COLUMN cloud_justification TEXT;
```

### Query DSL

Thin layer on top of SQL — not a full Lucene. Grammar:

```
query   := term (WS (AND|OR) WS term)*
term    := NOT? key ':' value
key     := banner | tech | sans | port | service | ip | favicon_mmh3 | ja3 | ja3s | cve
value   := bareword | quoted | wildcard ('*' allowed)
```

Compiled to a parameterized SQL WHERE clause against `services` (+ FTS5 for `banner`/`tech`/`sans`). No arbitrary SQL from users.

### Diff resolver (`--from`, `--to`)

Accepts:
- integer → treated as `scan_id`;
- `prev` / `latest` → relative to the workspace's scans;
- ISO date (`2026-04-17`) → latest completed scan on or before that date.

### Rescan scheduling

Out of scope inside lodan. Ship a sample `systemd` timer unit under `contrib/` and document it. `lodan scan` is idempotent-per-workspace and safe to run from cron.

### Rate limiting & politeness

- Global PPS cap (discovery): masscan's `--rate`, scapy's token bucket.
- Probe phase: global concurrency semaphore + per-host semaphore (prevents hammering one box).
- TCP connect timeout 3s, probe read timeout 5s, both overridable per-probe.
- `retries=1` by default; second failure is recorded to `scan_errors` and dropped.

### Testing

- **Unit**: every probe parser has fixtures of captured raw responses under `tests/fixtures/<probe>/` and a `parse()`-only test path that never touches the network.
- **Integration**: `tests/docker/` spins up nginx (TLS + plain), OpenSSH, vsftpd, Redis (no auth), Mongo (no auth) on loopback; scan `127.0.0.1` and assert the service table.
- **Diff**: golden test — two hand-rolled SQLite snapshots → expected diff rows.
- **Query DSL**: parse/compile snapshot tests.
- **CI**: GitHub Actions, ubuntu-latest, no external network (NVD/MaxMind mocked).

### Security / guard rails (implementation)

- `authorized_ranges` checked at config load *and* right before each probe batch. Any target outside → hard fail + entry in `scan_errors`.
- Cloud-prefix table shipped in-repo (AWS, GCP, Azure, OCI, DO public ranges). Overlap with `authorized_ranges` + `cloud_provider_allowed=false` → hard fail; `=true` requires `cloud_provider_justification` which is copied into `scans.cloud_justification`.
- No probe ever sends credentials. HTTP probe sends only `GET /` and `GET /favicon.ico` with a `User-Agent: lodan/<version>`.
- Web UI binds to `127.0.0.1` by default. `--addr 0.0.0.0` requires `--auth-token` (checked against `X-Lodan-Token` header); no token = refuse to bind non-loopback.

## Milestones

1. **M1 — declare + discover**: workspace config, port sweep, store hosts/services.
2. **M2 — HTTP + TLS probes**: the 80% case. Headers, title, favicon hash, cert SANs.
3. **M3 — SSH + SMB + RDP probes**: the next most common services.
4. **M4 — enrich**: rDNS, ASN, offline CVE matching against NVD.
5. **M5 — diff**: scan-to-scan comparison.
6. **M6 — web UI**: FastAPI+HTMX dashboard, pivot queries.
7. **M7 — more probes**: MQTT, Redis, Mongo, Docker/K8s API detection (unauth only).
8. **M8 — FTS + query language**: lodan-query DSL for pivots.

## Decisions (resolved)

- **Scanning backend**: offer masscan / naabu / scapy; auto-pick best available, overridable in config. Default masscan.
- **Rescan cadence**: systemd timers via `contrib/`; lodan stays stateless between runs.
- **Privacy/authorization**: config `authorized_ranges` allowlist enforced at load *and* per batch; cloud-prefix hard-fail unless explicitly opted in with a justification string.
- **Storage topology**: one SQLite per workspace (portability).
- **Async model**: single asyncio event loop; blocking libs in `to_thread`.
- **Web UI default**: localhost-only bind; non-loopback requires an auth token.
- **Packaging**: plain `pip` + `pyproject.toml` + `requirements.txt` / `requirements-dev.txt`.
- **Protocol scope v1**: TCP + UDP, IPv4 only. IPv6 deferred.
- **Query surface v1**: mini-DSL (grammar above) from day one; compiles to parameterized SQL over `services` + FTS5.
- **Favicon DB**: start empty; hashes accumulate in a `favicons` table from real scans. No seed shipped in v1.
- **CVE source**: NVD 2.0 REST API only. Optional `LODAN_NVD_KEY` for higher rate limit.
- **GeoIP/ASN**: IP2Location LITE DB-ASN (free, no key) — chosen over MaxMind GeoLite2 to keep the stack fully free/FOSS.
- **Tech detection**: hand-rolled signatures are primary; `enthec/webappanalyzer` JSON loaded on top for breadth; self-rolled wins on conflict.
- **Discovery sizing**: no cap — operator picks the port list, including `1-65535`, and owns the workspace size.
- **Scan retention**: user-configurable via `[retention]` in config; `lodan prune` applies it manually. Never runs automatically. Default (section omitted) = keep everything.

## Open questions (still need your call)

1. **uvt NVD path**: `~/gits/uvt_universal_vuln_tracker/` is a sibling here, but the actual snapshot location inside uvt isn't pinned down. For now lodan owns `~/.lodan/data/nvd/` as the canonical path and uvt can symlink to it; we'll re-document once the uvt side is confirmed.

## Legal / ethics guard

- Config must declare `authorized_ranges`. Scan refuses ranges outside that list.
- A `cloud_provider_allowed: false` default block (prevents accidentally scanning AWS/GCP/Azure public IPs without explicit opt-in) — operator must flip it and state why; logged into scan metadata.
- README spells out "scan what you own".
- No exploitation, no brute force, no auth attempts. lodan looks, doesn't touch.
