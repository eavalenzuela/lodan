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

## Milestones

1. **M1 — declare + discover**: workspace config, port sweep, store hosts/services.
2. **M2 — HTTP + TLS probes**: the 80% case. Headers, title, favicon hash, cert SANs.
3. **M3 — SSH + SMB + RDP probes**: the next most common services.
4. **M4 — enrich**: rDNS, ASN, offline CVE matching against NVD.
5. **M5 — diff**: scan-to-scan comparison.
6. **M6 — web UI**: FastAPI+HTMX dashboard, pivot queries.
7. **M7 — more probes**: MQTT, Redis, Mongo, Docker/K8s API detection (unauth only).
8. **M8 — FTS + query language**: lodan-query DSL for pivots.

## Open questions

- Scanning backend: shell out to masscan (fast, needs CAP_NET_RAW) or do it native in scapy (slower, pure Python)? Offer both, default to masscan if available.
- Rescan cadence: cron-scheduled within lodan, or leave to systemd timers? Systemd.
- Privacy: lodan is for ranges you own. Enforce via a strict CIDR allowlist in config. Warn loudly if the workspace declares a public range.
- Sharing the NVD data with uvt: symlink or API? Symlink the snapshot dir, document.

## Legal / ethics guard

- Config must declare `authorized_ranges`. Scan refuses ranges outside that list.
- A `cloud_provider_allowed: false` default block (prevents accidentally scanning AWS/GCP/Azure public IPs without explicit opt-in) — operator must flip it and state why; logged into scan metadata.
- README spells out "scan what you own".
- No exploitation, no brute force, no auth attempts. lodan looks, doesn't touch.
