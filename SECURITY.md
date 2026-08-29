# Security & Responsible Use

lodan is a **detection-only reconnaissance** tool for infrastructure **you own
or are explicitly authorized to assess**. It looks; it does not touch. This
document states the contract the code enforces, the accountability trail it
leaves, and how to report a vulnerability in lodan itself.

## Scan what you own

Every workspace declares an `authorized_ranges` allowlist in its `config.toml`.
The authorization guard runs **twice** — once when the config loads and again
per target inside the scan loop — and refuses any address outside the allowlist.
There is no flag to disable it.

Well-known public cloud prefixes (AWS, GCP, Azure, OCI, DigitalOcean) are
refused **even if listed** in `authorized_ranges`, unless the workspace both sets
`cloud_provider_allowed = true` and supplies a non-empty
`cloud_provider_justification`. That justification is copied into the scan
metadata and the authorization ledger, so an opt-in to scanning cloud-hosted
ranges you own is always recorded with its stated reason.

Using lodan against ranges you are not authorized to assess may be illegal and
is not a supported use case.

## Detection-only contract

Every probe is strictly look-don't-touch:

- **No credentials are ever sent** — no SSH login, no SMB session setup, no RDP
  `Cookie: mstshash=`, no MQTT username/password, no Redis `AUTH`, no Docker
  container listing, no Kubernetes pod listing.
- The most active thing lodan does to a web endpoint is an empty `GET /` and
  `GET /favicon.ico` with a `User-Agent: lodan/<version>` header.
- No exploitation, no evasion, no denial-of-service behavior. Discovery rate is
  operator-controlled (`rate_pps`); lodan does not try to be stealthy.

## Accountability trail

Two independent records make every run reconstructable after the fact:

- **`scan.log`** (per workspace) — an append-only JSONL audit log. One object per
  line, each carrying `operator`, `workspace`, `scan_id`, and an ISO-8601 UTC
  `timestamp`, for events `scan_started`, `authz_rejected`, `discovery_completed`,
  `probes_completed`, `enrichment_completed`, `diff_computed`, `scan_finished`,
  and `scan_failed`. See the README "Audit trail" section for the field list.
- **The authorization ledger** (`authz_ledger` table, queryable via
  `lodan authz-ledger <ws>`) — an immutable, append-only record of every
  authorization decision: the CIDRs (and cloud opt-ins) a scan was cleared to
  touch, and every out-of-scope target it refused. It is deliberately
  independent of scan bookkeeping — retention pruning a scan does **not** erase
  its ledger record — so "what did we touch, and what did we refuse" stays
  auditable. Immutability is enforced by database triggers.

The operator identity comes from `$LODAN_OPERATOR` (useful for shared service
accounts, cron, or a change-ticket reference); it falls back to the OS login
name.

## Programmatic clients

`lodan serve` exposes a JSON read API under `/api/v1` (see the README). It is
constrained so that connecting a tool to lodan cannot loosen anything this
document promises:

- Every endpoint is a SELECT. The API cannot start a scan, resolve a name, or
  add a range to `authorized_ranges`. Scope stays a deliberate operator act
  through `lodan manage` — an integration able to widen it on demand would
  make the allowlist decorative.
- It does not gate reads on current scope, because that would protect nothing:
  a stored row exists only because the address was authorized when it was
  scanned, and any client that can reach the API can read the workspace DB.
  Each host response instead reports `authorized`, so a client can tell the
  operator to authorize an address rather than silently showing nothing.
- It is covered by `--auth-token` like every other route, and a non-loopback
  bind still refuses to start without one.

## Handling scan data

A workspace's `lodan.db` and `scan.log` contain reconnaissance findings about
your infrastructure (open ports, banners, certificates, host keys). Treat them
as sensitive:

- The web UI binds to `127.0.0.1` by default. A non-loopback bind **requires**
  `--auth-token` (checked against the `X-Lodan-Token` header on every request);
  terminate TLS in front of it if you expose it beyond localhost.
- Use `lodan serve <ws> --read-only` to share a browse-only instance — it
  disables every mutation endpoint (scan launch, scope/settings edits) and hides
  the write forms.
- On a loopback bind, mutation requests are pinned to loopback `Host`/`Origin`
  headers, so a malicious web page (even via DNS rebinding) can't drive a scan
  through your browser.

## Reporting a vulnerability in lodan

If you find a security issue in lodan itself — for example a way to make it
send credentials, scan outside `authorized_ranges`, bypass the cloud-prefix
guard, crash the probe phase on hostile input, or drive a mutation through the
UI's anti-rebinding guards — please report it privately to the maintainer rather
than opening a public issue, and allow reasonable time for a fix before any
public disclosure. Include a minimal reproduction (a fixture or a request is
ideal; the parser tests under `tests/` show the preferred style).
