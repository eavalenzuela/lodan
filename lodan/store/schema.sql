-- lodan workspace schema. One SQLite DB per workspace.
-- See PLAN.md for the data model rationale.

PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS scans (
  id INTEGER PRIMARY KEY,
  started_at TEXT NOT NULL,
  finished_at TEXT,
  cidrs TEXT NOT NULL,            -- JSON array
  workspace TEXT NOT NULL,
  seed INTEGER,
  status TEXT NOT NULL DEFAULT 'pending',  -- pending | running | completed | failed
  cloud_justification TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  ip TEXT NOT NULL,
  rdns TEXT,
  asn INTEGER,
  asn_org TEXT,
  country TEXT,
  -- Host-level consensus of the per-service passive stack fingerprint.
  -- Unanimous-or-NULL: ports that disagree are the NAT/load-balancer signal,
  -- so they are left NULL here rather than collapsed to a majority.
  stack_sig TEXT,
  os_family TEXT,
  os_confidence REAL,
  hop_count INTEGER,
  PRIMARY KEY (scan_id, ip)
);

CREATE TABLE IF NOT EXISTS services (
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  ip TEXT NOT NULL,
  port INTEGER NOT NULL,
  proto TEXT NOT NULL,            -- tcp | udp
  service TEXT,                   -- http, ssh, ...  NULL while pre-probe
  banner TEXT,
  cert_fingerprint TEXT,
  cert_sans TEXT,                 -- JSON array
  ja3 TEXT,
  ja3s TEXT,
  ja4 TEXT,
  ja4s TEXT,
  ssh_hostkey TEXT,               -- sha256 of the server's default SSH host key
  favicon_mmh3 INTEGER,
  tech TEXT,                      -- JSON array
  raw BLOB,                       -- JSON blob, probe-specific
  -- Passive stack fingerprint, derived from the discovery SYN-ACK. Set at
  -- discovery time (not probe time) and only by backends that see the raw
  -- packet; NULL everywhere else. Per-port rather than per-host because
  -- disagreement across ports of one IP is itself a topology signal.
  stack_sig TEXT,
  os_family TEXT,
  os_confidence REAL,
  hop_count INTEGER,
  clock_key TEXT,                 -- bucketed boot-time estimate from TSval
  PRIMARY KEY (scan_id, ip, port, proto)
);

CREATE INDEX IF NOT EXISTS services_ip_port ON services(ip, port);

-- Hot-pivot indexes. Each is:
--   * PARTIAL (WHERE col IS NOT NULL) — the pivot columns are set only during
--     the probe phase, so the vast majority of rows (every bare discovery row,
--     every non-matching service) are NULL. A partial index skips those, so it
--     stays small AND isn't touched by the high-volume discovery INSERTs, which
--     all carry NULL here. This is the write-amplification win for big ranges.
--   * COMPOSITE (col, scan_id, ip, port) — the pivot query is
--     `WHERE col = ? ORDER BY scan_id DESC, ip, port`; carrying the sort keys
--     in the index lets it resolve the equality and the ordering from the index
--     (only service/banner need a row fetch), so a pivot on a common value
--     doesn't fall back to a full sort.
-- Retired single-column predecessors (services_ja3s, services_cert_fp, ...) are
-- dropped by store.db.ensure_schema on upgraded workspaces.
-- scan_id is DESC to match the pivot's `ORDER BY scan_id DESC, ip, port`
-- exactly, so the ordering is resolved straight from the index (no temp b-tree).
CREATE INDEX IF NOT EXISTS services_pivot_cert_fp
  ON services(cert_fingerprint, scan_id DESC, ip, port) WHERE cert_fingerprint IS NOT NULL;
CREATE INDEX IF NOT EXISTS services_pivot_favicon
  ON services(favicon_mmh3, scan_id DESC, ip, port) WHERE favicon_mmh3 IS NOT NULL;
CREATE INDEX IF NOT EXISTS services_pivot_ja3s
  ON services(ja3s, scan_id DESC, ip, port) WHERE ja3s IS NOT NULL;
CREATE INDEX IF NOT EXISTS services_pivot_ja4s
  ON services(ja4s, scan_id DESC, ip, port) WHERE ja4s IS NOT NULL;
CREATE INDEX IF NOT EXISTS services_pivot_hostkey
  ON services(ssh_hostkey, scan_id DESC, ip, port) WHERE ssh_hostkey IS NOT NULL;

-- Stack-fingerprint pivots. Same partial+composite shape as above, but note
-- the write-amplification argument differs: these are populated at DISCOVERY
-- time, so on the scapy backend nearly every row carries a value and the
-- partial predicate excludes little. It still pays for itself on the
-- masscan/naabu backends, where the column is NULL for every row and the
-- index stays empty.
CREATE INDEX IF NOT EXISTS services_pivot_stack_sig
  ON services(stack_sig, scan_id DESC, ip, port) WHERE stack_sig IS NOT NULL;
CREATE INDEX IF NOT EXISTS services_pivot_clock_key
  ON services(clock_key, scan_id DESC, ip, port) WHERE clock_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS vulns (
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  ip TEXT NOT NULL,
  port INTEGER NOT NULL,
  cve TEXT NOT NULL,
  cpe TEXT,
  confidence REAL,
  source TEXT
);

CREATE INDEX IF NOT EXISTS vulns_scan ON vulns(scan_id, ip, port);

CREATE TABLE IF NOT EXISTS scan_errors (
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  ip TEXT,
  port INTEGER,
  stage TEXT NOT NULL,            -- discovery | probe:<name> | enrich:<name>
  error TEXT NOT NULL,
  ts TEXT NOT NULL
);

-- Authorization ledger: an immutable, append-only record of every authz
-- decision — the scope we were authorized to touch, and every out-of-scope
-- target we refused. Deliberately independent of scan bookkeeping: `scan_id`
-- correlates to scans(id) but is NOT a cascading foreign key, so pruning a
-- scan (retention) never erases the accountability record of what that scan
-- touched or refused. Rows are self-describing (workspace, operator, ts are
-- denormalized) so the ledger stays meaningful after its scan row is gone.
-- Immutability is enforced by the triggers below: inserts only, no
-- updates/deletes. This is the durable "what did we touch and what did we
-- refuse" trail, separate from the transient scan_errors bookkeeping.
CREATE TABLE IF NOT EXISTS authz_ledger (
  id INTEGER PRIMARY KEY,
  ts TEXT NOT NULL,
  workspace TEXT NOT NULL,
  scan_id INTEGER,               -- correlates to scans(id); intentionally NOT a
                                 -- cascading FK (survives retention prune)
  operator TEXT,
  decision TEXT NOT NULL,        -- authorized | refused
  scope_kind TEXT NOT NULL,      -- cidr | cloud | target
  target TEXT NOT NULL,          -- authorized CIDR, or the refused IP
  port INTEGER,
  proto TEXT,
  reason TEXT                    -- cloud-opt-in justification, or refusal reason
);

CREATE INDEX IF NOT EXISTS authz_ledger_scan ON authz_ledger(scan_id);
CREATE INDEX IF NOT EXISTS authz_ledger_decision ON authz_ledger(decision, ts);

CREATE TRIGGER IF NOT EXISTS authz_ledger_no_update
BEFORE UPDATE ON authz_ledger BEGIN
  SELECT RAISE(ABORT, 'authz_ledger is append-only (no updates)');
END;

CREATE TRIGGER IF NOT EXISTS authz_ledger_no_delete
BEFORE DELETE ON authz_ledger BEGIN
  SELECT RAISE(ABORT, 'authz_ledger is append-only (no deletes)');
END;

-- Derived exposure/misconfiguration findings for a scan. Computed from the
-- probe results (services.service + services.raw) after probing/enrichment;
-- cascade-deleted with the scan like the other per-scan derived tables.
CREATE TABLE IF NOT EXISTS findings (
  scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  ip TEXT NOT NULL,
  port INTEGER,
  category TEXT NOT NULL,         -- cleartext-admin | no-tls | unauth-service | tls-cert | ...
  severity TEXT NOT NULL,         -- high | medium | low | info
  title TEXT NOT NULL,
  detail BLOB                     -- JSON, category-specific
);

CREATE INDEX IF NOT EXISTS findings_scan ON findings(scan_id, severity);

CREATE TABLE IF NOT EXISTS scan_diffs (
  from_scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  to_scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,             -- new_service | gone_service | changed
                                  -- | new_cert | new_host | path_changed
  ip TEXT NOT NULL,
  port INTEGER,
  detail BLOB,                    -- JSON
  PRIMARY KEY (from_scan_id, to_scan_id, kind, ip, port)
);

CREATE TABLE IF NOT EXISTS favicons (
  mmh3 INTEGER PRIMARY KEY,
  label TEXT,                     -- operator-assigned label (e.g. "Jenkins login")
  first_seen_scan INTEGER,
  first_seen_ip TEXT,
  first_seen_port INTEGER
);

CREATE VIRTUAL TABLE IF NOT EXISTS services_fts USING fts5(
  banner, tech, cert_sans,
  content='services',
  content_rowid='rowid'
);

-- Keep services_fts in sync with services. content='services' means FTS5
-- reads column text from the base table, but the index still needs
-- tokenized rowids; the standard pattern is the three triggers below.
CREATE TRIGGER IF NOT EXISTS services_fts_ai AFTER INSERT ON services BEGIN
  INSERT INTO services_fts(rowid, banner, tech, cert_sans)
  VALUES (new.rowid, new.banner, new.tech, new.cert_sans);
END;

CREATE TRIGGER IF NOT EXISTS services_fts_ad AFTER DELETE ON services BEGIN
  INSERT INTO services_fts(services_fts, rowid, banner, tech, cert_sans)
  VALUES ('delete', old.rowid, old.banner, old.tech, old.cert_sans);
END;

CREATE TRIGGER IF NOT EXISTS services_fts_au AFTER UPDATE ON services BEGIN
  INSERT INTO services_fts(services_fts, rowid, banner, tech, cert_sans)
  VALUES ('delete', old.rowid, old.banner, old.tech, old.cert_sans);
  INSERT INTO services_fts(rowid, banner, tech, cert_sans)
  VALUES (new.rowid, new.banner, new.tech, new.cert_sans);
END;
