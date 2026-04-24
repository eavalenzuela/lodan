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
  favicon_mmh3 INTEGER,
  tech TEXT,                      -- JSON array
  raw BLOB,                       -- JSON blob, probe-specific
  PRIMARY KEY (scan_id, ip, port, proto)
);

CREATE INDEX IF NOT EXISTS services_ip_port ON services(ip, port);
CREATE INDEX IF NOT EXISTS services_cert_fp ON services(cert_fingerprint);
CREATE INDEX IF NOT EXISTS services_favicon ON services(favicon_mmh3);
CREATE INDEX IF NOT EXISTS services_ja3s    ON services(ja3s);

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

CREATE TABLE IF NOT EXISTS scan_diffs (
  from_scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  to_scan_id INTEGER NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
  kind TEXT NOT NULL,             -- new_service | gone_service | changed | new_cert | new_host
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
