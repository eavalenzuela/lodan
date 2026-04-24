-- Shared CVE database under ~/.lodan/data/nvd/cve.db.
-- Workspace-agnostic; one copy services every workspace.

PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS cve_cpe (
  cpe TEXT NOT NULL,                -- cpe:2.3:a:apache:http_server:2.4.54:*:*:*:*:*:*:*
  cve TEXT NOT NULL,                -- CVE-2023-12345
  cvss REAL,                        -- CVSSv3.1 baseScore when present, else v3.0, else v2
  published TEXT,                   -- ISO-8601
  last_modified TEXT,
  PRIMARY KEY (cpe, cve)
);

CREATE INDEX IF NOT EXISTS cve_cpe_prefix ON cve_cpe(substr(cpe, 1, 40));
CREATE INDEX IF NOT EXISTS cve_cpe_cve    ON cve_cpe(cve);

CREATE TABLE IF NOT EXISTS cve_meta (
  key TEXT PRIMARY KEY,
  value TEXT
);
