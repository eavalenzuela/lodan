-- Rising-risk datasets, alongside cve_cpe in ~/.lodan/data/nvd/cve.db.
-- All three are static scored snapshots fetched out-of-band exactly like the
-- NVD one; nothing here is derived from probe traffic.

PRAGMA journal_mode = WAL;

-- FIRST EPSS: probability a CVE will be exploited in the next 30 days, plus
-- its percentile against the whole catalogue.
CREATE TABLE IF NOT EXISTS epss (
  cve TEXT PRIMARY KEY,
  score REAL NOT NULL,              -- 0.0 .. 1.0
  percentile REAL,                  -- 0.0 .. 1.0
  scored_on TEXT                    -- ISO date of the model run
);

-- CISA Known Exploited Vulnerabilities: confirmed exploited in the wild.
-- Presence in this table is the signal; the columns are context.
CREATE TABLE IF NOT EXISTS kev (
  cve TEXT PRIMARY KEY,
  vendor TEXT,
  product TEXT,
  name TEXT,
  date_added TEXT,                  -- ISO date CISA added it
  due_date TEXT,
  ransomware INTEGER,               -- 1 when CISA marks known-ransomware use
  notes TEXT
);

-- End-of-life dates per product release cycle, endoflife.date-shaped.
-- `cycle` is the release series ("2.4", "20.04", "6.0"), not a full version:
-- support ends per series, and that is the granularity the data has.
CREATE TABLE IF NOT EXISTS eol (
  product TEXT NOT NULL,            -- lodan's own product key, e.g. "ubuntu"
  cycle TEXT NOT NULL,
  eol_date TEXT,                    -- ISO date, or NULL when still supported
  support_date TEXT,                -- active-support end, if different
  latest TEXT,                      -- latest release in the cycle
  PRIMARY KEY (product, cycle)
);

CREATE INDEX IF NOT EXISTS eol_product ON eol(product);

CREATE TABLE IF NOT EXISTS risk_meta (
  key TEXT PRIMARY KEY,
  value TEXT
);
