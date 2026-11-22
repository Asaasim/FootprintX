"""Database schema."""

SCHEMA_VERSION = 1

SCHEMA = """
CREATE TABLE IF NOT EXISTS scans (
    id           TEXT PRIMARY KEY,          -- session id
    started_at   TEXT NOT NULL,
    finished_at  TEXT,
    status       TEXT NOT NULL,
    output_dir   TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scan_targets (
    scan_id  TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    value    TEXT NOT NULL,
    type     TEXT NOT NULL,
    PRIMARY KEY (scan_id, value)
);

CREATE TABLE IF NOT EXISTS module_runs (
    scan_id      TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    module       TEXT NOT NULL,
    status       TEXT NOT NULL,
    started_at   TEXT,
    finished_at  TEXT,
    errors       TEXT,                      -- JSON array
    PRIMARY KEY (scan_id, module)
);

CREATE TABLE IF NOT EXISTS findings (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id   TEXT NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
    kind      TEXT NOT NULL,
    value     TEXT NOT NULL,
    source    TEXT NOT NULL,
    target    TEXT,
    data      TEXT,                         -- JSON object
    discovered_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_findings_scan_kind ON findings(scan_id, kind);
"""
