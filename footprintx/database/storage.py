"""SQLite persistence of scan sessions and findings (scan history)."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import TYPE_CHECKING

from footprintx.database.models import SCHEMA

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext

#: History database file, created inside the results directory.
HISTORY_DB = "footprintx.db"


class Storage:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(SCHEMA)
        columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
        if "mode" not in columns:  # databases created by schema v1
            conn.execute("ALTER TABLE scans ADD COLUMN mode TEXT NOT NULL DEFAULT 'full'")
        return conn

    def save_scan(self, context: ScanContext) -> None:
        """Insert or replace one scan session with its targets, module runs and findings."""
        with self.connect() as conn:
            conn.execute("DELETE FROM scans WHERE id = ?", (context.session_id,))
            conn.execute(
                "INSERT INTO scans (id, started_at, finished_at, status, output_dir, mode) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (context.session_id, context.started_at.isoformat(),
                 context.finished_at.isoformat() if context.finished_at else None,
                 context.status, str(context.output_dir.resolve()),
                 "passive" if context.passive else "full"))
            conn.executemany(
                "INSERT OR IGNORE INTO scan_targets (scan_id, value, type) VALUES (?, ?, ?)",
                [(context.session_id, t.value, t.type.value) for t in context.targets])
            conn.executemany(
                "INSERT INTO module_runs (scan_id, module, status, started_at, finished_at, "
                "errors) VALUES (?, ?, ?, ?, ?, ?)",
                [(context.session_id, r.module, r.status.value,
                  r.started_at.isoformat() if r.started_at else None,
                  r.finished_at.isoformat() if r.finished_at else None,
                  json.dumps(r.errors)) for r in context.results.values()])
            conn.executemany(
                "INSERT INTO findings (scan_id, kind, value, source, target, data, "
                "discovered_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                [(context.session_id, f.kind.value, f.value, f.source, f.target,
                  json.dumps(f.data, default=str), f.discovered_at.isoformat())
                 for f in context.findings()])
