"""SQLite connection and persistence of scan results."""

from __future__ import annotations

import sqlite3
from pathlib import Path

from footprintx.core.context import ScanContext
from footprintx.database.models import SCHEMA


class Storage:
    def __init__(self, db_path: Path) -> None:
        self.db_path = db_path

    def connect(self) -> sqlite3.Connection:
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA foreign_keys = ON")
        conn.executescript(SCHEMA)
        return conn

    def save_scan(self, context: ScanContext) -> None:
        raise NotImplementedError
