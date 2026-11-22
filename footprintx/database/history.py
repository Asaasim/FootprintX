"""Query past scans (scan history, later: comparison / change detection)."""

from __future__ import annotations

from typing import Any

from footprintx.database.storage import Storage


def list_scans(storage: Storage, limit: int = 20) -> list[dict[str, Any]]:
    raise NotImplementedError
