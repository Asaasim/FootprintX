"""Query past scans (``footprintx history``)."""

from __future__ import annotations

from typing import Any

from footprintx.database.storage import Storage


def list_scans(storage: Storage, limit: int = 20) -> list[dict[str, Any]]:
    """Most recent scans first, with their targets and finding counts."""
    if not storage.db_path.is_file():
        return []
    with storage.connect() as conn:
        rows = conn.execute(
            """
            SELECT s.id, s.started_at, s.finished_at, s.status, s.output_dir,
                   (SELECT group_concat(value, ', ') FROM scan_targets t
                     WHERE t.scan_id = s.id) AS targets,
                   (SELECT count(*) FROM findings f WHERE f.scan_id = s.id) AS findings,
                   (SELECT count(*) FROM findings f
                     WHERE f.scan_id = s.id AND f.kind = 'observation') AS observations
            FROM scans s
            ORDER BY s.started_at DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
    return [dict(row) for row in rows]
