"""Query past scans: ``footprintx history`` and change detection between scans."""

from __future__ import annotations

from collections.abc import Collection
from typing import Any

from footprintx.core.models import TRACKED_KINDS, Baseline, change_key
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


def previous_scan(storage: Storage, targets: Collection[str], passive: bool
                  ) -> Baseline | None:
    """The latest *completed* scan of exactly these targets, in the same mode.

    Passive and full scans aren't compared with each other — a full scan would
    "discover" everything a passive one never looks for.
    """
    if not storage.db_path.is_file():
        return None
    wanted = sorted(targets)
    with storage.connect() as conn:
        rows = conn.execute(
            "SELECT id, started_at, mode FROM scans WHERE status = 'completed' "
            "ORDER BY started_at DESC LIMIT 50").fetchall()
        for row in rows:
            if (row["mode"] or "full") != ("passive" if passive else "full"):
                continue
            scan_targets = sorted(r[0] for r in conn.execute(
                "SELECT value FROM scan_targets WHERE scan_id = ?", (row["id"],)))
            if scan_targets != wanted:
                continue
            kinds = sorted(k.value for k in TRACKED_KINDS)
            marks = ",".join("?" * len(kinds))
            # Only "?" placeholders are interpolated; values are bound parameters.
            findings = conn.execute(
                f"SELECT kind, value, target FROM findings WHERE scan_id = ? "
                f"AND kind IN ({marks})", (row["id"], *kinds)).fetchall()
            return Baseline(row["id"], row["started_at"],
                            frozenset(change_key(f[0], f[1], f[2]) for f in findings))
    return None
