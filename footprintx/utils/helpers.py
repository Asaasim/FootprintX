"""Small general-purpose helpers."""

from __future__ import annotations

import contextlib
import os
import re
from datetime import UTC, datetime
from pathlib import Path

_UNSAFE_PATH_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_session_id(now: datetime | None = None) -> str:
    """Session directory name, e.g. ``scan_20261122_143005``."""
    return (now or utc_now()).strftime("scan_%Y%m%d_%H%M%S")


def unique_session_dir(parent: Path, now: datetime | None = None) -> Path:
    """``parent/scan_<timestamp>``, with a numeric suffix if that already exists."""
    base = parent / new_session_id(now)
    candidate, n = base, 1
    while candidate.exists():
        n += 1
        candidate = base.with_name(f"{base.name}_{n}")
    return candidate


def restore_ownership(path: Path, parents: tuple[Path, ...] = ()) -> None:
    """After ``sudo footprintx …`` on Kali, give results back to the invoking user.

    Chowns ``path`` recursively and each of ``parents`` (non-recursively).
    No-op unless running as root with ``SUDO_UID``/``SUDO_GID`` set.
    """
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not (hasattr(os, "geteuid") and os.geteuid() == 0 and uid and gid):
        return
    for item in [*parents, path, *path.rglob("*")]:
        with contextlib.suppress(OSError):
            os.chown(item, int(uid), int(gid))  # type: ignore[attr-defined]


def safe_dirname(value: str) -> str:
    """Turn a target (URL, CIDR, IPv6 …) into a filesystem-safe directory name."""
    cleaned = _UNSAFE_PATH_CHARS.sub("_", value.split("://", 1)[-1]).strip("._")
    return cleaned or "target"
