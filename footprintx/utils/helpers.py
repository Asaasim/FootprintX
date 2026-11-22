"""Small general-purpose helpers."""

from __future__ import annotations

import re
from datetime import UTC, datetime

_UNSAFE_PATH_CHARS = re.compile(r"[^A-Za-z0-9._-]+")


def utc_now() -> datetime:
    return datetime.now(UTC)


def new_session_id(now: datetime | None = None) -> str:
    """Session directory name, e.g. ``scan_20261122_143005``."""
    return (now or utc_now()).strftime("scan_%Y%m%d_%H%M%S")


def safe_dirname(value: str) -> str:
    """Turn a target (URL, CIDR, IPv6 …) into a filesystem-safe directory name."""
    cleaned = _UNSAFE_PATH_CHARS.sub("_", value.split("://", 1)[-1]).strip("._")
    return cleaned or "target"
