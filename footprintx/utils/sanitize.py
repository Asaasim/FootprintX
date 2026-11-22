"""Defensive handling of untrusted text and secrets.

Everything FootprintX reports comes from systems it does not control (page titles,
DNS TXT records, service banners, tool error output). Before that text reaches a
terminal, a log or a report it is stripped of control characters, so a hostile
server can't inject ANSI escape sequences into someone's terminal via
``cat report.txt``. Secrets from the environment are masked wherever they might
end up in output (e.g. an API key echoed back inside an HTTP error message).
"""

from __future__ import annotations

import logging
import os
import re
from typing import Any

# C0 controls except TAB/LF/CR, DEL, and C1 controls (incl. the 8-bit CSI).
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_SECRET_NAME = re.compile(r"(API_?KEY|TOKEN|SECRET|PASSWORD)$", re.IGNORECASE)
_MIN_SECRET_LENGTH = 6
REDACTED = "[REDACTED]"


def clean_text(value: str) -> str:
    """Remove terminal control characters (ESC sequences become harmless text)."""
    return _CONTROL.sub("", value)


def clean(value: Any) -> Any:
    """``clean_text`` applied recursively to strings inside dicts and lists."""
    if isinstance(value, str):
        return clean_text(value)
    if isinstance(value, list):
        return [clean(v) for v in value]
    if isinstance(value, tuple):
        return tuple(clean(v) for v in value)
    if isinstance(value, dict):
        return {k: clean(v) for k, v in value.items()}
    return value


def secret_values() -> list[str]:
    """Values of environment variables that look like credentials (…_API_KEY, …_TOKEN)."""
    found = {v.strip() for k, v in os.environ.items()
             if _SECRET_NAME.search(k) and len(v.strip()) >= _MIN_SECRET_LENGTH}
    return sorted(found, key=len, reverse=True)


def redact(text: str) -> str:
    for secret in secret_values():
        text = text.replace(secret, REDACTED)
    return text


def safe(text: str) -> str:
    """Control characters stripped and secrets masked — for anything we display or store."""
    return redact(clean_text(text))


class RedactingFilter(logging.Filter):
    """Logging filter that masks secrets and control characters in every record."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = safe(record.getMessage())
        record.args = ()
        return True
