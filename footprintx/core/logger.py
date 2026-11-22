"""Logging: Rich console output plus a per-scan ``scan.log`` (spec §6.2, §13.6)."""

from __future__ import annotations

import logging
from pathlib import Path

from rich.logging import RichHandler

from footprintx.utils.sanitize import RedactingFilter, safe

ROOT_LOGGER = "footprintx"
_FILE_FORMAT = "%(asctime)s %(levelname)-8s %(name)s: %(message)s"


def setup_logging(console_level: str = "WARNING") -> logging.Logger:
    """Console logging at ``console_level``; file handlers may capture more."""
    logger = logging.getLogger(ROOT_LOGGER)
    logger.setLevel(logging.DEBUG)
    logger.propagate = False
    for handler in [h for h in logger.handlers if isinstance(h, RichHandler)]:
        logger.removeHandler(handler)
    console = RichHandler(rich_tracebacks=True, show_path=False, markup=False)
    console.setLevel(console_level.upper())
    console.addFilter(RedactingFilter())
    logger.addHandler(console)
    return logger


class _SafeFormatter(logging.Formatter):
    """Masks secrets/control characters in the fully formatted record (incl. tracebacks)."""

    def format(self, record: logging.LogRecord) -> str:
        return safe(super().format(record))


def attach_log_file(path: Path, level: str = "INFO") -> logging.Handler:
    """Add a file handler for one scan session; remove it with :func:`detach_log_file`."""
    logger = logging.getLogger(ROOT_LOGGER)
    logger.setLevel(logging.DEBUG)
    path.parent.mkdir(parents=True, exist_ok=True)
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setLevel(level.upper())
    handler.setFormatter(_SafeFormatter(_FILE_FORMAT))
    logger.addHandler(handler)
    return handler


def detach_log_file(handler: logging.Handler) -> None:
    logging.getLogger(ROOT_LOGGER).removeHandler(handler)
    handler.close()


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"{ROOT_LOGGER}.{name}")
