"""Logging setup: Rich console output plus an optional per-scan log file (spec §6.2, §13.6)."""

from __future__ import annotations

import logging
from pathlib import Path

from rich.logging import RichHandler

ROOT_LOGGER = "footprintx"


def setup_logging(level: str = "INFO", log_file: Path | None = None) -> logging.Logger:
    logger = logging.getLogger(ROOT_LOGGER)
    logger.setLevel(level.upper())
    logger.handlers.clear()
    logger.propagate = False

    logger.addHandler(RichHandler(rich_tracebacks=True, show_path=False, markup=False))

    if log_file is not None:
        log_file.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-8s %(name)s: %(message)s")
        )
        logger.addHandler(file_handler)

    return logger


def get_logger(name: str) -> logging.Logger:
    return logging.getLogger(f"{ROOT_LOGGER}.{name}")
