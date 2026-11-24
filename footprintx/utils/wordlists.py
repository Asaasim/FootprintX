"""Locate fuzzing wordlists — project copy first, then Kali's standard locations."""

from __future__ import annotations

from pathlib import Path

from footprintx.utils.locations import user_home

DEFAULT_WORDLIST_CANDIDATES: tuple[Path, ...] = (
    Path("wordlists/common.txt"),                                  # project / Docker image
    user_home() / ".config/footprintx/wordlists/common.txt",       # install.sh download
    Path("/usr/share/seclists/Discovery/Web-Content/common.txt"),  # Kali: apt install seclists
    Path("/usr/share/wordlists/dirb/common.txt"),                  # Kali: wordlists package
    Path("/usr/share/dirb/wordlists/common.txt"),                  # Kali: apt install dirb
)


def resolve_wordlist(
    configured: str | Path | None,
    candidates: tuple[Path, ...] = DEFAULT_WORDLIST_CANDIDATES,
) -> Path | None:
    """A configured path is used as-is (``None`` if missing); else the first candidate found."""
    if configured:
        path = Path(configured).expanduser()
        return path if path.is_file() else None
    return next((p for p in candidates if p.is_file()), None)
