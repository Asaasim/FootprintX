"""Where things are, from the point of view of the person using FootprintX.

Three set-ups print paths that don't exist "on my laptop":

* ``sudo footprintx`` — ``~`` is root's home, which the user can't open. We keep
  using the invoking user's home (``SUDO_USER``) for settings and results.
* Docker — ``/app/results/...`` only exists inside the container. Results are
  shown as the ``results`` folder inside the FootprintX folder on the host.
* WSL (Kali/Ubuntu inside Windows) — Windows programs can't open ``/home/...``;
  we show the copy in the Windows results folder (see :mod:`footprintx.utils.wsl`),
  or failing that the ``\\\\wsl.localhost\\...`` path, and open pages with Windows.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import webbrowser
from functools import lru_cache
from pathlib import Path, PurePosixPath

#: Inside the Docker image the results volume is mounted here.
CONTAINER_RESULTS = PurePosixPath("/app/results")


def user_home() -> Path:
    """The real user's home folder, also under ``sudo`` (where HOME may be /root)."""
    sudo_user = os.environ.get("SUDO_USER")
    if sudo_user and sudo_user != "root" and hasattr(os, "geteuid") and os.geteuid() == 0:
        try:
            import pwd

            return Path(pwd.getpwnam(sudo_user).pw_dir)  # type: ignore[attr-defined,unused-ignore]
        except (ImportError, KeyError):
            pass
    return Path.home()


@lru_cache(maxsize=1)
def in_docker() -> bool:
    return Path("/.dockerenv").exists() or os.environ.get("FOOTPRINTX_IN_DOCKER") == "1"


@lru_cache(maxsize=1)
def is_wsl() -> bool:
    if os.environ.get("WSL_DISTRO_NAME"):
        return True
    try:
        return "microsoft" in Path("/proc/version").read_text(encoding="utf-8").lower()
    except OSError:
        return False


def windows_path(path: Path) -> str | None:
    """``path`` as Windows sees it, when running under WSL."""
    if not is_wsl() or not shutil.which("wslpath"):
        return None
    try:
        out = subprocess.run(["wslpath", "-w", str(path)], capture_output=True, text=True,
                             timeout=5, check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    return out.stdout.strip() or None


def host_path(path: Path) -> str | None:
    """Where a file inside the Docker container is on the computer running Docker."""
    if not in_docker():
        return None
    try:
        relative = PurePosixPath(path.as_posix()).relative_to(CONTAINER_RESULTS)
    except ValueError:
        return None
    host_dir = os.environ.get("FOOTPRINTX_HOST_DIR", "").rstrip("/\\")
    if host_dir:
        sep = "\\" if ":" in host_dir[:3] else "/"  # C:\Users\... on Windows hosts
        return host_dir + sep + "results" + sep + str(relative).replace("/", sep)
    return f"results/{relative}  (in your FootprintX folder)"


def describe(path: Path) -> str:
    """The path(s) the user can actually open on their computer."""
    if (outside := host_path(path)) is not None:
        return outside
    from footprintx.utils import wsl  # imports this module

    copy = wsl.copied(path)
    if copy is not None and (win := windows_path(copy)) is not None:
        return win
    if (win := windows_path(path)) is not None:
        return f"{path}\n      in Windows: {win}"
    return str(path)


def can_open_page() -> bool:
    if in_docker():
        return False
    if is_wsl():
        from footprintx.utils import wsl

        return wsl.can_open()
    has_desktop = bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))
    return has_desktop or os.name != "posix"


def open_page(path: Path) -> bool:
    """Open a local HTML file in the user's browser."""
    if is_wsl():
        from footprintx.utils import wsl

        return wsl.open_in_windows(path)
    return webbrowser.open(path.resolve().as_uri())
