"""Making FootprintX feel like a normal Windows program when it runs inside WSL.

Someone using Kali/Ubuntu inside Windows works in Windows: File Explorer, their
browser, Excel. Linux paths mean nothing there, the PC goes to sleep in the middle
of a scan, and there is no applications menu. So, under WSL only:

* every scan's reports are copied to ``C:\\Users\\<name>\\FootprintX-results``
  (the scan itself stays on the Linux disk, which is many times faster);
* Windows is kept awake while a scan runs;
* ``footprintx windows-shortcuts`` (run by install.sh) puts icons on the desktop.

Nothing here may ever break a scan: without Windows interop every function
quietly does nothing.
"""

from __future__ import annotations

import contextlib
import getpass
import os
import re
import shutil
import subprocess
from collections.abc import Iterator
from functools import lru_cache
from pathlib import Path

from footprintx.core.logger import get_logger
from footprintx.utils.locations import in_docker, is_wsl, user_home

log = get_logger("wsl")

RESULTS_FOLDER = "FootprintX-results"
#: Raw tool output and logs stay on the Linux side; people don't read them.
_NOT_COPIED = ("raw", "scan.log")
_SCAN_DIR = re.compile(r"^scan_\d{8}_\d{6}(_\d+)?$")
_SYSTEM32 = Path("/mnt/c/Windows/System32")
_POWERSHELL = _SYSTEM32 / "WindowsPowerShell" / "v1.0" / "powershell.exe"
#: Keeps Windows awake until our end of its stdin closes — which also happens if
#: FootprintX crashes or its window is closed, so it can never be left behind.
_KEEP_AWAKE = (
    "$t = Add-Type -PassThru -Name Power -Namespace FootprintX -MemberDefinition "
    "'[DllImport(\"kernel32.dll\")] public static extern uint SetThreadExecutionState(uint f);';"
    "[void]$t::SetThreadExecutionState([uint32]2147483649);"  # CONTINUOUS | SYSTEM_REQUIRED
    "[void][Console]::In.ReadToEnd()"
)


def active() -> bool:
    """Running inside WSL itself (a Docker container on Windows is not WSL)."""
    return is_wsl() and not in_docker()


@lru_cache(maxsize=1)
def is_wsl1() -> bool:
    """WSL 1 has no real Linux kernel: raw sockets (fast port scans) don't work there."""
    if not active():
        return False
    try:
        release = Path("/proc/sys/kernel/osrelease").read_text(encoding="utf-8")
    except OSError:
        return False
    return "Microsoft" in release and "WSL2" not in release  # WSL 2 spells it lower-case


def _program(name: str, fallback: Path) -> str | None:
    """A Windows program, also when Windows' PATH isn't shared with Linux."""
    return shutil.which(name) or (str(fallback) if fallback.is_file() else None)


def _run(args: list[str], timeout: float = 15.0) -> str | None:
    try:
        # cwd: Windows programs complain when started from a Linux folder
        cwd = "/mnt/c" if Path("/mnt/c").is_dir() else None
        out = subprocess.run(args, capture_output=True, timeout=timeout, check=False, cwd=cwd,
                             stdin=subprocess.DEVNULL)
    except (OSError, subprocess.SubprocessError) as exc:
        log.debug("wsl: %s failed: %s", args[0], exc)
        return None
    if out.returncode != 0:
        log.debug("wsl: %s exited with %d", args[0], out.returncode)
        return None
    return out.stdout.decode("utf-8", errors="replace").strip()


def _powershell(script: str, timeout: float = 30.0) -> str | None:
    program = _program("powershell.exe", _POWERSHELL)
    if program is None:
        return None
    return _run([program, "-NoProfile", "-NonInteractive", "-Command",
                 "[Console]::OutputEncoding = [Text.Encoding]::UTF8;" + script], timeout)


@lru_cache(maxsize=1)
def results_dir() -> Path | None:
    """The Windows results folder as seen from Linux (``/mnt/c/Users/…``), or None."""
    if not active():
        return None
    # A fixed folder in the Windows profile, not Documents/Desktop: OneDrive often
    # syncs those, and scan results shouldn't be uploaded anywhere.
    profile = _powershell("[Environment]::GetFolderPath('UserProfile')")
    if not profile:
        return None
    linux = _run(["wslpath", "-u", profile])
    if not linux or not Path(linux).is_dir():
        return None
    return Path(linux) / RESULTS_FOLDER


def linux_path(text: str) -> Path:
    """A path the user typed, pasted or dragged in: Windows paths work too under WSL."""
    if active() and re.match(r"^([A-Za-z]:[\\/]|\\\\)", text):
        converted = _run(["wslpath", "-u", text])
        if converted:
            return Path(converted)
    return Path(text).expanduser()


def copy_location(path: Path) -> Path | None:
    """Where ``path`` (a scan folder or something inside one) is copied to."""
    root = results_dir()
    if root is None or str(path).startswith("/mnt/"):  # already on a Windows drive
        return None
    for i, part in enumerate(path.parts):
        if i and _SCAN_DIR.match(part):
            return root.joinpath(*path.parts[i - 1:])
    return None


def copy_scan(scan_dir: Path) -> Path | None:
    """Copy a scan's reports and lists to the Windows results folder."""
    destination = copy_location(scan_dir)
    if destination is None:
        return None
    try:
        for source in sorted(scan_dir.rglob("*")):
            relative = source.relative_to(scan_dir)
            if relative.parts[0] in _NOT_COPIED or not source.is_file():
                continue
            target = destination / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            # copyfile: Windows drives don't accept Linux permissions and owners
            shutil.copyfile(source, target)
    except OSError as exc:  # disk full, file open in Excel, …
        log.warning("Could not copy the results to Windows (%s): %s", destination, exc)
        return None
    return destination


def copied(path: Path) -> Path | None:
    """The Windows copy of ``path``, if there is one."""
    location = copy_location(path)
    return location if location is not None and location.exists() else None


@contextlib.contextmanager
def keep_awake() -> Iterator[None]:
    """Stop Windows from going to sleep while the body runs."""
    program = _program("powershell.exe", _POWERSHELL) if active() else None
    process: subprocess.Popen[bytes] | None = None
    if program is not None:
        with contextlib.suppress(OSError):
            process = subprocess.Popen(
                [program, "-NoProfile", "-NonInteractive", "-Command", _KEEP_AWAKE],
                stdin=subprocess.PIPE, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                cwd="/mnt/c" if Path("/mnt/c").is_dir() else None,
                start_new_session=True)  # Ctrl+C must not reach it before we close it
    try:
        yield
    finally:
        if process is not None:
            with contextlib.suppress(OSError, subprocess.SubprocessError):
                if process.stdin:
                    process.stdin.close()
                process.wait(timeout=3)
            if process.poll() is None:
                process.kill()


def _explorer() -> str | None:
    return _program("explorer.exe", Path("/mnt/c/Windows/explorer.exe"))


def can_open() -> bool:
    return _explorer() is not None


def open_in_windows(path: Path) -> bool:
    """Open a file or folder with Windows (browser, File Explorer, …)."""
    program = _explorer()
    windows = _run(["wslpath", "-w", str(copied(path) or path)])
    if program is None or not windows:
        return False
    try:
        # explorer.exe returns 1 even on success, so don't check the exit code
        subprocess.run([program, windows], capture_output=True, timeout=30, check=False)
    except (OSError, subprocess.SubprocessError):
        return False
    return True


def _quote(value: str) -> str:
    """A PowerShell single-quoted string."""
    return "'" + value.replace("'", "''") + "'"


def shortcut_script(distro: str, user: str, program: str, windows_results: str) -> str:
    """PowerShell that creates the two desktop shortcuts."""
    arguments = (f'-d "{distro}" -u "{user}" --cd ~ -e env FOOTPRINTX_LAUNCHER=1 '
                 f'"{program}"')
    return ";".join([
        "$ErrorActionPreference = 'Stop'",
        "$desktop = [Environment]::GetFolderPath('Desktop')",
        "$shell = New-Object -ComObject WScript.Shell",
        "$s = $shell.CreateShortcut((Join-Path $desktop 'FootprintX.lnk'))",
        "$s.TargetPath = (Join-Path $env:SystemRoot 'System32\\wsl.exe')",
        f"$s.Arguments = {_quote(arguments)}",
        "$s.WorkingDirectory = $env:USERPROFILE",
        "$s.IconLocation = (Join-Path $env:SystemRoot 'System32\\shell32.dll') + ',22'",
        "$s.Description = 'Start a FootprintX scan'",
        "$s.Save()",
        "$r = $shell.CreateShortcut((Join-Path $desktop 'FootprintX results.lnk'))",
        f"$r.TargetPath = {_quote(windows_results)}",
        "$r.Description = 'Reports of your FootprintX scans'",
        "$r.Save()",
        "Write-Output 'created'",
    ])


def create_shortcuts() -> bool:
    """Put "FootprintX" and "FootprintX results" on the Windows desktop."""
    folder = results_dir()
    distro = os.environ.get("WSL_DISTRO_NAME", "")
    if folder is None or not distro:
        return False
    try:
        folder.mkdir(parents=True, exist_ok=True)
    except OSError:
        return False
    windows = _run(["wslpath", "-w", str(folder)])
    if not windows:
        return False
    installed = user_home() / ".local" / "bin" / "footprintx"
    program = str(installed) if installed.exists() else shutil.which("footprintx")
    if not program:
        return False
    return (_powershell(shortcut_script(distro, getpass.getuser(), program, windows)) or "") \
        .endswith("created")
