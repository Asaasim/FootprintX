"""Async subprocess execution for external tools (spec §6.2, §13).

- No shell is ever involved: arguments are passed as a list, so target names can't
  inject commands.
- Output is read incrementally, so a tool that hits its timeout still returns what
  it printed so far (partial results, spec §14).
- Captured output is capped (``MAX_OUTPUT_BYTES`` per stream) to bound memory use.
- Every command is written to the scan log as an audit trail (spec §13.6).
"""

from __future__ import annotations

import asyncio
import contextlib
import shlex
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path

from footprintx.core.logger import get_logger

log = get_logger("process")

MAX_OUTPUT_BYTES = 100 * 1024 * 1024
_CHUNK = 64 * 1024


@dataclass(slots=True)
class CommandResult:
    args: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return not self.timed_out and self.returncode == 0


async def _drain(stream: asyncio.StreamReader | None, chunks: list[bytes],
                 flags: dict[str, bool]) -> None:
    if stream is None:
        return
    size = 0
    while chunk := await stream.read(_CHUNK):
        if size < MAX_OUTPUT_BYTES:
            chunks.append(chunk[: MAX_OUTPUT_BYTES - size])
            size += len(chunk)
        else:
            flags["truncated"] = True  # keep reading so the tool never blocks on a full pipe


async def run_command(
    args: Sequence[str],
    *,
    timeout: float | None = None,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> CommandResult:
    """Run ``args`` without a shell. On timeout the process is killed and the
    output captured up to that point is returned with ``timed_out=True``."""
    log.info("exec: %s", shlex.join(args))
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.DEVNULL,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=dict(env) if env is not None else None,
    )
    out: list[bytes] = []
    err: list[bytes] = []
    flags = {"truncated": False}
    readers = asyncio.gather(_drain(proc.stdout, out, flags), _drain(proc.stderr, err, flags),
                             proc.wait())
    timed_out = False
    try:
        await asyncio.wait_for(readers, timeout)
    except TimeoutError:
        timed_out = True
        _kill(proc)
        await proc.wait()
    except asyncio.CancelledError:
        # Scan interrupted (Ctrl+C): don't leave orphaned tool processes behind.
        _kill(proc)
        raise

    duration = time.monotonic() - start
    if timed_out:
        log.warning("timed out after %.0fs: %s", duration, args[0])
    return CommandResult(
        list(args), proc.returncode,
        b"".join(out).decode(errors="replace"), b"".join(err).decode(errors="replace"),
        duration, timed_out, flags["truncated"])


def _kill(proc: asyncio.subprocess.Process) -> None:
    if proc.returncode is None:
        with contextlib.suppress(ProcessLookupError):
            proc.kill()
