"""Async subprocess execution for external tools (spec §6.2)."""

from __future__ import annotations

import asyncio
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class CommandResult:
    args: list[str]
    returncode: int | None
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False

    @property
    def ok(self) -> bool:
        return not self.timed_out and self.returncode == 0


async def run_command(
    args: Sequence[str],
    *,
    timeout: float | None = None,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
) -> CommandResult:
    """Run ``args`` without a shell and capture output. The process is killed on timeout."""
    start = time.monotonic()
    proc = await asyncio.create_subprocess_exec(
        *args,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=cwd,
        env=dict(env) if env is not None else None,
    )
    try:
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout)
    except TimeoutError:
        proc.kill()
        await proc.wait()
        # TODO: stream output to raw/ files so partial results survive a timeout.
        return CommandResult(list(args), proc.returncode, "", "", time.monotonic() - start, True)

    return CommandResult(
        list(args),
        proc.returncode,
        stdout.decode(errors="replace"),
        stderr.decode(errors="replace"),
        time.monotonic() - start,
    )
