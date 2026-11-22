"""Async request-rate limiting (spec §13.3)."""

from __future__ import annotations

import asyncio


class RateLimiter:
    """Allow at most ``rate`` acquisitions per second across all tasks (0 = unlimited)."""

    def __init__(self, rate: float) -> None:
        self._interval = 1.0 / rate if rate > 0 else 0.0
        self._lock = asyncio.Lock()
        self._next = 0.0

    async def wait(self) -> None:
        if not self._interval:
            return
        loop = asyncio.get_running_loop()
        async with self._lock:
            now = loop.time()
            if self._next > now:
                await asyncio.sleep(self._next - now)
                now = loop.time()
            self._next = max(now, self._next) + self._interval
