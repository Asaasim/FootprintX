"""Shared HTTP client behaviour: settings, retries and size-limited fetching."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Any

import httpx

from footprintx import __version__

USER_AGENT = f"Mozilla/5.0 (compatible; FootprintX/{__version__})"

#: Largest response body read from a scanned server. A hostile server could
#: otherwise stream gigabytes and exhaust memory; titles and fingerprints are
#: always near the top of the page.
MAX_BODY_BYTES = 1_000_000

_REDIRECT_CODES = {301, 302, 303, 307, 308}
_RETRY_STATUS = {429, 500, 502, 503, 504}


def make_client(
    timeout: float,
    *,
    proxy: str | None = None,
    verify: bool = False,
    follow_redirects: bool = True,
    max_connections: int = 50,
) -> httpx.AsyncClient:
    """Recon targets often have self-signed or broken TLS, so verification is off
    by default for probing (certificate problems are reported separately).
    API clients pass ``verify=True``."""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        headers={"User-Agent": USER_AGENT},
        follow_redirects=follow_redirects,
        verify=verify,
        proxy=proxy,
        limits=httpx.Limits(max_connections=max_connections),
    )


@dataclass
class Page:
    """A response whose body was read up to :data:`MAX_BODY_BYTES`."""

    url: httpx.URL
    status_code: int
    headers: httpx.Headers
    body: bytes
    truncated: bool = False

    @property
    def text(self) -> str:
        charset = "utf-8"
        content_type = self.headers.get("content-type", "")
        if "charset=" in content_type:
            charset = content_type.split("charset=", 1)[1].split(";")[0].strip() or charset
        try:
            return self.body.decode(charset, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")

    @property
    def is_redirect(self) -> bool:
        return self.status_code in _REDIRECT_CODES and "location" in self.headers


async def fetch_limited(client: httpx.AsyncClient, url: str,
                        max_bytes: int = MAX_BODY_BYTES) -> Page:
    """GET ``url`` but stop reading the body after ``max_bytes``."""
    async with client.stream("GET", url) as response:
        chunks: list[bytes] = []
        size = 0
        truncated = False
        async for chunk in response.aiter_bytes():
            chunks.append(chunk)
            size += len(chunk)
            if size >= max_bytes:
                truncated = True
                break
        return Page(response.url, response.status_code, response.headers,
                    b"".join(chunks)[:max_bytes], truncated)


class RetryableHTTPError(Exception):
    """The server kept answering with a transient error status (429/5xx)."""

    def __init__(self, status_code: int) -> None:
        super().__init__(f"HTTP {status_code}")
        self.status_code = status_code


async def get_with_retries(client: httpx.AsyncClient, url: str, *, retries: int = 2,
                           backoff: float = 1.0, **kwargs: Any) -> httpx.Response:
    """GET with exponential backoff on connection errors, 429 and 5xx (spec §14).

    Raises :class:`RetryableHTTPError` (status only — never the URL, which may hold
    an API key) or the last ``httpx`` transport error.
    """
    for attempt in range(retries + 1):
        last = attempt == retries
        try:
            response = await client.get(url, **kwargs)
        except (httpx.TransportError, httpx.TimeoutException):
            if last:
                raise
        else:
            if response.status_code not in _RETRY_STATUS:
                return response
            if last:
                raise RetryableHTTPError(response.status_code)
            retry_after = response.headers.get("retry-after", "")
            if retry_after.isdigit():
                await asyncio.sleep(min(int(retry_after), 30))
                continue
        await asyncio.sleep(backoff * 2**attempt)
    raise AssertionError("unreachable")
