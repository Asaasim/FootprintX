"""Shared HTTP client settings for native (Python) probing and API calls."""

from __future__ import annotations

import httpx

from footprintx import __version__

USER_AGENT = f"Mozilla/5.0 (compatible; FootprintX/{__version__})"


def make_client(
    timeout: float,
    *,
    proxy: str | None = None,
    verify: bool = False,
    follow_redirects: bool = True,
    max_connections: int = 50,
) -> httpx.AsyncClient:
    """Recon targets often have self-signed or broken TLS, so verification is off
    by default for probing (certificate problems are reported separately)."""
    return httpx.AsyncClient(
        timeout=httpx.Timeout(timeout),
        headers={"User-Agent": USER_AGENT},
        follow_redirects=follow_redirects,
        verify=verify,
        proxy=proxy,
        limits=httpx.Limits(max_connections=max_connections),
    )
