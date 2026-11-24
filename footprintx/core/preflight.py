"""A few seconds of checks before a scan, so it doesn't run for minutes for nothing.

* A typo in the domain (``exmaple.com``): the registered domain doesn't exist in
  DNS (NXDOMAIN) — that target is skipped with a clear message.
* No internet / DNS not working: every lookup times out — the scan is not started.

Only DNS is used (no traffic to the targets), so this is also safe in passive mode.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from urllib.parse import urlsplit

import dns.asyncresolver
import dns.exception
import dns.resolver
import tldextract

from footprintx.core.models import Target, TargetType

_extract = tldextract.TLDExtract(suffix_list_urls=())
_HOSTNAMES = (TargetType.DOMAIN, TargetType.SUBDOMAIN, TargetType.URL)
LOOKUP_TIMEOUT = 6.0


@dataclass
class PreflightResult:
    usable: list[Target] = field(default_factory=list)
    #: (target, reason) — skipped because the domain does not exist
    missing: list[tuple[Target, str]] = field(default_factory=list)
    #: hostnames whose lookups timed out (network or DNS trouble)
    unreachable: list[Target] = field(default_factory=list)

    @property
    def offline(self) -> bool:
        """Every name lookup failed: most likely no internet connection."""
        return bool(self.unreachable) and not self.usable and not self.missing


def _registered_domain(host: str) -> str:
    parts = _extract(host)
    # tldextract 5.3 renamed registered_domain; older versions (e.g. Kali's) lack the new name
    value = getattr(parts, "top_domain_under_public_suffix", None)
    return str(value if value is not None else parts.registered_domain)


def _hostname(target: Target) -> str:
    return (urlsplit(target.value).hostname or "") if target.type is TargetType.URL \
        else target.value


async def _status(resolver: dns.asyncresolver.Resolver, name: str) -> str:
    """'ok', 'nxdomain' or 'timeout'."""
    try:
        await resolver.resolve(name, "SOA", raise_on_no_answer=False)
        return "ok"
    except dns.resolver.NXDOMAIN:
        return "nxdomain"
    except (dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout):
        return "timeout"
    except dns.exception.DNSException:
        return "ok"  # unusual answer, but the name is reachable — let the scan decide


async def check_targets(targets: list[Target], resolvers: list[str] | None = None
                        ) -> PreflightResult:
    resolver = dns.asyncresolver.Resolver()
    if resolvers:
        resolver.nameservers = list(resolvers)
    resolver.lifetime = LOOKUP_TIMEOUT
    resolver.timeout = LOOKUP_TIMEOUT / 2

    result = PreflightResult()
    names = [t for t in targets if t.type in _HOSTNAMES and _hostname(t)]
    # The registered domain decides whether a name can exist at all (a missing
    # subdomain of a real domain is still worth a passive look).
    registered = {t: (_registered_domain(_hostname(t)) or _hostname(t)) for t in names}
    unique = sorted(set(registered.values()))
    statuses = dict(zip(unique, await asyncio.gather(*(_status(resolver, d) for d in unique)),
                        strict=True))
    for target in targets:
        if target not in registered:
            result.usable.append(target)  # IPs and ranges need no DNS
            continue
        status = statuses[registered[target]]
        if status == "nxdomain":
            result.missing.append((target, f"{registered[target]} does not exist "
                                           "(no DNS records) — check the spelling"))
        elif status == "timeout":
            result.unreachable.append(target)
        else:
            result.usable.append(target)
    if result.unreachable and (result.usable or result.missing):
        # Some names resolved, so the network works: keep the slow ones.
        result.usable += result.unreachable
        result.unreachable = []
    return result
