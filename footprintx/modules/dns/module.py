"""DNS enumeration (spec §5.2).

Resolves every in-scope hostname with a native async resolver (no external tool
needed), records A/AAAA/CNAME for all hosts and the full record set for seed
domains, and adds DNS configuration observations: SPF, DMARC, CAA, wildcard DNS
and — outside passive mode — zone transfer (AXFR) exposure.
"""

from __future__ import annotations

import asyncio
import secrets
from typing import TYPE_CHECKING

import dns.asyncresolver
import dns.exception
import dns.name
import dns.query
import dns.resolver
import dns.zone

from footprintx.core.logger import get_logger
from footprintx.core.models import (
    HOSTNAME_TYPES,
    Finding,
    FindingKind,
    ModuleResult,
    ModuleStatus,
    TargetType,
    observation,
)
from footprintx.modules.base import BaseModule
from footprintx.modules.common import scan_hostnames, skipped

if TYPE_CHECKING:
    from footprintx.core.context import ScanContext

log = get_logger("modules.dns")

FULL_RECORD_TYPES = ("A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA")
HOST_RECORD_TYPES = ("A", "AAAA")
_EMPTY = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
          dns.resolver.YXDOMAIN, dns.exception.Timeout, dns.name.EmptyLabel,
          dns.name.LabelTooLong)


class DnsModule(BaseModule):
    name = "dns"
    description = "Enumerate A/AAAA/CNAME/MX/NS/TXT/SOA/CAA records and DNS misconfigurations."
    applies_to = HOSTNAME_TYPES | {TargetType.URL}
    depends_on = ("subdomains", "osint")
    integrations = ()

    async def run(self, context: ScanContext) -> ModuleResult:
        hosts = scan_hostnames(context)
        if not hosts:
            return skipped(self.name, "no hostnames to resolve")

        result = ModuleResult(self.name, ModuleStatus.SUCCESS)
        self.resolver = self._make_resolver(context, float(context.settings.execution.timeout))
        # Discovered subdomains can number in the tens of thousands (CT-log noise),
        # so they get a fast resolver and only A/AAAA lookups.
        self.bulk_resolver = self._make_resolver(context, 5.0)
        seeds = {t.host for t in context.targets
                 if t.type in HOSTNAME_TYPES or t.type is TargetType.URL}
        apexes = sorted({t.value for t in context.targets if t.type is TargetType.DOMAIN})

        # Detect wildcard DNS first: names that only resolve to the wildcard address
        # are not real hosts and must not be probed, port-scanned or fuzzed.
        wildcards = {apex: await self._wildcard_ips(apex) for apex in apexes}

        bulk = [h for h in hosts if h not in seeds]
        max_hosts = int(self.config.option("max_hosts", 10_000))
        if len(bulk) > max_hosts:
            result.notes.append(f"{len(bulk)} subdomains found; resolving the first "
                                f"{max_hosts} (raise modules.dns.max_hosts to resolve more)")
            bulk = bulk[:max_hosts]

        full_types = tuple(self.config.option("record_types", FULL_RECORD_TYPES))
        semaphore = asyncio.Semaphore(int(self.config.option("concurrency", 100)))

        async def resolve_host(host: str, seed: bool) -> list[Finding]:
            async with semaphore:
                if seed:
                    return await self._resolve(host, full_types, self.resolver)
                return await self._resolve(host, HOST_RECORD_TYPES, self.bulk_resolver)

        targets = [(h, True) for h in hosts if h in seeds] + [(h, False) for h in bulk]
        per_host = await asyncio.gather(*(resolve_host(h, s) for h, s in targets))

        unresolved = wildcard_only = 0
        for (host, seed), findings in zip(targets, per_host, strict=True):
            if not findings:
                unresolved += 1
                continue
            ips = {f.value for f in findings if f.kind is FindingKind.IP_ADDRESS}
            wildcard = next((w for apex, w in wildcards.items()
                             if w and (host == apex or host.endswith("." + apex))), set())
            if not seed and ips and ips <= wildcard:
                wildcard_only += 1
                continue
            result.findings.extend(findings)

        if unresolved:
            result.notes.append(f"{unresolved} of {len(targets)} hostnames did not resolve")
        if wildcard_only:
            result.notes.append(f"{wildcard_only} names only matched wildcard DNS and were "
                                "ignored")

        for apex in apexes:
            result.findings.extend(
                await self._domain_checks(apex, wildcards[apex], result, context))

        log.info("dns: %d records for %d hosts", len(result.findings), len(targets))
        return result

    # -- resolution ----------------------------------------------------------

    def _make_resolver(self, context: ScanContext, lifetime: float
                       ) -> dns.asyncresolver.Resolver:
        resolver = dns.asyncresolver.Resolver()
        custom = self.config.option("resolvers")
        if custom:
            resolver.nameservers = list(custom)
        resolver.lifetime = lifetime
        resolver.timeout = min(2.5, lifetime)
        return resolver

    async def _query(self, name: str, rtype: str,
                     resolver: dns.asyncresolver.Resolver | None = None) -> list[tuple[str, int]]:
        try:
            answer = await (resolver or self.resolver).resolve(name, rtype,
                                                               raise_on_no_answer=False)
        except _EMPTY:
            return []
        if answer.rrset is None:
            return []
        return [(rdata.to_text(), answer.rrset.ttl) for rdata in answer]

    async def _wildcard_ips(self, domain: str) -> set[str]:
        """IPs that random, non-existent names under ``domain`` resolve to (empty = none)."""
        probes = await asyncio.gather(*(
            self._query(f"fx-{secrets.token_hex(6)}.{domain}", "A") for _ in range(2)))
        return {ip for answers in probes for ip, _ in answers}

    async def _resolve(self, host: str, types: tuple[str, ...],
                       resolver: dns.asyncresolver.Resolver) -> list[Finding]:
        answers = await asyncio.gather(*(self._query(host, t, resolver) for t in types))
        findings: list[Finding] = []
        for rtype, records in zip(types, answers, strict=True):
            for value, ttl in records:
                findings.append(Finding(
                    FindingKind.DNS_RECORD, f"{host} {rtype} {value}", self.name, host,
                    {"host": host, "type": rtype, "value": value, "ttl": ttl}))
                if rtype in ("A", "AAAA"):
                    findings.append(Finding(
                        FindingKind.IP_ADDRESS, value, self.name, host,
                        {"hostnames": [host], "version": 4 if rtype == "A" else 6}))
        return findings

    # -- domain-level configuration checks -----------------------------------

    async def _domain_checks(
        self, domain: str, wildcard: set[str], result: ModuleResult, context: ScanContext
    ) -> list[Finding]:
        found: list[Finding] = []
        txt = [_unquote(v) for v, _ in await self._query(domain, "TXT")]
        spf = [t for t in txt if t.lower().startswith("v=spf1")]
        if not spf:
            found.append(observation(
                "No SPF record", domain, self.name, "low",
                "Without SPF, anyone can send email that appears to come from this domain."))
        elif any(t.replace(" ", "").endswith("+all") for t in spf):
            found.append(observation(
                "SPF allows all senders (+all)", domain, self.name, "medium",
                f"SPF record ends with +all: {spf[0]}"))

        dmarc = [_unquote(v) for v, _ in await self._query(f"_dmarc.{domain}", "TXT")]
        dmarc = [d for d in dmarc if d.lower().startswith("v=dmarc1")]
        if not dmarc:
            found.append(observation(
                "No DMARC record", domain, self.name, "low",
                "No _dmarc TXT record: spoofed email is not rejected or reported."))
        elif "p=none" in dmarc[0].replace(" ", "").lower():
            found.append(observation(
                "DMARC policy is 'none'", domain, self.name, "info",
                f"DMARC only monitors, it does not block spoofing: {dmarc[0]}"))

        if not await self._query(domain, "CAA"):
            found.append(observation(
                "No CAA record", domain, self.name, "info",
                "Any certificate authority may issue certificates for this domain."))

        if wildcard:
            found.append(observation(
                "Wildcard DNS enabled", domain, self.name, "info",
                f"Random subdomains resolve to {', '.join(sorted(wildcard))}; names that "
                "only resolve to these addresses were ignored."))

        if not context.passive:
            found.extend(await self._check_axfr(domain, result, context))
        return found

    async def _check_axfr(
        self, domain: str, result: ModuleResult, context: ScanContext
    ) -> list[Finding]:
        found: list[Finding] = []
        timeout = float(context.settings.execution.timeout)
        for ns, _ in await self._query(domain, "NS"):
            ns_host = ns.rstrip(".")
            for ns_ip, _ in await self._query(ns_host, "A"):
                names = await asyncio.to_thread(_try_axfr, ns_ip, domain, timeout)
                if names is None:
                    continue
                found.append(observation(
                    "DNS zone transfer (AXFR) allowed", domain, self.name, "high",
                    f"Name server {ns_host} ({ns_ip}) returned the full zone "
                    f"({len(names)} names)."))
                for host in names:
                    if host != domain and context.scope.is_in_scope(host):
                        found.append(Finding(FindingKind.SUBDOMAIN, host, "axfr", domain))
                result.notes.append(f"zone transfer succeeded on {ns_host}")
                return found  # one successful transfer is enough
        return found


def _unquote(txt: str) -> str:
    """TXT rdata text is quoted and may be split into chunks: "v=spf1 " "include:..."."""
    parts = txt.split('" "')
    return "".join(p.strip('"') for p in parts)


def _try_axfr(ns_ip: str, domain: str, timeout: float) -> list[str] | None:
    try:
        zone = dns.zone.from_xfr(dns.query.xfr(ns_ip, domain, timeout=timeout,
                                               lifetime=timeout * 2))
    except Exception:  # noqa: BLE001 — refused/timeouts/garbage all mean "no transfer"
        return None
    names = []
    for name in zone.nodes:
        label = str(name)
        names.append(domain if label == "@" else f"{label}.{domain}".lower())
    return names
