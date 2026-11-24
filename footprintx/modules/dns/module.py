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
import dns.message
import dns.name
import dns.query
import dns.rcode
import dns.rdatatype
import dns.resolver
import dns.zone
import httpx

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
#: Second attempt at failed lookups: few at a time, and never for long (names whose own
#: DNS servers are broken fail again, however often they are asked).
RETRY_CONCURRENCY = 15
RETRY_TIME_LIMIT = 120.0
#: Asked only for records the normal DNS server did not answer for.
DOH_SERVERS = ("https://cloudflare-dns.com/dns-query", "https://dns.google/dns-query")
#: The name or record definitely does not exist.
_EMPTY = (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.YXDOMAIN,
          dns.name.EmptyLabel, dns.name.LabelTooLong)
#: The lookup itself failed (timeout, SERVFAIL/REFUSED from every server): we don't
#: know whether the record exists, so it must never be reported as "missing".
_FAILED = (dns.exception.Timeout, dns.resolver.NoNameservers)


class DnsModule(BaseModule):
    name = "dns"
    description = "Enumerate A/AAAA/CNAME/MX/NS/TXT/SOA/CAA records and DNS misconfigurations."
    applies_to = HOSTNAME_TYPES | {TargetType.URL}
    depends_on = ("subdomains", "osint")
    integrations = ()
    options = frozenset({"concurrency", "max_hosts", "record_types", "resolvers"})
    #: Lookups that timed out or were refused during the current run.
    failed_lookups: int = 0
    #: Record types this network only answers over HTTPS.
    https_types: set[str] = set()  # noqa: RUF012 — replaced at the start of every run

    async def run(self, context: ScanContext) -> ModuleResult:
        hosts = scan_hostnames(context)
        if not hosts:
            return skipped(self.name, "no hostnames to resolve")

        result = ModuleResult(self.name, ModuleStatus.SUCCESS)
        self.failed_lookups = 0
        self.https_types = set()
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

        # Zone transfers first: any names they reveal are resolved with the rest.
        if not context.passive:
            for apex in apexes:
                result.findings.extend(await self._check_axfr(apex, result, context))
        known = set(hosts)
        for f in result.findings:
            if f.kind is FindingKind.SUBDOMAIN and f.value not in known:
                hosts.append(f.value)
                known.add(f.value)

        bulk = [h for h in hosts if h not in seeds]
        max_hosts = int(self.config.option("max_hosts", 10_000))
        if len(bulk) > max_hosts:
            result.notes.append(f"{len(bulk)} subdomains found; resolving the first "
                                f"{max_hosts} (raise modules.dns.max_hosts to resolve more)")
            bulk = bulk[:max_hosts]

        full_types = tuple(self.config.option("record_types", FULL_RECORD_TYPES))
        semaphore = asyncio.Semaphore(int(self.config.option("concurrency", 100)))

        async def resolve_host(host: str, seed: bool) -> tuple[list[Finding], int]:
            async with semaphore:
                if seed:
                    return await self._resolve(host, full_types, self.resolver)
                return await self._resolve(host, HOST_RECORD_TYPES, self.bulk_resolver)

        targets = [(h, True) for h in hosts if h in seeds] + [(h, False) for h in bulk]
        answers = await asyncio.gather(*(resolve_host(h, s) for h, s in targets))
        per_host = [findings for findings, _ in answers]

        # Hundreds of lookups at once overload home routers and WSL's DNS relay, which
        # simply drop some. Those names are asked again, gently: a dropped lookup must
        # not make a real host disappear from the report.
        dropped = [i for i, (_, failed) in enumerate(answers) if failed]
        retry_semaphore = asyncio.Semaphore(RETRY_CONCURRENCY)

        async def retry_host(i: int) -> None:
            async with retry_semaphore:
                host, seed = targets[i]
                findings, failed = await self._resolve(
                    host, full_types if seed else HOST_RECORD_TYPES, self.resolver)
                self.failed_lookups -= answers[i][1]  # superseded by this attempt
                if len(findings) >= len(per_host[i]):
                    per_host[i] = findings

        if dropped:
            log.info("dns: asking again for %d names whose lookup failed", len(dropped))
            retries = [asyncio.ensure_future(retry_host(i)) for i in dropped]
            try:
                await asyncio.wait(retries, timeout=RETRY_TIME_LIMIT)
            finally:  # out of time, or the scan was stopped
                for task in retries:
                    task.cancel()

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

        if self.https_types:
            result.notes.append("this network blocks some DNS lookups "
                                f"({', '.join(sorted(self.https_types))}); asked over HTTPS "
                                "instead")
        if self.failed_lookups:
            message = (f"{self.failed_lookups} DNS lookups timed out or were refused by the "
                       "DNS server; results may be incomplete (set modules.dns.resolvers "
                       "to use other DNS servers)")
            result.notes.append(message)
            log.warning("dns: %s", message)
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

    async def _lookup(self, name: str, rtype: str,
                      resolver: dns.asyncresolver.Resolver | None = None
                      ) -> list[tuple[str, int]] | None:
        """Records for ``name``: ``[]`` if none exist, ``None`` if the lookup failed."""
        if rtype in self.https_types:  # plain DNS doesn't answer these here
            over_https = await self._lookup_https(name, rtype)
            if over_https is not None:
                return over_https
        try:
            answer = await (resolver or self.resolver).resolve(name, rtype,
                                                               raise_on_no_answer=False)
        except _EMPTY:
            return []
        except _FAILED as exc:
            over_https = await self._lookup_https(name, rtype)
            if over_https is not None:
                return over_https
            self.failed_lookups += 1
            log.debug("dns: %s %s lookup failed: %s", name, rtype, exc)
            return None
        if answer.rrset is None:
            return []
        return [(rdata.to_text(), answer.rrset.ttl) for rdata in answer]

    async def _lookup_https(self, name: str, rtype: str) -> list[tuple[str, int]] | None:
        """Second way to ask for TXT/CAA/MX/… records: some networks (mobile hotspots,
        hotels, some providers) block those lookups but let websites through."""
        if rtype in HOST_RECORD_TYPES or self.config.option("resolvers"):
            return None  # A/AAAA are never blocked; chosen DNS servers are respected
        records = await doh_lookup(name, rtype)
        if records is not None:
            self.https_types.add(rtype)
        return records

    async def _query(self, name: str, rtype: str,
                     resolver: dns.asyncresolver.Resolver | None = None) -> list[tuple[str, int]]:
        """Like :meth:`_lookup`, but a failed lookup simply yields no records."""
        return await self._lookup(name, rtype, resolver) or []

    async def _wildcard_ips(self, domain: str) -> set[str]:
        """IPs that random, non-existent names under ``domain`` resolve to (empty = none)."""
        probes = await asyncio.gather(*(
            self._query(f"fx-{secrets.token_hex(6)}.{domain}", "A") for _ in range(2)))
        return {ip for answers in probes for ip, _ in answers}

    async def _resolve(self, host: str, types: tuple[str, ...],
                       resolver: dns.asyncresolver.Resolver) -> tuple[list[Finding], int]:
        """The records of ``host``, and how many of the lookups failed."""
        answers = await asyncio.gather(*(self._lookup(host, t, resolver) for t in types))
        findings: list[Finding] = []
        for rtype, records in zip(types, answers, strict=True):
            for value, ttl in records or []:
                findings.append(Finding(
                    FindingKind.DNS_RECORD, f"{host} {rtype} {value}", self.name, host,
                    {"host": host, "type": rtype, "value": value, "ttl": ttl}))
                if rtype in ("A", "AAAA"):
                    findings.append(Finding(
                        FindingKind.IP_ADDRESS, value, self.name, host,
                        {"hostnames": [host], "version": 4 if rtype == "A" else 6}))
        return findings, sum(records is None for records in answers)

    # -- domain-level configuration checks -----------------------------------

    async def _domain_checks(
        self, domain: str, wildcard: set[str], result: ModuleResult, context: ScanContext
    ) -> list[Finding]:
        found: list[Finding] = []
        unchecked: list[str] = []

        txt_records = await self._lookup(domain, "TXT")
        if txt_records is None:
            unchecked.append("SPF")
        else:
            txt = [_unquote(v) for v, _ in txt_records]
            spf = [t for t in txt if t.lower().startswith("v=spf1")]
            if not spf:
                found.append(observation(
                    "No SPF record", domain, self.name, "low",
                    "Without SPF, anyone can send email that appears to come from this "
                    "domain."))
            elif any(t.replace(" ", "").endswith("+all") for t in spf):
                found.append(observation(
                    "SPF allows all senders (+all)", domain, self.name, "medium",
                    f"SPF record ends with +all: {spf[0]}"))

        dmarc_records = await self._lookup(f"_dmarc.{domain}", "TXT")
        if dmarc_records is None:
            unchecked.append("DMARC")
        else:
            dmarc = [_unquote(v) for v, _ in dmarc_records]
            dmarc = [d for d in dmarc if d.lower().startswith("v=dmarc1")]
            if not dmarc:
                found.append(observation(
                    "No DMARC record", domain, self.name, "low",
                    "No _dmarc TXT record: spoofed email is not rejected or reported."))
            elif "p=none" in dmarc[0].replace(" ", "").lower():
                found.append(observation(
                    "DMARC policy is 'none'", domain, self.name, "info",
                    f"DMARC only monitors, it does not block spoofing: {dmarc[0]}"))

        caa_records = await self._lookup(domain, "CAA")
        if caa_records is None:
            unchecked.append("CAA")
        elif not caa_records:
            found.append(observation(
                "No CAA record", domain, self.name, "info",
                "Any certificate authority may issue certificates for this domain."))

        if unchecked:
            result.notes.append(
                f"{', '.join(unchecked)} of {domain} could not be checked: the DNS lookup "
                "timed out or failed")

        if wildcard:
            found.append(observation(
                "Wildcard DNS enabled", domain, self.name, "info",
                f"Random subdomains resolve to {', '.join(sorted(wildcard))}; names that "
                "only resolve to these addresses were ignored."))

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


async def doh_lookup(name: str, rtype: str) -> list[tuple[str, int]] | None:
    """Records from a public DNS-over-HTTPS server; ``None`` if that failed too."""
    query = dns.message.make_query(name, rtype).to_wire()
    async with httpx.AsyncClient(timeout=8.0) as client:
        for server in DOH_SERVERS:
            try:
                response = await client.post(
                    server, content=query, headers={"Content-Type": "application/dns-message",
                                                    "Accept": "application/dns-message"})
                response.raise_for_status()
                reply = dns.message.from_wire(response.content)
            except (httpx.HTTPError, dns.exception.DNSException):
                continue
            if reply.rcode() == dns.rcode.NXDOMAIN:
                return []
            if reply.rcode() != dns.rcode.NOERROR:
                continue
            return [(rdata.to_text(), rrset.ttl) for rrset in reply.answer
                    if rrset.rdtype == dns.rdatatype.from_text(rtype) for rdata in rrset]
    return None


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
