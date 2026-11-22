"""Module behaviour with external tools and network access stubbed out."""

import json

import httpx

from footprintx.core.config import ModuleConfig, Settings
from footprintx.core.context import ScanContext
from footprintx.core.models import (
    Finding,
    FindingKind,
    ModuleResult,
    ModuleStatus,
    Target,
    TargetType,
)
from footprintx.core.process_manager import CommandResult
from footprintx.core.scope_manager import ScopeManager
from footprintx.modules import common
from footprintx.modules.dns.module import DnsModule, _unquote
from footprintx.modules.http_probe.module import HttpProbeModule
from footprintx.modules.port_scanning.module import PortScanningModule
from footprintx.modules.shodan.module import ShodanModule
from footprintx.modules.web_fuzzing.module import WebFuzzingModule
from footprintx.reporting.correlator import correlate
from footprintx.utils.fingerprints import fingerprint, missing_security_headers

DOMAIN = Target("example.com", TargetType.DOMAIN)


def make_context(tmp_path, targets=(DOMAIN,), scope=("example.com",), passive=False):
    return ScanContext("s1", tmp_path, Settings(), ScopeManager(list(scope)), list(targets),
                       passive=passive)


def add_result(context, module, *findings):
    context.results[module] = ModuleResult(module, ModuleStatus.SUCCESS, list(findings))


def test_input_helpers_respect_scope_and_dns(tmp_path):
    ctx = make_context(tmp_path)
    add_result(ctx, "subdomains",
               Finding(FindingKind.SUBDOMAIN, "app.example.com", "t"),
               Finding(FindingKind.SUBDOMAIN, "gone.example.com", "t"),
               Finding(FindingKind.SUBDOMAIN, "cdn.other.net", "t"))
    assert common.scan_hostnames(ctx) == ["example.com", "app.example.com", "gone.example.com"]

    add_result(ctx, "dns",
               Finding(FindingKind.IP_ADDRESS, "93.184.215.10", "dns", "app.example.com",
                       {"hostnames": ["app.example.com"]}),
               Finding(FindingKind.IP_ADDRESS, "93.184.215.1", "dns", "example.com",
                       {"hostnames": ["example.com"]}))
    assert common.resolved_hostnames(ctx) == ["example.com", "app.example.com"]
    # IPs resolved from hostnames are not port-scanned directly (could be a CDN)
    assert common.scan_ips(ctx) == []
    assert sorted(common.all_known_ips(ctx)) == ["93.184.215.1", "93.184.215.10"]


def test_names_pointing_at_internal_addresses_are_not_scanned(tmp_path):
    """SSRF-style guard: an in-scope *name* must not steer active scans at the scanner's
    own loopback, the cloud metadata service, or (by default) internal networks."""
    ctx = make_context(tmp_path)
    hosts = {"www.example.com": "93.184.215.14", "local.example.com": "127.0.0.1",
             "meta.example.com": "169.254.169.254", "intranet.example.com": "10.1.2.3"}
    add_result(ctx, "subdomains", *(Finding(FindingKind.SUBDOMAIN, h, "t") for h in hosts))
    add_result(ctx, "dns", *(Finding(FindingKind.IP_ADDRESS, ip, "dns", h, {"hostnames": [h]})
                             for h, ip in hosts.items()))
    assert common.internal_hosts(ctx) == {"local.example.com": "local",
                                          "meta.example.com": "local",
                                          "intranet.example.com": "internal"}
    assert common.resolved_hostnames(ctx) == ["www.example.com"]

    # --allow-internal lets internal (never local) addresses through
    ctx.settings.safety.allow_internal_targets = True
    assert common.resolved_hostnames(ctx) == ["www.example.com", "intranet.example.com"]

    # an address the user explicitly put in scope is always allowed
    ctx.settings.safety.allow_internal_targets = False
    ctx.scope = ScopeManager(["example.com", "10.0.0.0/8"])
    assert "intranet.example.com" in common.resolved_hostnames(ctx)


def test_live_urls_falls_back_to_seed_urls(tmp_path):
    url = Target("https://app.example.com/", TargetType.URL)
    ctx = make_context(tmp_path, targets=[url])
    assert common.live_urls(ctx) == ["https://app.example.com/"]
    add_result(ctx, "http_probe",
               Finding(FindingKind.URL, "https://app.example.com", "x", data={"live": True}))
    assert common.live_urls(ctx) == ["https://app.example.com"]


async def test_dns_drops_wildcard_only_subdomains(tmp_path, monkeypatch):
    answers = {
        ("example.com", "A"): [("192.0.2.1", 300)],
        ("example.com", "TXT"): [('"v=spf1 -all"', 300)],
        ("real.example.com", "A"): [("192.0.2.10", 300)],
        ("junk.example.com", "A"): [("198.51.100.9", 300)],
    }

    async def fake_query(self, name, rtype, resolver=None):
        if name.startswith("fx-") and rtype == "A":
            return [("198.51.100.9", 60)]          # wildcard answer
        return answers.get((name, rtype), [])

    monkeypatch.setattr(DnsModule, "_query", fake_query)
    ctx = make_context(tmp_path, passive=True)
    add_result(ctx, "subdomains",
               Finding(FindingKind.SUBDOMAIN, "real.example.com", "t"),
               Finding(FindingKind.SUBDOMAIN, "junk.example.com", "t"))
    result = await DnsModule(ModuleConfig()).run(ctx)

    ips = {(f.target, f.value) for f in result.findings if f.kind is FindingKind.IP_ADDRESS}
    assert ips == {("example.com", "192.0.2.1"), ("real.example.com", "192.0.2.10")}
    assert "1 names only matched wildcard DNS and were ignored" in result.notes
    titles = {f.value for f in result.findings if f.kind is FindingKind.OBSERVATION}
    assert {"Wildcard DNS enabled", "No DMARC record", "No CAA record"} <= titles
    assert "No SPF record" not in titles


def test_txt_unquote():
    assert _unquote('"v=spf1 include:_spf.example.com" " -all"') == \
        "v=spf1 include:_spf.example.com -all"


async def test_fetch_in_scope_stops_at_out_of_scope_redirect():
    def handler(request):
        if request.url.host == "app.example.com":
            return httpx.Response(302, headers={"location": "https://evil.net/"})
        raise AssertionError("followed a redirect out of scope")

    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        response = await common.fetch_in_scope(client, "https://app.example.com/",
                                               ScopeManager(["example.com"]))
    assert response.status_code == 302


async def test_http_probe_native(tmp_path, monkeypatch):
    def handler(request):
        if request.url.scheme == "https":
            return httpx.Response(200, text="<html><title> Welcome &amp; Hi </title></html>",
                                  headers={"server": "nginx"})
        return httpx.Response(301, headers={"location": "https://example.com/"})

    real_client = httpx.AsyncClient
    monkeypatch.setattr("footprintx.modules.http_probe.module.make_client",
                        lambda *a, **k: real_client(transport=httpx.MockTransport(handler)))
    monkeypatch.setattr("footprintx.modules.http_probe.module.fetch_certificate",
                        lambda host, port, timeout: {"valid": False, "error": "self-signed"})
    ctx = make_context(tmp_path)
    result = await HttpProbeModule(ModuleConfig(engine="native")).run(ctx)

    urls = {f.value: f.data for f in result.findings if f.kind is FindingKind.URL}
    assert urls["https://example.com"]["title"] == "Welcome & Hi"
    assert urls["http://example.com"]["status_code"] == 301
    titles = {f.value for f in result.findings if f.kind is FindingKind.OBSERVATION}
    assert titles == {"Invalid TLS certificate"}  # http redirects to https: not flagged


async def test_port_scan_uses_nmap_and_flags_risky_services(tmp_path, monkeypatch):
    ctx = make_context(tmp_path)
    xml = """<nmaprun><host><status state="up"/><address addr="192.0.2.1" addrtype="ipv4"/>
      <hostnames><hostname name="example.com" type="user"/></hostnames><ports>
      <port protocol="tcp" portid="6379"><state state="open"/><service name="redis"/></port>
      </ports></host></nmaprun>"""

    async def fake_run_tool(context, tool, path, args, raw_name, timeout):
        (context.raw_dir / "nmap.xml").write_text(xml)
        return CommandResult(args, 0, "", "", 1.0)

    ctx.raw_dir.mkdir(parents=True)
    monkeypatch.setattr("footprintx.modules.port_scanning.module.run_tool", fake_run_tool)
    monkeypatch.setattr("footprintx.modules.port_scanning.module.locate",
                        lambda context, tool: f"/usr/bin/{tool.name}")
    result = await PortScanningModule(ModuleConfig()).run(ctx)
    assert result.status is ModuleStatus.SUCCESS
    kinds = {(f.kind, f.value) for f in result.findings}
    assert (FindingKind.OPEN_PORT, "example.com:6379/tcp") in kinds
    assert (FindingKind.OBSERVATION, "Redis exposed") in kinds


async def test_web_fuzzing_observations_and_missing_tools(tmp_path, monkeypatch):
    ctx = make_context(tmp_path)
    add_result(ctx, "http_probe",
               Finding(FindingKind.URL, "https://example.com", "x", data={"live": True}))
    wordlist = tmp_path / "words.txt"
    wordlist.write_text(".git/HEAD\nadmin\n")

    monkeypatch.setattr("footprintx.modules.web_fuzzing.module.locate",
                        lambda context, tool: None)
    result = await WebFuzzingModule(ModuleConfig(wordlist=str(wordlist))).run(ctx)
    assert result.status is ModuleStatus.SKIPPED

    async def fake_ffuf(self, tool, path, base, wl, context):
        return tool.parse(json.dumps({"results": [
            {"status": 200, "url": f"{base}/.git/HEAD"},
            {"status": 403, "url": f"{base}/admin"},
            {"status": 200, "url": f"{base}/about"}]}), base)

    monkeypatch.setattr("footprintx.modules.web_fuzzing.module.locate",
                        lambda context, tool: f"/usr/bin/{tool.name}")
    monkeypatch.setattr(WebFuzzingModule, "_ffuf", fake_ffuf)
    result = await WebFuzzingModule(ModuleConfig(wordlist=str(wordlist))).run(ctx)
    obs = {f.value: f.data["severity"] for f in result.findings
           if f.kind is FindingKind.OBSERVATION}
    assert obs == {"Exposed Git repository": "high",
                   "Administrative or login interface found": "info"}


async def test_shodan_skipped_without_key(tmp_path, monkeypatch):
    monkeypatch.delenv("SHODAN_API_KEY", raising=False)
    result = await ShodanModule(ModuleConfig()).run(make_context(tmp_path))
    assert result.status is ModuleStatus.SKIPPED


def test_fingerprints():
    techs = fingerprint(
        {"Server": "Apache/2.4.57 (Debian)", "X-Powered-By": "PHP/8.2.7", "CF-RAY": "x"},
        ["PHPSESSID", "wordpress_logged_in"],
        '<meta name="generator" content="WordPress 6.4.2"><script src="jquery-3.7.1.min.js">')
    found = {t.name: t.version for t in techs}
    assert found["Apache"] == "2.4.57"
    assert found["PHP"] == "8.2.7"
    assert found["WordPress"] == "6.4.2"
    assert found["jQuery"] == "3.7.1"
    assert "Cloudflare" in found
    assert missing_security_headers({"X-Frame-Options": "DENY"}, https=False) == [
        "Content-Security-Policy", "X-Content-Type-Options"]


def test_correlator_builds_asset_tree():
    findings = [
        Finding(FindingKind.SUBDOMAIN, "app.example.com", "subfinder", "example.com"),
        Finding(FindingKind.IP_ADDRESS, "192.0.2.10", "dns", "app.example.com",
                {"hostnames": ["app.example.com"]}),
        Finding(FindingKind.URL, "https://app.example.com", "httpx", "app.example.com",
                {"live": True, "status_code": 200, "title": "Login"}),
        Finding(FindingKind.OPEN_PORT, "192.0.2.10:443/tcp", "shodan", "192.0.2.10",
                {"host": "192.0.2.10", "port": 443, "protocol": "tcp", "service": "https"}),
        Finding(FindingKind.TECHNOLOGY, "Nginx", "httpx", "https://app.example.com",
                {"version": "1.24", "host": "app.example.com"}),
        Finding(FindingKind.OBSERVATION, "Exposed Git repository", "web_fuzzing",
                "https://app.example.com/.git/HEAD", {"severity": "high"}),
    ]
    (group,) = correlate([DOMAIN], findings)
    (host,) = group["hosts"]
    assert host["host"] == "app.example.com"
    assert host["ips"] == ["192.0.2.10"]
    assert host["ports"][0]["port"] == 443          # attached via the IP
    assert host["technologies"] == ["Nginx 1.24"]
    assert host["observations"][0]["severity"] == "high"
