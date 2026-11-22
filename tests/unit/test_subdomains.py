import json

from footprintx.core.config import ModuleConfig, Settings
from footprintx.core.context import ScanContext
from footprintx.core.models import Finding, FindingKind, ModuleStatus, Target, TargetType
from footprintx.core.scope_manager import ScopeManager
from footprintx.integrations import INTEGRATION_REGISTRY
from footprintx.integrations.crtsh import CrtShIntegration
from footprintx.modules.subdomains.module import SubdomainModule
from footprintx.reporting.deduplicator import deduplicate
from footprintx.utils.validators import hostnames_in


def test_hostnames_in_filters_to_domain_and_strips_wildcards():
    text = "*.example.com\nApp.Example.com.\nexample.com\nevil.com\nnotexample.com\n"
    assert hostnames_in(text, "example.com") == ["example.com", "app.example.com"]


def test_subfinder_parse_drops_apex_and_foreign_hosts():
    out = "api.example.com\nexample.com\nfoo.other.org\n"
    findings = INTEGRATION_REGISTRY["subfinder"].parse(out, "example.com")
    assert [f.value for f in findings] == ["api.example.com"]
    assert findings[0].source == "subfinder"


def test_amass_graph_output_is_parsed():
    out = ("www.example.com (FQDN) --> a_record --> 192.0.2.1 (IPAddress)\n"
           "example.com (FQDN) --> ns_record --> ns1.dns-host.net (FQDN)\n")
    findings = INTEGRATION_REGISTRY["amass"].parse(out, "example.com")
    assert [f.value for f in findings] == ["www.example.com"]


def test_crtsh_parse():
    raw = json.dumps([
        {"name_value": "example.com\n*.example.com"},
        {"name_value": "mail.example.com\nwww.example.com"},
    ])
    findings = CrtShIntegration().parse(raw, "example.com")
    assert [f.value for f in findings] == ["mail.example.com", "www.example.com"]
    assert CrtShIntegration().parse("<html>busy</html>", "example.com") == []


def test_deduplicate_merges_sources():
    a = Finding(FindingKind.SUBDOMAIN, "app.example.com", "subfinder", data={"x": 1})
    b = Finding(FindingKind.SUBDOMAIN, "APP.example.com", "crtsh", data={"y": 2})
    (merged,) = deduplicate([a, b])
    assert merged.data == {"x": 1, "y": 2, "sources": ["subfinder", "crtsh"]}


async def test_module_combines_sources_scope_filters_and_survives_failures(tmp_path, monkeypatch):
    async def fake_tool(self, tool, path, domain, context):
        if tool.name == "assetfinder":
            raise RuntimeError("network unreachable")
        return tool.parse("a.example.com\nb.example.com\nout.example.com\n", domain)

    async def fake_crtsh(self, client, domain, context):
        return client.parse(json.dumps([{"name_value": "b.example.com\nc.example.com"}]), domain)

    monkeypatch.setattr(SubdomainModule, "_run_tool", fake_tool)
    monkeypatch.setattr(SubdomainModule, "_run_crtsh", fake_crtsh)
    for name in ("subfinder", "assetfinder"):
        monkeypatch.setattr(type(INTEGRATION_REGISTRY[name]), "locate",
                            lambda self, override=None: "/usr/bin/fake")

    context = ScanContext(
        "s1", tmp_path, Settings(),
        ScopeManager(["example.com"], exclude=["out.example.com"]),
        [Target("example.com", TargetType.DOMAIN)],
    )
    result = await SubdomainModule(ModuleConfig()).run(context)

    assert result.status is ModuleStatus.SUCCESS
    assert sorted({f.value for f in result.findings}) == [
        "a.example.com", "b.example.com", "c.example.com"]
    assert result.errors == ["assetfinder (example.com): network unreachable"]
    assert "1 out-of-scope hostnames discarded" in result.notes


async def test_module_skips_when_no_sources(tmp_path):
    context = ScanContext("s1", tmp_path, Settings(), ScopeManager(["example.com"]),
                          [Target("example.com", TargetType.DOMAIN)])
    result = await SubdomainModule(ModuleConfig(sources=["nope"])).run(context)
    assert result.status is ModuleStatus.SKIPPED
