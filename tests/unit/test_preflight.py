"""Pre-scan checks: typos and missing internet are caught in seconds, not after a scan."""

from footprintx.core import preflight
from footprintx.core.target_parser import TargetParser

parse = TargetParser().parse


async def _run(monkeypatch, statuses, *raw):
    async def fake_status(resolver, name, rtype="SOA"):
        return statuses.get(name, "ok")

    monkeypatch.setattr(preflight, "_status", fake_status)
    return await preflight.check_targets([parse(r) for r in raw])


async def test_typo_domain_is_skipped(monkeypatch):
    result = await _run(monkeypatch, {"exmaple.com": "nxdomain"},
                        "exmaple.com", "https://shop.exmaple.com/x", "example.com")
    assert [t.value for t in result.usable] == ["example.com"]
    assert len(result.missing) == 2 and "check the spelling" in result.missing[0][1]
    assert not result.offline


async def test_missing_subdomain_of_real_domain_is_kept(monkeypatch):
    result = await _run(monkeypatch, {"old.example.com": "nxdomain"}, "old.example.com")
    assert [t.value for t in result.usable] == ["old.example.com"]


async def test_no_internet_is_detected(monkeypatch):
    result = await _run(monkeypatch, {"example.com": "timeout", "example.org": "timeout"},
                        "example.com", "example.org")
    assert result.offline and not result.usable


async def test_slow_dns_for_one_target_is_not_offline(monkeypatch):
    result = await _run(monkeypatch, {"slow.example": "timeout"}, "slow.example",
                        "example.com", "10.0.0.1")
    assert not result.offline
    assert {t.value for t in result.usable} == {"slow.example", "example.com", "10.0.0.1"}


async def test_ip_targets_need_no_dns(monkeypatch):
    result = await _run(monkeypatch, {}, "203.0.113.5", "192.168.1.0/24")
    assert len(result.usable) == 2
