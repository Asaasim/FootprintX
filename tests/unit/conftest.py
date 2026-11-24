import pytest


@pytest.fixture(autouse=True)
def no_network_preflight(request, monkeypatch):
    """CLI tests must not depend on real DNS: the pre-scan check passes everything
    through (tests/unit/test_preflight.py tests the check itself)."""
    if request.module.__name__.endswith("test_preflight"):
        return
    from footprintx import cli
    from footprintx.core.preflight import PreflightResult

    async def passthrough(targets, resolvers=None):
        return PreflightResult(usable=list(targets))

    monkeypatch.setattr(cli, "check_targets", passthrough)


@pytest.fixture(autouse=True)
def no_dns_over_https(monkeypatch):
    from footprintx.modules.dns import module

    async def unavailable(name, rtype):
        return None

    monkeypatch.setattr(module, "doh_lookup", unavailable)
