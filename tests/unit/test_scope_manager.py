from footprintx.core.config import ScopeConfig
from footprintx.core.scope_manager import ScopeManager
from footprintx.core.target_parser import TargetParser


def test_domain_scope_includes_subdomains_and_honours_exclusions():
    scope = ScopeManager(include=["example.com"], exclude=["dev.example.com"])
    assert scope.is_in_scope("example.com")
    assert scope.is_in_scope("app.example.com")
    assert scope.is_in_scope("https://app.example.com/login")
    assert not scope.is_in_scope("dev.example.com")
    assert not scope.is_in_scope("api.dev.example.com")
    assert not scope.is_in_scope("notexample.com")
    assert not scope.is_in_scope("example.com.evil.net")


def test_network_scope():
    scope = ScopeManager(include=["192.0.2.0/24", "2001:db8::/32"], exclude=["192.0.2.128/25"])
    assert scope.is_in_scope("192.0.2.10")
    assert scope.is_in_scope("192.0.2.0/26")
    assert not scope.is_in_scope("192.0.2.200")
    assert not scope.is_in_scope("198.51.100.1")
    assert scope.is_in_scope("2001:db8::1")


def test_seed_targets_define_scope_when_none_configured():
    targets, _ = TargetParser().parse_many(["example.com", "https://shop.example.org/"])
    scope = ScopeManager.from_settings(ScopeConfig(), targets)
    assert scope.is_in_scope("www.example.com")
    assert scope.is_in_scope("shop.example.org")
    assert not scope.is_in_scope("example.org")
