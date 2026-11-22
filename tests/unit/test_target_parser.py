import pytest

from footprintx.core.models import TargetType
from footprintx.core.target_parser import InvalidTargetError, TargetParser


@pytest.fixture
def parser() -> TargetParser:
    return TargetParser()


@pytest.mark.parametrize(
    ("raw", "expected_type", "expected_value"),
    [
        ("example.com", TargetType.DOMAIN, "example.com"),
        ("  Example.COM.  ", TargetType.DOMAIN, "example.com"),
        ("example.co.uk", TargetType.DOMAIN, "example.co.uk"),
        ("app.example.com", TargetType.SUBDOMAIN, "app.example.com"),
        ("https://Example.com", TargetType.URL, "https://example.com/"),
        ("http://example.com:80/login", TargetType.URL, "http://example.com/login"),
        ("https://example.com:8443/a?b=1#frag", TargetType.URL, "https://example.com:8443/a?b=1"),
        ("http://[2001:db8::1]:8080/", TargetType.URL, "http://[2001:db8::1]:8080/"),
        ("192.168.1.10", TargetType.IPV4, "192.168.1.10"),
        ("2001:0db8:0000::1", TargetType.IPV6, "2001:db8::1"),
        ("192.168.1.0/24", TargetType.CIDR, "192.168.1.0/24"),
        ("192.168.1.77/24", TargetType.CIDR, "192.168.1.0/24"),
    ],
)
def test_parse_valid(parser, raw, expected_type, expected_value):
    target = parser.parse(raw)
    assert target.type is expected_type
    assert target.value == expected_value


@pytest.mark.parametrize(
    "raw",
    ["", "   ", "localhost", "not a domain", "-bad-.com", "999.1.1.1",
     "ftp://example.com", "example.com/path", "https://", "10.0.0.0/33"],
)
def test_parse_invalid(parser, raw):
    with pytest.raises(InvalidTargetError):
        parser.parse(raw)


def test_parse_many_dedupes_and_reports_invalid(parser):
    targets, invalid = parser.parse_many(["example.com", "EXAMPLE.com.", "nope", "10.0.0.1"])
    assert [t.value for t in targets] == ["example.com", "10.0.0.1"]
    assert [raw for raw, _ in invalid] == ["nope"]


def test_read_file_skips_blanks_and_comments(tmp_path):
    f = tmp_path / "targets.txt"
    f.write_text("# authorised targets\nexample.com\n\n  10.0.0.1  \n", encoding="utf-8")
    assert TargetParser.read_file(f) == ["example.com", "10.0.0.1"]
