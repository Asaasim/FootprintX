"""Parsers for external tool output, using samples in each tool's real format."""

import json

from footprintx.core.models import FindingKind
from footprintx.integrations import INTEGRATION_REGISTRY
from footprintx.integrations.rdap import RdapIntegration
from footprintx.integrations.shodan import ShodanIntegration

NMAP_XML = """<?xml version="1.0"?>
<nmaprun scanner="nmap">
  <host><status state="up"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <hostnames><hostname name="app.example.com" type="user"/>
               <hostname name="ptr.example.net" type="PTR"/></hostnames>
    <ports>
      <port protocol="tcp" portid="22"><state state="open"/>
        <service name="ssh" product="OpenSSH" version="9.2p1"/></port>
      <port protocol="tcp" portid="443"><state state="open"/>
        <service name="http" product="nginx" version="1.24.0" tunnel="ssl"/></port>
      <port protocol="tcp" portid="8080"><state state="closed"/></port>
    </ports>
  </host>
  <host><status state="down"/><address addr="192.0.2.11" addrtype="ipv4"/></host>
</nmaprun>"""


def test_nmap_ports():
    findings = INTEGRATION_REGISTRY["nmap"].parse(NMAP_XML)
    assert [f.value for f in findings] == ["app.example.com:22/tcp", "app.example.com:443/tcp"]
    assert findings[1].data["product"] == "nginx"
    assert findings[1].data["tunnel"] == "ssl"
    assert findings[0].data["ip"] == "192.0.2.10"


def test_nmap_top_ports_from_services_table(tmp_path):
    services = tmp_path / "nmap-services"
    services.write_text("# comment\nhttp\t80/tcp\t0.48\nssh\t22/tcp\t0.18\n"
                        "snmp\t161/udp\t0.43\nredis\t6379/tcp\t0.00007\n")
    nmap = INTEGRATION_REGISTRY["nmap"]
    assert nmap.top_tcp_ports(2, (str(services),)) == [80, 22]
    assert nmap.top_tcp_ports(2, (str(tmp_path / "missing"),)) is None
    args = nmap.port_scan_args("t", "o.xml", top_ports=2, raw_sockets=True, ports=[22, 6379])
    assert args[args.index("-p") + 1] == "T:22,6379" and "--top-ports" not in args


def test_nmap_sweep_and_bad_xml():
    nmap = INTEGRATION_REGISTRY["nmap"]
    assert nmap.parse_sweep(NMAP_XML) == ["192.0.2.10"]
    assert nmap.parse("<not xml") == []


def test_naabu_json_lines():
    out = ('{"host":"app.example.com","ip":"192.0.2.10","port":443,"protocol":"tcp"}\n'
           'garbage\n{"ip":"192.0.2.11","port":{"Port":22,"Protocol":0}}\n')
    findings = INTEGRATION_REGISTRY["naabu"].parse(out)
    assert [f.value for f in findings] == ["app.example.com:443/tcp", "192.0.2.11:22/tcp"]


def test_naabu_top_ports_presets():
    naabu = INTEGRATION_REGISTRY["naabu"]
    args = naabu.port_scan_args("t.txt", top_ports=250, rate=100, raw_sockets=False)
    assert args[args.index("-top-ports") + 1] == "1000"
    assert args[args.index("-scan-type") + 1] == "c"


def test_httpx_probes():
    out = "\n".join(json.dumps(row) for row in [
        {"url": "https://app.example.com", "input": "app.example.com", "status_code": 200,
         "title": "Login", "webserver": "nginx", "tech": ["Nginx:1.24.0", "PHP"],
         "content_length": 512, "a": ["192.0.2.10"]},
        {"url": "http://app.example.com:8080", "status_code": 301,
         "location": "https://app.example.com/"},
        {"url": "https://down.example.com", "failed": True},
    ])
    probes = INTEGRATION_REGISTRY["httpx"].parse_probes(out)
    assert [p["url"] for p in probes] == ["https://app.example.com", "http://app.example.com:8080"]
    assert probes[0]["port"] == 443 and probes[1]["port"] == 8080
    assert probes[0]["tech"] == ["Nginx:1.24.0", "PHP"]


def test_whatweb_array_and_lines():
    entry = {"target": "https://app.example.com/", "http_status": 200, "plugins": {
        "nginx": {"version": ["1.24.0"]}, "WordPress": {"version": ["6.4"]},
        "Country": {"string": ["RESERVED"]}, "Title": {"string": ["Login"]}}}
    whatweb = INTEGRATION_REGISTRY["whatweb"]
    for text in (json.dumps([entry]), json.dumps(entry) + ",\n"):
        findings = whatweb.parse(text)
        assert sorted((f.value, f.data["version"]) for f in findings) == [
            ("WordPress", "6.4"), ("nginx", "1.24.0")]
        assert findings[0].target == "https://app.example.com"


def test_ffuf_results():
    out = json.dumps({"results": [
        {"input": {"FUZZ": ".git/HEAD"}, "status": 200, "length": 23, "words": 2,
         "url": "https://app.example.com/.git/HEAD", "redirectlocation": ""},
        {"input": {"FUZZ": "admin"}, "status": 301, "length": 0,
         "url": "https://app.example.com/admin", "redirectlocation": "/admin/"}]})
    findings = INTEGRATION_REGISTRY["ffuf"].parse(out, "https://app.example.com")
    assert [f.value for f in findings] == ["https://app.example.com/.git/HEAD",
                                           "https://app.example.com/admin"]
    assert findings[1].data["redirect"] == "/admin/"
    assert INTEGRATION_REGISTRY["ffuf"].parse("not json") == []


def test_gobuster_lines():
    out = ("/admin                (Status: 301) [Size: 169] [--> http://x/admin/]\n"
           "backup.zip           (Status: 200) [Size: 1024]\n"
           "Progress: 4614 / 4615\n")
    findings = INTEGRATION_REGISTRY["gobuster"].parse(out, "http://x")
    assert [(f.value, f.data["status"]) for f in findings] == [
        ("http://x/admin", 301), ("http://x/backup.zip", 200)]


def test_theharvester_json():
    out = json.dumps({"emails": ["Info@Example.com", "x@other.org"],
                      "hosts": ["mail.example.com:192.0.2.5", "www.example.com", "foo.bar"]})
    findings = INTEGRATION_REGISTRY["theharvester"].parse(out, "example.com")
    assert [(f.kind, f.value) for f in findings] == [
        (FindingKind.EMAIL, "info@example.com"),
        (FindingKind.SUBDOMAIN, "mail.example.com"),
        (FindingKind.SUBDOMAIN, "www.example.com")]


def test_rdap_domain_and_ip_summaries():
    domain = {
        "events": [{"eventAction": "registration", "eventDate": "1995-08-14T04:00:00Z"},
                   {"eventAction": "expiration", "eventDate": "2027-08-13T04:00:00Z"}],
        "entities": [{"roles": ["registrar"],
                      "vcardArray": ["vcard", [["version", {}, "text", "4.0"],
                                               ["fn", {}, "text", "Example Registrar"]]]}],
        "nameservers": [{"ldhName": "A.IANA-SERVERS.NET"}, {"ldhName": "B.IANA-SERVERS.NET"}],
        "status": ["client delete prohibited"],
    }
    info = RdapIntegration.summarise_domain(domain)
    assert info["registrar"] == "Example Registrar"
    assert info["nameservers"] == ["a.iana-servers.net", "b.iana-servers.net"]
    assert info["created"].startswith("1995")

    ip = {"name": "EXAMPLE-NET", "startAddress": "192.0.2.0", "endAddress": "192.0.2.255",
          "country": "US", "cidr0_cidrs": [{"v4prefix": "192.0.2.0", "length": 24}],
          "entities": [{"roles": ["registrant"], "handle": "EX-1",
                        "vcardArray": ["vcard", [["fn", {}, "text", "Example Org"]]]}]}
    ip_info = RdapIntegration.summarise_ip(ip)
    assert ip_info["organisation"] == "Example Org"
    assert ip_info["cidrs"] == ["192.0.2.0/24"]


def test_shodan_summary():
    data = {"org": "Example Hosting", "ports": [443, 22], "vulns": {"CVE-2023-0001": {}},
            "hostnames": ["app.example.com"],
            "data": [{"port": 443, "transport": "tcp", "product": "nginx",
                      "_shodan": {"module": "https"}}]}
    info = ShodanIntegration.summarise(data)
    assert info["ports"] == [22, 443]
    assert info["vulns"] == ["CVE-2023-0001"]
    assert info["services"][0]["module"] == "https"
