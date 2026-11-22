"""Lightweight built-in web technology fingerprints (headers, cookies, HTML)."""

from __future__ import annotations

import re
from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class Tech:
    name: str
    version: str = ""
    category: str = ""


_SERVER = re.compile(r"([A-Za-z][\w.-]*)(?:/([\w.-]+))?")

#: header (lower-case) present → technology
HEADER_PRESENCE = {
    "cf-ray": Tech("Cloudflare", category="CDN"),
    "x-amz-cf-id": Tech("Amazon CloudFront", category="CDN"),
    "x-fastly-request-id": Tech("Fastly", category="CDN"),
    "x-akamai-transformed": Tech("Akamai", category="CDN"),
    "x-vercel-id": Tech("Vercel", category="Hosting"),
    "x-github-request-id": Tech("GitHub Pages", category="Hosting"),
    "x-drupal-cache": Tech("Drupal", category="CMS"),
    "x-shopify-stage": Tech("Shopify", category="E-commerce"),
    "x-aspnet-version": Tech("ASP.NET", category="Framework"),
    "x-azure-ref": Tech("Azure Front Door", category="CDN"),
    "x-sucuri-id": Tech("Sucuri", category="WAF"),
}

#: cookie name prefix → technology
COOKIES = {
    "phpsessid": Tech("PHP", category="Language"),
    "jsessionid": Tech("Java", category="Language"),
    "asp.net_sessionid": Tech("ASP.NET", category="Framework"),
    "laravel_session": Tech("Laravel", category="Framework"),
    "ci_session": Tech("CodeIgniter", category="Framework"),
    "wordpress_": Tech("WordPress", category="CMS"),
    "wp-settings": Tech("WordPress", category="CMS"),
    "connect.sid": Tech("Express", category="Framework"),
    "csrftoken": Tech("Django", category="Framework"),
    "__cf_bm": Tech("Cloudflare", category="CDN"),
    "awselb": Tech("AWS Elastic Load Balancing", category="Load balancer"),
}

#: regex on HTML → technology (version from group 1 if present)
BODY = [
    (re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', re.I), None),
    (re.compile(r"/wp-(?:content|includes)/"), Tech("WordPress", category="CMS")),
    (re.compile(r"Drupal\.settings|/sites/default/files/"), Tech("Drupal", category="CMS")),
    (re.compile(r"/media/jui/|Joomla!"), Tech("Joomla", category="CMS")),
    (re.compile(r'id="__NEXT_DATA__"'), Tech("Next.js", category="JavaScript framework")),
    (re.compile(r"window\.__NUXT__"), Tech("Nuxt.js", category="JavaScript framework")),
    (re.compile(r'ng-version="([\d.]+)"'), Tech("Angular", category="JavaScript framework")),
    (re.compile(r"data-reactroot|react-dom(?:\.production)?\.min\.js"),
     Tech("React", category="JavaScript framework")),
    (re.compile(r"jquery[.-]?(\d+\.\d+(?:\.\d+)?)(?:\.min)?\.js", re.I),
     Tech("jQuery", category="JavaScript library")),
    (re.compile(r"bootstrap(?:\.min)?\.(?:css|js)", re.I), Tech("Bootstrap", category="UI")),
    (re.compile(r"cdn\.shopify\.com"), Tech("Shopify", category="E-commerce")),
]

SECURITY_HEADERS = {
    "strict-transport-security": "Strict-Transport-Security (HSTS)",
    "content-security-policy": "Content-Security-Policy",
    "x-frame-options": "X-Frame-Options",
    "x-content-type-options": "X-Content-Type-Options",
}


def fingerprint(headers: Mapping[str, str], cookies: list[str], body: str) -> list[Tech]:
    found: dict[str, Tech] = {}

    def add(tech: Tech) -> None:
        if tech.name not in found or (tech.version and not found[tech.name].version):
            found[tech.name] = tech

    lower = {k.lower(): v for k, v in headers.items()}
    for header, category in (("server", "Web server"), ("x-powered-by", "Framework")):
        for match in _SERVER.finditer(lower.get(header, "")):
            name = match.group(1)
            if name.lower() not in {"ubuntu", "debian", "centos", "win64", "unix"}:
                add(Tech(name, match.group(2) or "", category))
            break  # first product only, e.g. "Apache/2.4.57 (Debian)"
    for header, tech in HEADER_PRESENCE.items():
        if header in lower:
            add(tech)
    if "cloudflare" in lower.get("server", "").lower():
        add(Tech("Cloudflare", category="CDN"))
    if "varnish" in lower.get("via", "").lower() or "x-varnish" in lower:
        add(Tech("Varnish", category="Cache"))

    for cookie in (c.lower() for c in cookies):
        for prefix, tech in COOKIES.items():
            if cookie.startswith(prefix):
                add(tech)

    for pattern, rule in BODY:
        hit = pattern.search(body)
        if not hit:
            continue
        if rule is None:  # meta generator: "WordPress 6.4.2"
            name, _, version = hit.group(1).strip().partition(" ")
            add(Tech(name, version.strip(), "Generator"))
        else:
            version = hit.group(1) if hit.groups() else ""
            add(Tech(rule.name, version or rule.version, rule.category))
    return list(found.values())


def missing_security_headers(headers: Mapping[str, str], https: bool) -> list[str]:
    lower = {k.lower() for k in headers}
    missing = [label for header, label in SECURITY_HEADERS.items() if header not in lower]
    if not https:
        missing = [m for m in missing if not m.startswith("Strict-Transport")]
    return missing
