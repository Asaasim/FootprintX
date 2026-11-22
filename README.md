# FootprintX

FootprintX is a cybersecurity reconnaissance tool for digital footprint discovery, asset enumeration, and attack surface mapping, helping security professionals identify and assess exposed assets.

**One target. One command. Comprehensive reconnaissance.** Full specification: [Spectifications.md](Spectifications.md).

> Only scan targets you are authorised to test. FootprintX asks for confirmation before every scan and keeps all activity inside the targets you give it (see `scope:` in `config/config.yaml`).

## New to this? Start here

**[docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)** — install on Kali Linux and run your first scan in plain language. In short:

```bash
bash install.sh      # once, on Kali Linux
footprintx           # answer three questions; the report opens in your browser
```

## What it does

Give it a domain, URL, IP address, IP range or a file of targets. FootprintX works out what applies and runs it, in dependency order, in parallel where possible:

| Step | Tools (Kali packages) | Built-in fallback |
| --- | --- | --- |
| Subdomain discovery | Subfinder, Assetfinder, Amass (optional), crt.sh | — |
| Public intelligence (OSINT) | theHarvester, RDAP registration data | RDAP only |
| DNS records + SPF / DMARC / CAA / zone-transfer / wildcard checks | — | native resolver |
| IP mapping, live-host sweep of ranges, reverse DNS | Nmap | all addresses kept |
| Website probing (status, title, server, redirects, TLS certificate) | httpx-toolkit | native prober |
| Port & service scanning (top 1000 + risky services such as Redis, MongoDB, RDP) | Nmap, Naabu | — |
| Technology fingerprinting + security headers | WhatWeb, httpx-toolkit | native fingerprints |
| Hidden files & folders (`.git`, `.env`, backups, admin panels) | FFUF, Gobuster | — |
| Shodan lookups (optional, needs `SHODAN_API_KEY`) | Shodan API | — |
| Send findings to Burp Suite / ZAP (off by default) | your proxy | — |

A failing or missing tool never stops the scan: its step is skipped or falls back, and the report says so. **Passive mode** (`--passive`, or option 2 in the guided mode) uses public sources only and never contacts the target's servers.

Every scan creates `results/<target>/scan_<timestamp>/` with `reports/report.html` (readable summary, security observations ranked by severity, per-host attack-surface map), `report.json`, `report.txt`, per-category files (`subdomains.txt`, `open_ports.json`, …), `scan.log` and untouched tool output in `raw/`. Scan history is kept in `results/footprintx.db` (`footprintx history`).

## Commands

```bash
footprintx                                       # guided mode
footprintx scan -t example.com                   # domain, subdomain, URL, IP, IPv6 or CIDR; repeatable
footprintx scan -l targets.txt -o ./results      # bulk targets
footprintx scan -t example.com --passive         # public sources only
footprintx scan -t example.com --exclude shodan,web_fuzzing
footprintx scan -t example.com --dry-run         # show the execution plan only
footprintx scan -t example.com --yes -v          # skip the authorisation prompt, debug logs
footprintx doctor                                # check tools, API keys, config
footprintx modules list
footprintx history
```

## Kali Linux (native)

`bash install.sh` installs the tools from Kali's repositories, installs FootprintX with pipx, creates `~/.config/footprintx/` (settings, `.env` for API keys, default wordlist), adds a menu entry and runs `footprintx doctor`. Options: `WITH_SECLISTS=1` (full SecLists, ~1 GB), `DEV=1` (editable `.venv` install).

Notes: Kali ships ProjectDiscovery's httpx as `httpx-toolkit` (`/usr/bin/httpx` is the Python library) — handled automatically. Kali's nmap has raw-socket capabilities, so SYN scans work without sudo. Results default to `~/FootprintX-results`.

## Docker

The image is based on `kalilinux/kali-rolling` with every tool and a default wordlist.

```bash
cp .env.example .env                                   # optional: SHODAN_API_KEY
docker compose build
docker compose run --rm footprintx                     # guided mode
docker compose run --rm footprintx doctor
docker compose run --rm footprintx scan -t example.com --yes
docker compose run --rm footprintx scan -l targets/targets.txt --yes   # file in ./targets
```

Results go to `./results`; `./config` is mounted read-only; files in `./wordlists` appear at `/app/wordlists/custom`; bulk target files go in `./targets` (gitignored). The container drops all Linux capabilities except `NET_RAW` (for SYN scans). Build args: `INSTALL_AMASS=false` leaves Amass out; `UID=$(id -u)` matches the container user to yours on Linux. To reach Burp/ZAP on the host, set the proxy URL to `http://host.docker.internal:8080`.

## Development

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest && ruff check footprintx tests && mypy footprintx
```

Tests also run in the container: `docker compose --profile dev run --rm tests`.

```text
footprintx/
├── cli.py            guided mode + scan / doctor / modules / history commands
├── core/             config, targets, scope, scheduler, engine, orchestrator, logging
├── modules/          one package per recon step; base.py = BaseModule, common.py = input helpers
├── integrations/     wrappers that run external tools / call APIs and parse their output
├── reporting/        normalise → dedupe → correlate → JSON / HTML / TXT reports
├── database/         SQLite scan history
└── utils/            validators, platform detection, TLS, fingerprints, rate limiting, doctor
```

**Adding a module:** create `footprintx/modules/<name>/module.py` subclassing `BaseModule` (set `name`, `applies_to`, `depends_on`, `active`), register it in `footprintx/modules/__init__.py`, and the scheduler places it by its dependencies.
