# FootprintX

FootprintX is a cybersecurity reconnaissance tool for digital footprint discovery, asset enumeration, and attack surface mapping, helping security professionals identify and assess exposed assets.

**One target. One command. Comprehensive reconnaissance.** See [Spectifications.md](Spectifications.md) for the full specification.

> Only scan targets you are authorised to test. FootprintX enforces scope (see `scope:` in `config/config.yaml`).

## Quick start (Docker — recommended)

The image bundles every external tool (Subfinder, Amass, Assetfinder, DNSx, HTTPx, Naabu, Nmap, FFUF, Gobuster, WhatWeb) plus a default wordlist.

```bash
cp .env.example .env            # optional: add SHODAN_API_KEY etc.
docker compose build
docker compose run --rm footprintx doctor
docker compose run --rm footprintx scan -t example.com
docker compose run --rm footprintx scan -l targets/targets.txt   # file in ./targets
```

Results are written to `./results`. Bulk target files go in `./targets` (gitignored). `./config` is mounted read-only, so edit `config/config.yaml` on the host. Anything in `./wordlists` appears in the container at `/app/wordlists/custom`.

Build options: `--build-arg INSTALL_AMASS=false` skips the slow Amass build; `--build-arg UID=$(id -u)` matches the container user to your host user on Linux.

## Local development

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest
ruff check footprintx tests
footprintx --help
```

Running locally, external tools must be on your `PATH` (`scripts/install_tools.sh`), and `scripts/fetch_wordlists.sh` downloads the default wordlist. Tests can also run in the container: `docker compose --profile dev run --rm tests`.

## Commands

```bash
footprintx scan -t example.com                   # domain, subdomain, URL, IP, IPv6 or CIDR; repeatable
footprintx scan -l targets.txt -o ./results      # bulk targets
footprintx scan -t example.com --exclude shodan,proxy
footprintx doctor                                # check tools, API keys, config
footprintx modules list
footprintx --version
```

## Project layout

```text
footprintx/
├── cli.py                 Typer CLI (scan, doctor, modules list)
├── core/                  config, target parsing, scope, scheduler, engine, orchestrator
├── modules/               one package per recon capability (subdomains, dns, http_probe, ...)
│   └── base.py            BaseModule interface + MODULE_REGISTRY in __init__.py
├── integrations/          wrappers for external tools / APIs (+ INTEGRATION_REGISTRY)
├── reporting/             aggregate → normalise → dedupe → correlate → JSON/HTML/TXT
├── database/              SQLite scan history
└── utils/                 validators, helpers, dependency checker (doctor)
config/config.yaml         default configuration (no secrets — use .env)
tests/                     unit / integration / functional
scripts/                   local tool + wordlist installers
```

**Adding a module:** create `footprintx/modules/<name>/module.py` subclassing `BaseModule` (set `name`, `applies_to`, `depends_on`, `integrations`), then register it in `footprintx/modules/__init__.py`. The scheduler orders it by its dependencies automatically.
