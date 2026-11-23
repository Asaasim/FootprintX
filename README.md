# FootprintX

FootprintX is a cybersecurity reconnaissance tool for digital footprint discovery, asset enumeration, and attack surface mapping, helping security professionals identify and assess exposed assets.

**One target. One command. Comprehensive reconnaissance.** Full specification: [Spectifications.md](Spectifications.md).

> Only scan targets you are authorised to test. FootprintX asks for confirmation before every scan and keeps all activity inside the targets you give it (or the `--scope` you set — see *Configuration*).

## New to this? Start here

**[docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)** — install on Kali Linux and run your first scan, step by step in plain language. In short:

```bash
git clone https://github.com/Asaasim/FootprintX.git && cd FootprintX
bash install.sh      # once, as your normal user (asks for your password)
footprintx           # in a new terminal: answer three questions; the report opens in your browser
```

## What it does

Give it a domain, URL, IP address, IP range or a file of targets. FootprintX works out what applies and runs it, in dependency order, in parallel where possible:

| Step | Tools (Kali packages) | Built-in fallback |
| --- | --- | --- |
| Subdomain discovery | Subfinder, Assetfinder, Findomain, Amass (optional), crt.sh | zone transfers |
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

Every scan creates `<results>/<target>/scan_<timestamp>/` (`<results>` is `~/FootprintX-results` after `install.sh`, `./results` in Docker or a project checkout) with `reports/report.html` (readable summary, security observations ranked by severity, per-host attack-surface map), `report.json`, `report.txt`, `findings.csv`, per-category files (`subdomains.txt`, `open_ports.json`, `shodan_results.json`, …), `scan.log` (including an audit trail of every tool command run) and untouched tool output in `raw/`. Scan history is kept in `<results>/footprintx.db` (`footprintx history`); each scan is compared with the previous one of the same targets, and anything **new since the last scan** is highlighted.

## Commands

```bash
footprintx                                       # guided mode
footprintx scan -t example.com                   # domain, subdomain, URL, IP, IPv6 or CIDR; repeatable
footprintx scan -l targets.txt -o ./results      # bulk targets
footprintx scan -t example.com --passive         # public sources only
footprintx scan -t example.com --exclude shodan,web_fuzzing
footprintx scan -t example.com --scope scope.txt   # authorised scope (domains/IPs/CIDRs, or a file)
footprintx scan -t example.com -w words.txt      # custom fuzzing wordlist
footprintx scan -t corp.example --allow-internal # internal test: scan names resolving to 10.x etc.
footprintx scan -t example.com --dry-run         # show the execution plan only
footprintx scan -t example.com --yes -v          # skip the authorisation prompt, debug logs
footprintx doctor                                # check tools, API keys, config
footprintx modules list
footprintx history
```

## Kali Linux (native)

`bash install.sh` installs the tools from Kali's repositories, installs FootprintX with pipx, creates `~/.config/footprintx/` (settings, `.env` for API keys, default wordlist), adds a menu entry and runs `footprintx doctor`. Options: `WITH_SECLISTS=1` (full SecLists, ~1 GB), `DEV=1` (editable `.venv` install).

Notes: Kali ships ProjectDiscovery's httpx as `httpx-toolkit` (`/usr/bin/httpx` is the Python library) — handled automatically. The installer makes sure Kali's nmap has its raw-socket capability, so SYN scans work without sudo. Results default to `~/FootprintX-results`.

Update with `git pull && bash install.sh` in the project folder; uninstall with `pipx uninstall footprintx` (details in the guide).

## Configuration

| File | Used by |
| --- | --- |
| `~/.config/footprintx/config.yaml` | Native installs (created by `install.sh`). Takes priority, so results land in the same place whichever folder you start `footprintx` from. |
| `config/config.yaml` | Docker and development (the project's own copy, fully commented). |
| `~/.config/footprintx/.env` or `./.env` | API keys such as `SHODAN_API_KEY` — never put keys in `config.yaml`. |

`--config FILE` or `$FOOTPRINTX_CONFIG` overrides the search. Misspelt or unknown settings are reported as warnings (with a "did you mean …?") instead of being silently ignored; `footprintx doctor` shows which file is in use.

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

Results go to `./results`; `./config` is mounted read-only; files in `./wordlists` appear at `/app/wordlists/custom`; bulk target files go in `./targets` (gitignored). The container drops all Linux capabilities except `NET_RAW` (for SYN scans). Build args: `docker compose build --build-arg INSTALL_AMASS=false` leaves Amass out; `--build-arg UID=$(id -u)` matches the container user to yours on Linux so the files in `./results` are owned by you. To reach Burp/ZAP on the host, set the proxy URL to `http://host.docker.internal:8080`.

## Safety and security

FootprintX is built to be safe to point at real organisations:

- **Scope is enforced everywhere.** Only the targets you give (or `--scope` / `scope.include`) are touched; discovered names outside it are dropped, redirects to out-of-scope sites are never followed, and fuzzing only uses read-only HTTP methods.
- **No SSRF via DNS.** A target's subdomain that points at `127.0.0.1`, `169.254.169.254` (cloud metadata) or an internal network is reported, not scanned (`--allow-internal` opts in to internal ranges; loopback/link-local never).
- **Secrets stay secret.** API keys live only in `.env` files (`doctor` warns if they're readable by others) and are masked in every log, report and error message.
- **Hostile targets can't attack you.** Terminal escape sequences are stripped, HTML reports escape everything, CSV cells can't run formulas, XML is parsed with `defusedxml`, response bodies and tool output are size-capped, and tools run without a shell.
- **Results are private** (scan folders are mode 700) and the container runs as a non-root user with every capability dropped except `NET_RAW`.

These properties are verified by an isolated Docker lab — see *End-to-end tests* below.

## Development

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pytest && ruff check footprintx tests && mypy footprintx
```

Tests also run in the container: `docker compose --profile dev run --rm tests`.

### End-to-end tests

`tests/e2e/` contains a self-contained lab on an internal Docker network (no internet): a DNS server that allows zone transfers and has trap records (loopback, cloud metadata, internal and public addresses), vulnerable web vhosts (exposed `.git`/`.env`, directory listing, a page with a `<script>`/ANSI-escape title, redirects to an out-of-scope site), an exposed Redis and an out-of-scope server that must never receive traffic.

```bash
docker compose build footprintx
FOOTPRINTX_E2E=1 pytest tests/e2e -v      # ~5 minutes
```

```text
footprintx/
├── cli.py            guided mode + scan / doctor / modules / history commands
├── core/             config, targets, scope, scheduler, engine, orchestrator, logging
├── modules/          one package per recon step; base.py = BaseModule, common.py = input helpers
├── integrations/     wrappers that run external tools / call APIs and parse their output
├── reporting/        normalise → dedupe → correlate → JSON / HTML / TXT / CSV reports
├── database/         SQLite scan history
└── utils/            validators, platform detection, TLS, fingerprints, rate limiting, doctor
```

**Adding a module:** create `footprintx/modules/<name>/module.py` subclassing `BaseModule` (set `name`, `applies_to`, `depends_on`, `active`), register it in `footprintx/modules/__init__.py`, and the scheduler places it by its dependencies.
