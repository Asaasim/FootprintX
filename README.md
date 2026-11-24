# FootprintX

FootprintX is a cybersecurity reconnaissance tool for digital footprint discovery, asset enumeration, and attack surface mapping, helping security professionals identify and assess exposed assets.

**One target. One command. Comprehensive reconnaissance.** Full specification: [Spectifications.md](Spectifications.md).

> Only scan targets you are authorised to test. FootprintX keeps all activity inside the targets you give it (or the `--scope` you set — see *Configuration*).

## New to this? Start here

**[docs/GETTING_STARTED.md](docs/GETTING_STARTED.md)** — install on Kali Linux, Ubuntu or Windows (WSL) and run your first scan, step by step in plain language. In short:

```bash
git clone https://github.com/Asaasim/FootprintX.git && cd FootprintX
bash install.sh      # once, as your normal user (asks for your password)
footprintx           # in a new terminal: answer two questions; the report is shown in the terminal
```

## What it does

Give it a domain, URL, IP address, IP range or a file of targets. FootprintX works out what applies and runs it, in dependency order, in parallel where possible:

| Step | Tools | Built-in fallback |
| --- | --- | --- |
| Subdomain discovery | Subfinder, Assetfinder, Findomain, Amass (optional), crt.sh | zone transfers |
| Public intelligence (OSINT) | theHarvester, RDAP registration data | RDAP only |
| DNS records + SPF / DMARC / CAA / zone-transfer / wildcard checks | — | native resolver; failed lookups are retried, and TXT/CAA/MX… lookups the network blocks go over HTTPS (Cloudflare, Google) unless `modules.dns.resolvers` is set |
| IP mapping, live-host sweep of ranges, reverse DNS | Nmap | all addresses kept |
| Website probing (status, title, server, redirects, TLS certificate) | httpx-toolkit | native prober |
| Port & service scanning (top 1000 + risky services such as Redis, MongoDB, RDP) | Nmap, Naabu | — |
| Technology fingerprinting + security headers | WhatWeb, httpx-toolkit | native fingerprints |
| Hidden files & folders (`.git`, `.env`, backups, admin panels) | FFUF, Gobuster | — |
| Shodan lookups (optional, needs `SHODAN_API_KEY`) | Shodan API | — |
| Send findings to Burp Suite / ZAP, optionally import ZAP's passive-scan alerts (off by default) | your proxy, ZAP API | — |

A failing or missing tool never stops the scan: its step is skipped or falls back, and the report says so. **Scan depth:**

| Profile | How | Typical time per domain | What it does |
| --- | --- | --- | --- |
| **Quick** (default) | `--profile quick`, guided option 1 | 5–15 minutes | top 100 ports + risky services (Redis, databases, RDP…) on up to 50 servers (names sharing a server are scanned once), a short built-in high-value wordlist (`.git`, `.env`, backups, admin panels…) on the 3 main websites, 3-minute source timeouts |
| **Thorough** | `--profile thorough`, guided option 2 | 30–60+ minutes | the limits in `config.yaml`: top 1000 ports on up to 256 hosts, the full wordlist on up to 10 websites |
| **Passive** | `--passive`, guided option 3 | 2–10 minutes | public sources only; never contacts the target's servers |

Quick-scan limits grow with the number of domains, and a list of targets is scanned together rather than one after the other.

At the end of a scan the report is printed **in the terminal**; `footprintx report` shows it again later (`footprintx report 2` for the scan before, `--full` for every finding). Every scan also creates `<results>/<target>/scan_<timestamp>/` (`<results>` is `~/FootprintX-results` after `install.sh`, `./results` in Docker or a project checkout) with `reports/report.html` (readable summary, security observations ranked by severity, per-host attack-surface map), `report.json`, `report.txt`, `findings.csv` (add `xml` to `output.formats` for `report.xml`), per-category files (`subdomains.txt`, `open_ports.json`, `shodan_results.json`, …), `scan.log` (including an audit trail of every tool command run) and untouched tool output in `raw/`. Scan history is kept in `<results>/footprintx.db` (`footprintx history`); each scan is compared with the previous one of the same targets, and anything **new since the last scan** is highlighted.

## Commands

```bash
footprintx                                       # guided mode
footprintx scan -t example.com                   # domain, subdomain, URL, IP, IPv6 or CIDR; repeatable
footprintx scan -l targets.txt -o ./results      # bulk targets
footprintx scan -t example.com --passive         # public sources only
footprintx scan -t example.com -p thorough       # deeper, slower scan (default: quick)
footprintx scan -t example.com --exclude shodan,web_fuzzing
footprintx scan -t example.com --scope scope.txt   # authorised scope (domains/IPs/CIDRs, or a file)
footprintx scan -t example.com -w words.txt      # custom fuzzing wordlist
footprintx scan -t corp.example --allow-internal # internal test: scan names resolving to 10.x etc.
footprintx scan -t example.com --dry-run         # show the execution plan only
footprintx scan -t example.com -v                # debug logs
footprintx doctor                                # check tools, API keys, config
footprintx modules list
footprintx history                               # previous scans
footprintx report                                # show the latest report in the terminal
```

## Kali Linux and Ubuntu/Debian (native)

`bash install.sh` installs the tools, installs FootprintX with pipx, creates `~/.config/footprintx/` (settings, `.env` for API keys, default wordlist), adds a menu entry and runs `footprintx doctor`. Options: `WITH_SECLISTS=1` (full SecLists, ~1 GB), `DEV=1` (editable `.venv` install).

| | Kali Linux | Ubuntu 24.04+ / Debian 12+ (and derivatives such as Linux Mint) |
| --- | --- | --- |
| Tools from apt | all of them | Nmap, FFUF, Gobuster, WhatWeb |
| Other tools | — | official prebuilt releases of Subfinder, httpx (installed as `httpx-toolkit`), Naabu, Findomain and Assetfinder in `~/.local/bin`, SHA-256-verified where the project publishes checksums ([scripts/github_release.py](scripts/github_release.py)); theHarvester with pipx (Python 3.12+) |
| Not installed | — | Amass (optional, off by default); Assetfinder on ARM |
| Port scans | SYN scans without sudo (the installer sets nmap's raw-socket capability, as Kali does) | TCP connect scans (run with `sudo` for SYN scans) |

Notes: Kali ships ProjectDiscovery's httpx as `httpx-toolkit` (`/usr/bin/httpx` is the Python library) — handled automatically. Ubuntu 22.04 and older ship Python 3.10, which is too old — use Docker there. Results default to `~/FootprintX-results`. Any other Linux or macOS: [scripts/install_tools.sh](scripts/install_tools.sh) (needs Go) plus `pipx install .`, or Docker.

Update with `git pull && bash install.sh` in the project folder; uninstall with `pipx uninstall footprintx` (details in the guide).

### Windows (WSL)

The same `bash install.sh` inside Kali or Ubuntu on WSL — no Docker needed. FootprintX notices that it runs in WSL and:

- puts **FootprintX** (starts a scan) and **FootprintX results** on the Windows desktop (`footprintx windows-shortcuts` recreates them);
- copies each scan's reports (not `raw/` or the log) to `C:\Users\<you>\FootprintX-results` and shows Windows paths — the scan itself stays on the faster Linux disk; turn off with `output.windows_copy: false`;
- keeps Windows awake while a scan runs (closing the laptop lid can still suspend it);
- accepts Windows paths (`C:\...\targets.txt`) in guided mode, ignores Windows programs on `PATH`, and uses TCP connect scans on WSL 1, which has no raw sockets. WSL 2 is recommended.

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
docker compose run --rm footprintx scan -t example.com
docker compose run --rm footprintx scan -l targets/targets.txt   # file in ./targets
```

Results go to `./results`; `./config` is mounted read-only; files in `./wordlists` appear at `/app/wordlists/custom`; bulk target files go in `./targets` (gitignored). The container drops all Linux capabilities except `NET_RAW` (for SYN scans). Build args: `docker compose build --build-arg INSTALL_AMASS=false` leaves Amass out; `--build-arg UID=$(id -u)` matches the container user to yours on Linux so the files in `./results` are owned by you. To reach Burp/ZAP on the host, set the proxy URL to `http://host.docker.internal:8080`. With `modules.proxy.api: zap`, FootprintX also reads ZAP's passive-scan alerts through its API and adds them to the report as observations (set `ZAP_API_KEY` in `.env` if ZAP's API key is enabled).

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
├── cli.py            guided mode + scan / report / doctor / modules / history commands
├── core/             config, scan profiles, targets, scope, scheduler, engine, orchestrator, logging
├── modules/          one package per recon step; base.py = BaseModule, common.py = input helpers
├── integrations/     wrappers that run external tools / call APIs and parse their output
├── reporting/        normalise → dedupe → correlate → JSON / HTML / TXT / CSV / XML reports
├── database/         SQLite scan history
└── utils/            validators, platform detection, TLS, fingerprints, rate limiting, doctor
```

**Adding a module:** create `footprintx/modules/<name>/module.py` subclassing `BaseModule` (set `name`, `applies_to`, `depends_on`, `active`), register it in `footprintx/modules/__init__.py`, and the scheduler places it by its dependencies.
