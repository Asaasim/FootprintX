"""End-to-end functional + security tests against an isolated Docker lab.

Opt-in (needs Docker and the footprintx:latest image):

    docker compose build footprintx
    FOOTPRINTX_E2E=1 pytest tests/e2e -v

The lab (docker-compose.e2e.yml) runs on an `internal` Docker network with no
route to the internet. It contains deliberate traps; the tests prove that
FootprintX finds the planted issues AND never:
  - sends traffic to an out-of-scope host (incl. via redirects),
  - lets an in-scope DNS name steer scans at loopback / cloud metadata / internal IPs,
  - writes an API key into any output file,
  - copies hostile HTML or terminal escape sequences into its reports,
and that it survives failures, keeps results private, runs unprivileged, logs the
commands it runs, honours passive mode, detects changes and handles Ctrl+C.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

HERE = Path(__file__).parent
RUN = HERE / ".run"
RESULTS = RUN / "results"
COMPOSE = ["docker", "compose", "-f", str(HERE / "docker-compose.e2e.yml")]
FAKE_KEY = "e2e-fake-shodan-key-0123456789"
ESC = "\x1b"

pytestmark = [
    pytest.mark.e2e,
    pytest.mark.skipif(os.environ.get("FOOTPRINTX_E2E") != "1",
                       reason="set FOOTPRINTX_E2E=1 to run the Docker E2E lab"),
]


# -- helpers ---------------------------------------------------------------------

def compose(*args: str, check: bool = True, timeout: int = 1200
            ) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "E2E_FAKE_SHODAN_KEY": FAKE_KEY}
    return subprocess.run([*COMPOSE, *args], capture_output=True, text=True, encoding="utf-8",
                          errors="replace", timeout=timeout, check=check, env=env)


def scan(*args: str, timeout: int = 1200) -> subprocess.CompletedProcess[str]:
    return compose("run", "--rm", "-T", "scanner", *args, check=False, timeout=timeout)


def sessions(target: str = "lab.test") -> list[Path]:
    return sorted((RESULTS / target).glob("scan_*"))


def report(session: Path) -> dict:
    return json.loads((session / "reports" / "report.json").read_text(encoding="utf-8"))


def http_requests(service: str) -> list[str]:
    logs = compose("logs", "--no-log-prefix", service, check=False).stdout
    return [line for line in logs.splitlines()
            if any(f'"{m} ' in line for m in ("GET", "HEAD", "POST", "PUT", "OPTIONS"))]


def build_site() -> None:
    """Copy the committed fixture and add what can't live in git (.git/, .env)."""
    site = RUN / "site"
    shutil.copytree(HERE / "lab" / "web" / "site", site)
    (site / "www" / ".git").mkdir()
    (site / "www" / ".git" / "HEAD").write_text("ref: refs/heads/main\n")
    (site / "www" / ".env").write_text("DB_PASSWORD=lab-only-fake\n")
    (site / "blog").mkdir(exist_ok=True)
    # hostile page: HTML injection + ANSI escapes (clear screen, colours) in the title
    (site / "blog" / "index.html").write_text(
        f"<html><head><title><script>alert(1)</script>{ESC}[2J{ESC}[31mPWNED{ESC}[0m"
        "</title></head></html>\n", encoding="utf-8")


# -- fixtures --------------------------------------------------------------------

@pytest.fixture(scope="module")
def lab():
    compose("down", "-v", "--remove-orphans", check=False)
    if RUN.exists():
        shutil.rmtree(RUN)
    RESULTS.mkdir(parents=True)
    build_site()
    compose("up", "-d", "dns", "web", "redis", "outsider")
    for _ in range(30):
        if compose("exec", "-T", "web", "wget", "-qO-", "http://127.0.0.1/",
                   check=False).returncode == 0:
            break
        time.sleep(1)
    # the readiness probe above must not count as a request to anything we assert on
    yield
    compose("down", "-v", "--remove-orphans", check=False)


@pytest.fixture(scope="module")
def full_scan(lab):
    proc = scan("scan", "-t", "lab.test", "--yes")
    assert proc.returncode == 0, proc.stdout[-3000:] + proc.stderr[-3000:]
    session = sessions()[-1]
    return proc, session, report(session)


def observations(data: dict) -> dict[tuple[str, str], str]:
    return {(o["value"], o["target"]): o["data"]["severity"] for o in data["observations"]}


# -- functional ------------------------------------------------------------------

def test_planted_issues_are_found(full_scan):
    _, _, data = full_scan
    found = observations(data)
    titles = {title: sev for (title, _), sev in found.items()}
    assert titles["DNS zone transfer (AXFR) allowed"] == "high"
    assert titles["Exposed Git repository"] == "high"
    assert titles["Exposed environment file (.env)"] == "high"
    assert titles["Redis exposed"] == "high"
    assert titles["SPF allows all senders (+all)"] == "medium"
    assert titles["Directory listing enabled"] == "medium"
    assert titles["No DMARC record"] == "low"


def test_zone_transfer_names_are_resolved_and_probed(full_scan):
    """crt.sh is unreachable in the lab, so every subdomain came from the AXFR."""
    _, _, data = full_scan
    subs = {f["value"] for f in data["findings"]["subdomain"]}
    assert {"www.lab.test", "blog.lab.test", "shop.lab.test", "cache.lab.test"} <= subs
    live = {f["value"] for f in data["findings"]["url"] if f["data"].get("live")}
    assert "http://blog.lab.test" in live and "http://www.lab.test" in live


def test_failed_modules_do_not_stop_the_scan(full_scan):
    _, _, data = full_scan
    status = {m["module"]: m["status"] for m in data["modules"]}
    assert status["subdomains"] == "failed"          # no internet → crt.sh unreachable
    for module in ("dns", "ip_discovery", "http_probe", "port_scanning",
                   "technology_detection", "web_fuzzing"):
        assert status[module] == "success", module
    assert data["status"] == "completed"


def test_all_report_formats_and_result_files_written(full_scan):
    _, session, _ = full_scan
    for name in ("scan_info.json", "targets.txt", "subdomains.txt", "dns_records.json",
                 "resolved_ips.txt", "live_hosts.txt", "open_ports.json", "technologies.json",
                 "urls.txt", "fuzzing_results.json", "observations.json", "scan.log",
                 "reports/report.html", "reports/report.json", "reports/report.txt",
                 "reports/findings.csv"):
        assert (session / name).is_file(), name


# -- security: scope -------------------------------------------------------------

def test_out_of_scope_host_receives_no_traffic(full_scan):
    """shop.lab.test redirects every request to www.outsider.test and /go redirects
    there too; neither redirect may be followed."""
    assert http_requests("outsider") == []


def test_names_pointing_at_local_or_internal_addresses_are_not_scanned(full_scan):
    _, session, data = full_scan
    scanned = "\n".join((session / "raw" / name).read_text(encoding="utf-8")
                        for name in ("httpx_input.txt", "port_scan_targets.txt"))
    for host, ip in (("loop.lab.test", "127.0.0.1"), ("meta.lab.test", "169.254.169.254"),
                     ("intranet.lab.test", "10.99.0.1")):
        assert host not in scanned and ip not in scanned, host
    found = observations(data)
    assert ("Hostname points to a loopback or link-local address", "loop.lab.test") in found
    assert ("Hostname points to a loopback or link-local address", "meta.lab.test") in found
    assert ("Public DNS reveals an internal address", "intranet.lab.test") in found


# -- security: output handling -----------------------------------------------------

def test_api_key_never_written_anywhere(full_scan):
    proc, _, data = full_scan
    status = {m["module"]: m for m in data["modules"]}
    assert status["shodan"]["status"] == "failed"   # tried (public IP known), unreachable
    leaks = [p for p in RESULTS.rglob("*") if p.is_file() and FAKE_KEY.encode() in p.read_bytes()]
    assert leaks == []
    assert FAKE_KEY not in proc.stdout + proc.stderr


def test_hostile_page_content_is_neutralised_in_reports(full_scan):
    _, session, data = full_scan
    blog = next(f for f in data["findings"]["url"] if f["value"] == "http://blog.lab.test")
    assert "PWNED" in blog["data"]["title"] and ESC not in blog["data"]["title"]
    html = (session / "reports" / "report.html").read_text(encoding="utf-8")
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    for path in [*session.glob("*.*"), *(session / "reports").glob("*")]:
        assert ESC not in path.read_text(encoding="utf-8", errors="replace"), path.name


# -- security: runtime -------------------------------------------------------------

def test_runs_unprivileged_and_results_are_private(full_scan):
    _, session, _ = full_scan
    proc = compose("run", "--rm", "-T", "--entrypoint", "sh", "scanner", "-c",
                   f"id -u; stat -c %a /app/results/lab.test/{session.name}", check=False)
    uid, mode = proc.stdout.split()
    assert uid != "0"
    assert mode == "700"


def test_commands_are_audit_logged(full_scan):
    _, session, _ = full_scan
    log = (session / "scan.log").read_text(encoding="utf-8")
    assert "exec: /usr/bin/nmap" in log and "exec: /usr/bin/ffuf" in log


# -- behaviour across scans ----------------------------------------------------------

def test_passive_scan_sends_nothing_to_the_targets(full_scan):
    before = len(http_requests("web"))
    proc = scan("scan", "-t", "lab.test", "--passive", "--yes")
    assert proc.returncode == 0, proc.stdout[-2000:]
    assert len(http_requests("web")) == before
    data = report(sessions()[-1])
    assert data["mode"] == "passive"
    status = {m["module"]: m["status"] for m in data["modules"]}
    for active in ("http_probe", "port_scanning", "web_fuzzing", "technology_detection"):
        assert status[active] == "skipped"


def test_repeat_full_scan_reports_changes(full_scan):
    _, first, _ = full_scan
    proc = scan("scan", "-t", "lab.test", "--yes")
    assert proc.returncode == 0, proc.stdout[-2000:]
    data = report(sessions()[-1])
    assert data["changes"]["compared_with"] == first.name   # passive scan is not compared
    assert data["changes"]["new"] == []


def test_interrupt_keeps_partial_results(lab):
    count = len(sessions())
    name = "footprintx-e2e-interrupt"
    env = {**os.environ, "E2E_FAKE_SHODAN_KEY": FAKE_KEY}
    proc = subprocess.Popen([*COMPOSE, "run", "--rm", "-T", "--name", name, "scanner", "scan",
                             "-t", "lab.test", "--yes"], env=env,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    deadline = time.time() + 120
    while time.time() < deadline and len(sessions()) == count:
        time.sleep(1)
    time.sleep(15)  # let it get into the scan
    subprocess.run(["docker", "kill", "--signal", "SIGINT", name], check=False,
                   capture_output=True)
    out, _ = proc.communicate(timeout=180)
    session = sessions()[-1]
    info = json.loads((session / "scan_info.json").read_text(encoding="utf-8"))
    assert info["status"] == "interrupted", out[-2000:]
    assert (session / "reports" / "report.html").is_file()
    assert proc.returncode == 130


def test_out_of_scope_host_still_untouched_after_all_runs(lab):
    assert http_requests("outsider") == []
