# syntax=docker/dockerfile:1.7
#
# FootprintX on Kali Linux: the Python CLI plus the recon tools it orchestrates,
# all installed from Kali's own repositories (no compiling).
#
#   docker build -t footprintx .                  # production image (default)
#   docker build --target dev -t footprintx:dev . # + test/lint tooling
#   docker build --build-arg INSTALL_AMASS=false . # smaller image without Amass

FROM kalilinux/kali-rolling AS runtime

# /opt/venv/bin holds the Python httpx library's `httpx` script; FootprintX
# uses Kali's `httpx-toolkit` binary instead, so there is no clash.
ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/venv/bin:${PATH}" \
    NMAP_PRIVILEGED=1

ARG INSTALL_AMASS=true
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      python3 python3-venv ca-certificates libcap2-bin dnsutils \
      subfinder assetfinder findomain httpx-toolkit naabu nmap ffuf gobuster whatweb theharvester \
      $( [ "$INSTALL_AMASS" = "true" ] && echo amass ) \
 && rm -rf /var/lib/apt/lists/*

# Raw-socket (SYN) scans as a non-root user. Kali's /usr/bin/nmap is a wrapper
# script around /usr/lib/nmap/nmap, which ships with net_admin + net_bind_service
# + net_raw. The container only keeps CAP_NET_RAW (docker-compose.yml drops ALL),
# and the kernel refuses to exec a binary whose file capabilities exceed that —
# so reduce both scanners to exactly cap_net_raw.
RUN setcap cap_net_raw+eip /usr/lib/nmap/nmap \
 && setcap cap_net_raw+eip "$(command -v naabu)" \
 && getcap /usr/lib/nmap/nmap "$(command -v naabu)"

# Kali's system Python is externally managed (PEP 668), so use a venv.
RUN python3 -m venv "$VIRTUAL_ENV"
WORKDIR /app

# Dependencies first for layer caching, then the package itself.
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY pyproject.toml README.md ./
COPY footprintx ./footprintx
RUN pip install --no-deps .

COPY config ./config

# Default fuzzing wordlist (SecLists common.txt) — the full seclists package is ~1 GB.
# Pin a commit SHA instead of `master` for reproducible builds.
ADD https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
    /app/wordlists/common.txt

ARG UID=1000
RUN useradd --create-home --uid "${UID}" footprintx \
 && mkdir -p /app/results /app/wordlists/custom /app/targets \
 && chmod 644 /app/wordlists/common.txt \
 && chown -R footprintx:footprintx /app/results

USER footprintx
VOLUME ["/app/results"]

# No arguments = guided, question-and-answer scan (`docker compose run --rm footprintx`).
ENTRYPOINT ["footprintx"]
CMD []

# ---------------------------------------------------------------------------
# Dev / test image
# ---------------------------------------------------------------------------
FROM runtime AS dev

USER root
COPY requirements-dev.txt ./
RUN pip install -r requirements-dev.txt \
 && pip install --no-deps -e .
COPY tests ./tests
RUN chown -R footprintx:footprintx /app
USER footprintx

ENTRYPOINT []
CMD ["pytest"]

# ---------------------------------------------------------------------------
# Default target for a plain `docker build .`
# ---------------------------------------------------------------------------
FROM runtime AS production
