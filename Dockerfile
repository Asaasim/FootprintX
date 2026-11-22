# syntax=docker/dockerfile:1.7
#
# FootprintX image: Python CLI + the external recon tools it orchestrates.
#
#   docker build -t footprintx .                 # production image (default)
#   docker build --target dev -t footprintx:dev . # + test/lint tooling
#   docker build --build-arg INSTALL_AMASS=false . # skip the slow Amass build

ARG PYTHON_VERSION=3.12
ARG GO_VERSION=1.24

# ---------------------------------------------------------------------------
# Stage 1: build Go-based reconnaissance tools
# ---------------------------------------------------------------------------
FROM golang:${GO_VERSION}-bookworm AS tools

# GOTOOLCHAIN=auto lets Go fetch a newer toolchain if a tool's go.mod needs one
# (the official image defaults to "local", which breaks on version bumps).
ENV GOTOOLCHAIN=auto \
    GOBIN=/out \
    CGO_ENABLED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

# One layer per tool so bumping one doesn't rebuild the rest.
# Replace @latest with pinned versions for reproducible builds.
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go install -v github.com/tomnomnom/assetfinder@latest
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go install -v github.com/ffuf/ffuf/v2@latest
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    go install -v github.com/OJ/gobuster/v3@latest

ARG INSTALL_AMASS=true
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    if [ "$INSTALL_AMASS" = "true" ]; then \
      go install -v github.com/owasp-amass/amass/v5/cmd/amass@main; \
    fi

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM python:${PYTHON_VERSION}-slim-bookworm AS runtime

# /opt/tools/bin comes first so ProjectDiscovery's `httpx` binary wins over the
# `httpx` console script installed by the Python httpx library.
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    VIRTUAL_ENV=/opt/venv \
    PATH="/opt/tools/bin:/opt/venv/bin:${PATH}" \
    NMAP_PRIVILEGED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      nmap whatweb dnsutils libpcap0.8 libcap2-bin ca-certificates \
 && rm -rf /var/lib/apt/lists/*

COPY --from=tools /out/ /opt/tools/bin/

# Raw-socket scans (SYN scans) as a non-root user. Only CAP_NET_RAW is granted —
# it is the one capability docker-compose.yml adds back after dropping ALL.
RUN setcap cap_net_raw+eip /usr/bin/nmap \
 && setcap cap_net_raw+eip /opt/tools/bin/naabu

RUN python -m venv "$VIRTUAL_ENV"
WORKDIR /app

# Dependencies first for layer caching, then the package itself.
COPY requirements.txt ./
RUN pip install -r requirements.txt
COPY pyproject.toml README.md ./
COPY footprintx ./footprintx
RUN pip install --no-deps .

COPY config ./config

# Default fuzzing wordlist (SecLists common.txt). Pin a commit SHA for reproducibility.
ADD https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt \
    /app/wordlists/common.txt

ARG UID=1000
RUN useradd --create-home --uid "${UID}" footprintx \
 && mkdir -p /app/results /app/wordlists/custom \
 && chmod 644 /app/wordlists/common.txt \
 && chown -R footprintx:footprintx /app/results

USER footprintx
VOLUME ["/app/results"]

ENTRYPOINT ["footprintx"]
CMD ["--help"]

# ---------------------------------------------------------------------------
# Stage 3: dev / test image
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
