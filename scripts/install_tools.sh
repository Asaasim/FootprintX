#!/usr/bin/env sh
# Install the external tools for a local (non-Docker) Linux/macOS setup.
# Requires Go 1.24+ and libpcap headers (apt install libpcap-dev) for naabu.
# Docker users don't need this — the image builds all of these.
set -eu

go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/ffuf/ffuf/v2@latest
go install -v github.com/OJ/gobuster/v3@latest
go install -v github.com/owasp-amass/amass/v5/cmd/amass@main

echo
echo "Go tools installed to $(go env GOPATH)/bin — make sure it is on your PATH."
echo "Also install with your package manager: nmap whatweb"
