#!/usr/bin/env bash
# One-time setup of FootprintX on Kali Linux.
#
#   bash install.sh                  # normal install (asks for your password once, for apt)
#   WITH_SECLISTS=1 bash install.sh  # also install the full SecLists collection (~1 GB)
#   DEV=1 bash install.sh            # developers: editable install in .venv instead of pipx
#
# What it does:
#   1. installs the recon tools from Kali's own repositories (apt)
#   2. installs FootprintX for your user with pipx
#   3. creates ~/.config/footprintx/ (settings, .env for API keys, default wordlist)
#   4. adds "FootprintX" to the Kali applications menu
#   5. runs `footprintx doctor` to confirm everything works
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="$HOME/.config/footprintx"
RESULTS_DIR="$HOME/FootprintX-results"
WORDLIST_URL="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[!] %s\033[0m\n' "$*" >&2; }

if ! grep -qi '^ID=kali' /etc/os-release 2>/dev/null; then
  warn "This installer is for Kali Linux. On other systems see scripts/install_tools.sh"
  warn "or use Docker (see README.md)."
  exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
  warn "Run this as your normal user (not with sudo) — it will ask for your password itself."
  exit 1
fi

say "Step 1/5: installing tools from the Kali repositories (you may be asked for your password)"
PACKAGES=(python3 python3-venv pipx curl dnsutils libcap2-bin
          subfinder assetfinder amass httpx-toolkit naabu nmap ffuf gobuster whatweb theharvester)
[ "${WITH_SECLISTS:-0}" = "1" ] && PACKAGES+=(seclists)
sudo apt-get update
sudo apt-get install -y "${PACKAGES[@]}"

# Kali's standard setup lets normal users run fast SYN scans by giving nmap raw-socket
# capabilities. The nmap package only does this when libcap2-bin was already present,
# so make sure it is in place (same capabilities Kali itself uses).
NMAP_BIN=/usr/lib/nmap/nmap
if [ -x "$NMAP_BIN" ] && ! /usr/sbin/getcap "$NMAP_BIN" | grep -q cap_net_raw; then
  sudo /usr/sbin/setcap cap_net_raw,cap_net_admin,cap_net_bind_service+eip "$NMAP_BIN" \
    && echo "    enabled fast (SYN) port scans without sudo"
fi

say "Step 2/5: installing FootprintX"
if [ "${DEV:-0}" = "1" ]; then
  python3 -m venv "$PROJECT_DIR/.venv"
  "$PROJECT_DIR/.venv/bin/pip" install --quiet -e "$PROJECT_DIR[dev]"
  FPX="$PROJECT_DIR/.venv/bin/footprintx"
else
  pipx install --force "$PROJECT_DIR"
  pipx ensurepath >/dev/null 2>&1 || true
  FPX="$HOME/.local/bin/footprintx"
fi

say "Step 3/5: creating your settings in $CONFIG_DIR"
mkdir -p "$CONFIG_DIR/wordlists" "$RESULTS_DIR"
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
  sed "s|^  directory: ./results|  directory: $RESULTS_DIR|" \
      "$PROJECT_DIR/config/config.yaml" > "$CONFIG_DIR/config.yaml"
  echo "    created config.yaml (results will be saved in $RESULTS_DIR)"
else
  echo "    kept your existing config.yaml"
fi
if [ ! -f "$CONFIG_DIR/.env" ]; then
  cp "$PROJECT_DIR/.env.example" "$CONFIG_DIR/.env"
  chmod 600 "$CONFIG_DIR/.env"
  echo "    created .env (add your Shodan API key there if you have one)"
fi
if [ ! -s "$CONFIG_DIR/wordlists/common.txt" ]; then
  curl -fsSL -o "$CONFIG_DIR/wordlists/common.txt" "$WORDLIST_URL" \
    && echo "    downloaded the default fuzzing wordlist" \
    || warn "could not download the wordlist — FootprintX will use SecLists/dirb if installed"
fi

say "Step 4/5: adding FootprintX to the applications menu"
mkdir -p "$HOME/.local/share/applications"
cat > "$HOME/.local/share/applications/footprintx.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=FootprintX
Comment=Map an organisation's internet attack surface
Exec=env FOOTPRINTX_LAUNCHER=1 $FPX
Terminal=true
Icon=utilities-terminal
Categories=Security;Network;
EOF
echo "    look for \"FootprintX\" in the Kali menu"

say "Step 5/5: checking the installation"
"$FPX" doctor || true

cat <<EOF

$(printf '\033[1;32m')FootprintX is installed.$(printf '\033[0m')

  Start it:   open a NEW terminal and type   footprintx
              (or pick "FootprintX" in the applications menu)
  Results:    $RESULTS_DIR
  Settings:   $CONFIG_DIR/config.yaml
  API keys:   $CONFIG_DIR/.env

EOF
