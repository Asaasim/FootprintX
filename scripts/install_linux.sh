#!/usr/bin/env bash
# One-time setup of FootprintX on Kali Linux or Ubuntu/Debian (and their derivatives,
# e.g. Linux Mint, Pop!_OS).
#
#   bash install.sh                  # normal install (asks for your password once, for apt)
#   WITH_SECLISTS=1 bash install.sh  # also install the full SecLists collection (~1 GB)
#   DEV=1 bash install.sh            # developers: editable install in .venv instead of pipx
#
# What it does:
#   1. installs the recon tools — on Kali all from Kali's repositories (apt); on
#      Ubuntu/Debian what apt has, plus the official prebuilt releases of the rest
#      (subfinder, httpx, naabu, assetfinder, findomain) into ~/.local/bin
#   2. installs FootprintX for your user with pipx
#   3. creates ~/.config/footprintx/ (settings, .env for API keys, default wordlist)
#   4. adds "FootprintX" to the applications menu
#   5. runs `footprintx doctor` to confirm everything works
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CONFIG_DIR="$HOME/.config/footprintx"
RESULTS_DIR="$HOME/FootprintX-results"
BIN_DIR="$HOME/.local/bin"
WORDLIST_URL="https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt"

say()  { printf '\n\033[1;36m==> %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[!] %s\033[0m\n' "$*" >&2; }

# --- which system is this? ---------------------------------------------------------
OS_ID="$(. /etc/os-release 2>/dev/null && echo "${ID:-}")"
OS_LIKE="$(. /etc/os-release 2>/dev/null && echo "${ID_LIKE:-}")"
OS_NAME="$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-$OS_ID}")"
if [ "$OS_ID" = "kali" ]; then
  FLAVOUR=kali
elif [ "$OS_ID" = "ubuntu" ] || [ "$OS_ID" = "debian" ] \
     || [[ " $OS_LIKE " == *" ubuntu "* ]] || [[ " $OS_LIKE " == *" debian "* ]]; then
  FLAVOUR=debian
else
  warn "This installer supports Kali Linux and Ubuntu/Debian (found: ${OS_NAME:-unknown})."
  warn "On other systems use Docker, or see scripts/install_tools.sh (README.md explains both)."
  exit 1
fi
if [ "$(id -u)" -eq 0 ]; then
  warn "Run this as your normal user (not with sudo) — it will ask for your password itself."
  exit 1
fi
echo "Installing FootprintX on $OS_NAME"

# --- 1. tools -----------------------------------------------------------------------
if [ "$FLAVOUR" = kali ]; then
  say "Step 1/5: installing tools from the Kali repositories (you may be asked for your password)"
  PACKAGES=(python3 python3-venv pipx curl dnsutils libcap2-bin
            subfinder assetfinder findomain amass httpx-toolkit naabu nmap ffuf gobuster whatweb theharvester)
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
else
  say "Step 1/5: installing tools (you may be asked for your password)"
  # pipx, ffuf, gobuster and whatweb live in Ubuntu's "universe" section.
  if [ "$OS_ID" = "ubuntu" ] && command -v add-apt-repository >/dev/null 2>&1; then
    sudo add-apt-repository -y universe >/dev/null 2>&1 || true
  fi
  sudo apt-get update
  # Required: FootprintX itself cannot be installed without these.
  sudo apt-get install -y python3 python3-venv pipx curl dnsutils nmap libpcap-dev
  # Optional: install one by one so a package missing on an older release doesn't stop us.
  OPTIONAL=(ffuf gobuster whatweb)
  [ "${WITH_SECLISTS:-0}" = "1" ] && OPTIONAL+=(seclists)
  for pkg in "${OPTIONAL[@]}"; do
    sudo apt-get install -y "$pkg" >/dev/null 2>&1 \
      && echo "    installed $pkg" || warn "$pkg is not available here — skipped"
  done

  if ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 11))'; then
    warn "FootprintX needs Python 3.11 or newer; this system has $(python3 -V 2>&1)."
    warn "Use Ubuntu 24.04 / Debian 12 or newer, or run FootprintX with Docker (see README.md)."
    exit 1
  fi

  # Not packaged by Ubuntu/Debian: fetch the projects' official prebuilt releases
  # (checksum-verified where the project publishes checksums) into ~/.local/bin.
  case "$(uname -m)" in
    x86_64|amd64)  ARCH=amd64; FINDOMAIN_ASSET='^findomain-linux\.zip$' ;;
    aarch64|arm64) ARCH=arm64; FINDOMAIN_ASSET='^findomain-aarch64\.zip$' ;;
    *)             ARCH="" ;;
  esac
  fetch() {  # fetch REPO ASSET_REGEX BINARY INSTALLED_NAME
    local result
    if result="$(python3 -I "$PROJECT_DIR/scripts/github_release.py" "$1" "$2" "$3" "$BIN_DIR/$4" 2>&1)"; then
      echo "    installed $4 $result"
    else
      warn "could not install $4 ($result) — FootprintX will work without it"
    fi
  }
  mkdir -p "$BIN_DIR"
  if [ -n "$ARCH" ]; then
    fetch projectdiscovery/subfinder "^subfinder_[0-9.]+_linux_${ARCH}\.zip$" subfinder subfinder
    # Installed as httpx-toolkit (Kali's name) so it never clashes with Python's httpx command.
    fetch projectdiscovery/httpx "^httpx_[0-9.]+_linux_${ARCH}\.zip$" httpx httpx-toolkit
    fetch projectdiscovery/naabu "^naabu_[0-9.]+_linux_${ARCH}\.zip$" naabu naabu
    fetch Findomain/Findomain "$FINDOMAIN_ASSET" findomain findomain
    if [ "$ARCH" = amd64 ]; then  # assetfinder has no arm64 release
      fetch tomnomnom/assetfinder "^assetfinder-linux-amd64-[0-9.]+\.tgz$" assetfinder assetfinder
    fi
  else
    warn "no prebuilt tools for $(uname -m) — FootprintX will use its built-in fallbacks"
  fi

  # theHarvester (email/host OSINT) is a Python program needing Python 3.12+.
  if python3 -c 'import sys; sys.exit(sys.version_info < (3, 12))'; then
    if TAG="$(python3 -I "$PROJECT_DIR/scripts/github_release.py" --tag laramies/theHarvester 2>/dev/null)" \
       && pipx install --force "git+https://github.com/laramies/theHarvester.git@$TAG" >/dev/null 2>&1; then
      echo "    installed theHarvester $TAG"
    else
      warn "could not install theHarvester — FootprintX will use its built-in OSINT sources"
    fi
  fi
fi

# --- 2. FootprintX ------------------------------------------------------------------
say "Step 2/5: installing FootprintX"
if [ "${DEV:-0}" = "1" ]; then
  python3 -m venv "$PROJECT_DIR/.venv"
  "$PROJECT_DIR/.venv/bin/pip" install --quiet -e "$PROJECT_DIR[dev]"
  FPX="$PROJECT_DIR/.venv/bin/footprintx"
else
  pipx install --force "$PROJECT_DIR"
  pipx ensurepath >/dev/null 2>&1 || true
  FPX="$BIN_DIR/footprintx"
fi

# --- 3. settings --------------------------------------------------------------------
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

# --- 4. menu entry ------------------------------------------------------------------
say "Step 4/5: adding FootprintX to the applications menu"
mkdir -p "$HOME/.local/share/applications"
# PATH is spelled out so tools in ~/.local/bin are found even before the next login.
cat > "$HOME/.local/share/applications/footprintx.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=FootprintX
Comment=Map an organisation's internet attack surface
Exec=env FOOTPRINTX_LAUNCHER=1 PATH=$BIN_DIR:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin $FPX
Terminal=true
Icon=utilities-terminal
Categories=Security;Network;
EOF
echo "    look for \"FootprintX\" in the applications menu"

# --- 5. check -----------------------------------------------------------------------
say "Step 5/5: checking the installation"
PATH="$BIN_DIR:$PATH" "$FPX" doctor || true

cat <<EOF

$(printf '\033[1;32m')FootprintX is installed.$(printf '\033[0m')

  Start it:   open a NEW terminal and type   footprintx
              (or pick "FootprintX" in the applications menu)
  Results:    $RESULTS_DIR
  Settings:   $CONFIG_DIR/config.yaml
  API keys:   $CONFIG_DIR/.env

EOF
