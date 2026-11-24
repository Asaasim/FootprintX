#!/usr/bin/env bash
# FootprintX installer for Kali Linux and Ubuntu/Debian. Run once:   bash install.sh
exec bash "$(dirname "${BASH_SOURCE[0]}")/scripts/install_linux.sh" "$@"
