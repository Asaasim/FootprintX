#!/usr/bin/env sh
# Download the default fuzzing wordlist for local (non-Docker) runs.
# The Docker image already ships it at /app/wordlists/common.txt.
set -eu

DEST="$(dirname "$0")/../wordlists"
mkdir -p "$DEST"
curl -fsSL -o "$DEST/common.txt" \
  https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt
echo "Saved $DEST/common.txt"
