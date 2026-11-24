#!/usr/bin/env python3
"""Download one executable from a project's latest GitHub release.

Used by install.sh on Ubuntu/Debian, whose repositories don't carry the
ProjectDiscovery tools that Kali packages.

    github_release.py REPO ASSET_REGEX BINARY DEST   # install BINARY from the asset to DEST
    github_release.py --tag REPO                      # print the latest release tag

Safety: the download is checked against the release's published SHA-256
checksums when the project provides them, and only the single file named
BINARY is taken from the archive (no extraction to disk, so archive paths
can't escape). Standard library only.
"""

from __future__ import annotations

import hashlib
import io
import json
import os
import re
import sys
import tarfile
import urllib.error
import urllib.request
import zipfile

API = "https://api.github.com/repos/{repo}/releases/latest"
MAX_DOWNLOAD = 200 * 1024 * 1024


def _get(url: str, limit: int = MAX_DOWNLOAD) -> bytes:
    request = urllib.request.Request(url, headers={"User-Agent": "footprintx-installer"})
    with urllib.request.urlopen(request, timeout=60) as response:  # noqa: S310 — https only
        data = response.read(limit + 1)
    if len(data) > limit:
        raise SystemExit(f"download too large: {url}")
    return data


def latest_release(repo: str) -> dict:
    try:
        return json.loads(_get(API.format(repo=repo), limit=5 * 1024 * 1024))
    except urllib.error.HTTPError as exc:
        if exc.code != 404:
            raise
    # Some projects (e.g. assetfinder) never mark a release as "latest": take the newest.
    releases = json.loads(_get(f"{API.format(repo=repo).rsplit('/', 1)[0]}?per_page=5",
                               limit=5 * 1024 * 1024))
    if not releases:
        raise SystemExit(f"{repo} has no releases")
    return releases[0]


def expected_checksum(release: dict, asset_name: str) -> str | None:
    for asset in release.get("assets", []):
        if "checksum" in asset["name"].lower():
            text = _get(asset["browser_download_url"], limit=1024 * 1024).decode()
            for line in text.splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1].lstrip("*") == asset_name:
                    return parts[0].lower()
    return None


def extract_binary(archive: bytes, asset_name: str, binary: str) -> bytes:
    if asset_name.endswith(".zip"):
        with zipfile.ZipFile(io.BytesIO(archive)) as zf:
            for info in zf.infolist():
                if not info.is_dir() and os.path.basename(info.filename) == binary:
                    return zf.read(info)
    else:
        with tarfile.open(fileobj=io.BytesIO(archive)) as tf:
            for member in tf.getmembers():
                if member.isfile() and os.path.basename(member.name) == binary:
                    handle = tf.extractfile(member)
                    if handle is not None:
                        return handle.read()
    raise SystemExit(f"{binary} not found in {asset_name}")


def install(repo: str, pattern: str, binary: str, dest: str) -> str:
    release = latest_release(repo)
    regex = re.compile(pattern)
    asset = next((a for a in release.get("assets", []) if regex.search(a["name"])), None)
    if asset is None:
        raise SystemExit(f"no release file of {repo} matches {pattern}")
    archive = _get(asset["browser_download_url"])
    expected = expected_checksum(release, asset["name"])
    if expected and hashlib.sha256(archive).hexdigest() != expected:
        raise SystemExit(f"checksum mismatch for {asset['name']} — not installed")
    data = extract_binary(archive, asset["name"], binary)
    os.makedirs(os.path.dirname(dest) or ".", exist_ok=True)
    tmp = f"{dest}.part"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.chmod(tmp, 0o755)
    os.replace(tmp, dest)
    return f"{release.get('tag_name', '?')}{' (checksum verified)' if expected else ''}"


def main(argv: list[str]) -> int:
    if len(argv) == 2 and argv[0] == "--tag":
        print(latest_release(argv[1])["tag_name"])
        return 0
    if len(argv) != 4:
        print(__doc__, file=sys.stderr)
        return 2
    print(install(*argv))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
