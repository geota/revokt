# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""Compare a PR's Kover XML line coverage with the latest `coverage-main` artifact (CONTRIBUTING §6).

Rule: overall line coverage may not fall below the value on `main`; the 90 % target is reached by 0.2. The `main`
artifact is the Kover XML uploaded by the `check (21)` job of the last successful run on `main`, fetched through the
GitHub API with the workflow token. A missing baseline (first run) passes with a note.
"""
import json
import os
import subprocess
import sys
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
import io


def line_rate(path: str) -> float:
    root = ET.parse(path).getroot()
    for counter in root.findall("counter"):
        if counter.get("type") == "LINE":
            covered = int(counter.get("covered", "0"))
            missed = int(counter.get("missed", "0"))
            total = covered + missed
            return covered / total if total else 1.0
    return 1.0


def baseline_rate(repo: str, token: str) -> float | None:
    api = f"https://api.github.com/repos/{repo}"
    req = urllib.request.Request(
        f"{api}/actions/artifacts?name=coverage-main&per_page=1", headers={"Authorization": f"Bearer {token}"}
    )
    with urllib.request.urlopen(req) as r:
        arts = json.load(r).get("artifacts", [])
    if not arts:
        return None
    req = urllib.request.Request(arts[0]["archive_download_url"], headers={"Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(req) as r:
        data = r.read()
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        name = next(n for n in z.namelist() if n.endswith(".xml"))
        with z.open(name) as f, open("baseline.xml", "wb") as out:
            out.write(f.read())
    return line_rate("baseline.xml")


def main() -> int:
    pr = line_rate(sys.argv[1])
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    token = os.environ.get("GH_TOKEN", "")
    base = baseline_rate(repo, token) if repo and token else None
    print(f"coverage: PR line rate {pr:.4f}; main {('%.4f' % base) if base is not None else 'n/a (no baseline yet)'}")
    if base is not None and pr + 1e-9 < base:
        print(
            f"coverage: line coverage fell from {base:.4f} to {pr:.4f}. Add tests for the new code, or justify in a kind/test PR (CONTRIBUTING §6).",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
