# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""File one private draft security advisory per new fuzz finding (fuzz.yml advisory job, #115; CONTRIBUTING §6).

The findings directory holds one subdirectory per `fuzz-finding-<target>` artifact of the fuzz job, as
actions/download-artifact lays out a pattern download, or, when exactly one artifact matched, that artifact's files
themselves (its name is then lost, and the target is the manifest's). That job ran the
fuzzed tree's code, which could have written or replaced any of it, so it is hostile data and is checked before use:
- an artifact directory: named fuzz-finding-<target>; regular files only (no link, no subdirectory); exactly
  manifest.json and the finding files it lists; each file within its cap, and the run within the total cap;
- manifest.json: a JSON object with exactly `target`, `module`, `hash`, `reproduced` and `files`. `target` and
  `module` hold only [A-Za-z0-9._/-], and `target` is the artifact's. `hash` is empty or 8 to 64 lowercase hex digits
  (Jazzer's DEDUP_TOKEN). `reproduced` is a boolean. `files` is 1 to 8 distinct names finding-<n>.tar.age;
- a finding file: ASCII age armour and nothing else. The BEGIN line, base64 lines of exactly 64 characters but the
  last, then the END line;
- at most 8 findings in one run; an artifact that would go past that is rejected.
A rejected artifact is reported by its name alone, or not at all if the name itself is unexpected, and makes the job
fail; the other artifacts are still filed. Nothing from an artifact is printed.

Only a finding that reproduces is filed (#321; ClusterFuzz likewise re-runs a crash to check that it reproduces):
fuzz.yml's reproduce step replayed a saved input alone, it failed again, and the empty input passed. A well-formed manifest whose
`reproduced` is not true is skipped, counted but not filed and not held against the caps; fuzz.yml uploads such a run
failure under another artifact name, so one here is not what the fuzz job writes, and nothing of it is filed.

Dedup: an advisory's summary is `fuzz: <target> <hash>`, and an existing advisory (any state) with that summary is
the same finding. A finding without a hash is filed as `fuzz: <target> run <run id>` and never deduplicated.

The description holds the run link, the target, the hash, how to decrypt (CONTRIBUTING §6) and each armoured file in
a fenced block, while the description stays within the API's 65 535 characters. A file that does not fit is named,
with a pointer to the run's artifact (kept 7 days).

Python 3.10 or later, standard library only. Usage: fuzz_advisory.py <findings dir>. Environment: GH_TOKEN
(FUZZ_ADVISORY_TOKEN: Repository security advisories read and write), REPO, RUN_URL, RUN_ID; API_URL overrides
https://api.github.com (tests only).
"""
import json
import os
import re
import stat
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path

ARTIFACT = re.compile(r"fuzz-finding-([A-Za-z0-9._/-]{1,200})")
FIELD = re.compile(r"[A-Za-z0-9._/-]{1,200}")
HASH = re.compile(r"[0-9a-f]{8,64}")
FINDING_FILE = re.compile(r"finding-[1-9][0-9]?\.tar\.age")
BODY_LINE = re.compile(rb"[A-Za-z0-9+/]{1,64}={0,2}")
BEGIN = b"-----BEGIN AGE ENCRYPTED FILE-----"
END = b"-----END AGE ENCRYPTED FILE-----"
MANIFEST = "manifest.json"
MANIFEST_KEYS = {"target", "module", "hash", "reproduced", "files"}
MAX_MANIFEST = 4 * 1024
MAX_FILE = 256 * 1024
MAX_TOTAL = 1024 * 1024
MAX_FINDINGS = 8
MAX_DESCRIPTION = 65535


class Rejected(Exception):
    """An artifact that is not what the fuzz job writes. The message never quotes the artifact's content."""


@dataclass
class Finding:
    target: str
    module: str
    hash: str
    reproduced: bool
    files: list[tuple[str, str]]  # (file name, armour)


def read_capped(path: Path, cap: int) -> bytes:
    """A regular file's bytes, opened without following a link; rejected above cap."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise Rejected("a file that is not a regular file")
        data = b""
        while len(data) <= cap:
            chunk = os.read(fd, cap + 1 - len(data))
            if not chunk:
                break
            data += chunk
    finally:
        os.close(fd)
    if len(data) > cap:
        raise Rejected(f"a file above {cap} bytes")
    return data


def check_armour(data: bytes) -> str:
    """The armour as text, if it is exactly age's ASCII armour."""
    if b"\r" in data or any(b > 0x7E or (b < 0x20 and b != 0x0A) for b in data):
        raise Rejected("a finding file with bytes outside printable ASCII and LF")
    lines = data.split(b"\n")
    if lines and lines[-1] == b"":
        lines.pop()
    if len(lines) < 3 or lines[0] != BEGIN or lines[-1] != END:
        raise Rejected("a finding file without age's BEGIN and END lines")
    body = lines[1:-1]
    for i, line in enumerate(body):
        last = i == len(body) - 1
        if not BODY_LINE.fullmatch(line) or (not last and (len(line) != 64 or b"=" in line)):
            raise Rejected("a finding file whose armour is not base64 in 64-column lines")
    return data.decode("ascii")


def check_manifest(data: bytes, target: str | None) -> tuple[str, str, str, bool, list[str]]:
    try:
        manifest = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise Rejected("a manifest that is not JSON") from None
    if not isinstance(manifest, dict) or set(manifest) != MANIFEST_KEYS:
        raise Rejected("a manifest without exactly target, module, hash, reproduced and files")
    for key in ("target", "module"):
        if not isinstance(manifest[key], str) or not FIELD.fullmatch(manifest[key]):
            raise Rejected(f"a manifest {key} outside [A-Za-z0-9._/-]")
    if target is not None and manifest["target"] != target:
        raise Rejected("a manifest target that is not the artifact's")
    if not isinstance(manifest["hash"], str) or (manifest["hash"] and not HASH.fullmatch(manifest["hash"])):
        raise Rejected("a manifest hash that is not empty or 8 to 64 lowercase hex digits")
    if not isinstance(manifest["reproduced"], bool):
        raise Rejected("a manifest reproduced that is not true or false")
    files = manifest["files"]
    if (not isinstance(files, list) or not 1 <= len(files) <= MAX_FINDINGS or len(set(map(str, files))) != len(files)
            or not all(isinstance(f, str) and FINDING_FILE.fullmatch(f) for f in files)):
        raise Rejected(f"a manifest files list that is not 1 to {MAX_FINDINGS} distinct finding-<n>.tar.age names")
    return manifest["target"], manifest["module"], manifest["hash"], manifest["reproduced"], files


def check_artifact(directory: Path, target: str | None) -> Finding:
    """One artifact's directory; target is the artifact's, or None when the download dropped its name."""
    entries = {}
    with os.scandir(directory) as it:
        for entry in it:
            if not entry.is_file(follow_symlinks=False):
                raise Rejected("an entry that is not a regular file")
            entries[entry.name] = Path(entry.path)
    if MANIFEST not in entries:
        raise Rejected("no manifest.json")
    target, module, hash_, reproduced, files = check_manifest(read_capped(entries[MANIFEST], MAX_MANIFEST), target)
    if set(entries) != {MANIFEST, *files}:
        raise Rejected("files other than manifest.json and the finding files it lists")
    armoured = [(name, check_armour(read_capped(entries[name], MAX_FILE))) for name in sorted(files)]
    return Finding(target, module, hash_, reproduced, armoured)


def collect(findings_dir: Path) -> tuple[list[Finding], list[str], int]:
    """The checked findings that reproduced, a line for each rejected artifact (by name only when the name is safe), and
    the number of well-formed artifacts skipped as not reproduced."""
    accepted: list[Finding] = []
    rejected: list[str] = []
    skipped = 0
    count = total = 0
    with os.scandir(findings_dir) as it:
        entries = sorted(it, key=lambda e: e.name)
    if any(e.name == MANIFEST for e in entries):
        # One artifact, downloaded without its directory: the whole directory is that artifact.
        artifacts = [(findings_dir, None, "the one artifact")]
    else:
        artifacts = []
        for entry in entries:
            m = ARTIFACT.fullmatch(entry.name)
            if not m or not entry.is_dir(follow_symlinks=False):
                label = entry.name if m else "an artifact with an unexpected name"
                rejected.append(f"{label}: not an artifact directory named fuzz-finding-<target>")
                continue
            artifacts.append((Path(entry.path), m.group(1), entry.name))
    for directory, target, label in artifacts:
        try:
            finding = check_artifact(directory, target)
            if not finding.reproduced:
                skipped += 1
                continue
            size = sum(len(a) for _, a in finding.files)
            if count + len(finding.files) > MAX_FINDINGS:
                raise Rejected(f"more than {MAX_FINDINGS} findings in this run")
            if total + size > MAX_TOTAL:
                raise Rejected(f"more than {MAX_TOTAL} bytes of findings in this run")
            count += len(finding.files)
            total += size
            accepted.append(finding)
        except (Rejected, OSError) as e:
            reason = str(e) if isinstance(e, Rejected) else "an unreadable file"
            rejected.append(f"{label}: {reason}")
    return accepted, rejected, skipped


def summary(finding: Finding, run_id: str) -> str:
    return f"fuzz: {finding.target} {finding.hash}" if finding.hash else f"fuzz: {finding.target} run {run_id}"


def description(finding: Finding, run_url: str) -> str:
    text = "\n".join([
        f"`{finding.target}` failed under Jazzer (spec §9.1 Findings), found by {run_url}.",
        "",
        f"- Jazzer DEDUP_TOKEN: {finding.hash or 'none'}",
        "- Reproduced: a saved input, replayed alone under the same harness, failed again, and the empty input passed.",
        "- Each block below is one saved input: a gzipped tar of the input, the minimised input, the JUnit XML and the"
        " fuzzer, minimiser and replay logs, encrypted with age to the maintainer's key (FUZZ_AGE_RECIPIENT).",
        "",
        "Decrypt (CONTRIBUTING §6): copy a block into `finding.age`, then run"
        " `rage -d -i <identity-file> finding.age > finding.bin` (`age -d -i` works too), and"
        " `tar -xzf finding.bin`. Triage under SECURITY.md; the fix follows CONTRIBUTING §8.",
    ])
    for name, armour in finding.files:
        block = f"\n\n### {name}\n\n```\n{armour.rstrip()}\n```\n"
        if len(text) + len(block) <= MAX_DESCRIPTION:
            text += block
        else:
            text += (f"\n\n### {name}\n\nToo large to inline here: decrypt it from the run's `fuzz-finding-"
                     f"{finding.target}` artifact (kept 7 days).\n")
    return text[:MAX_DESCRIPTION]


def request(method: str, url: str, token: str, body: dict | None = None) -> tuple[object, str]:
    """The decoded JSON answer and the Link header."""
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        **({"Content-Type": "application/json"} if data else {}),
    })
    with urllib.request.urlopen(req) as r:
        return json.load(r), r.headers.get("Link", "")


def existing_summaries(api: str, repo: str, token: str) -> set[str]:
    url = f"{api}/repos/{repo}/security-advisories?per_page=100"
    out: set[str] = set()
    while url:
        page, link = request("GET", url, token)
        out.update(a.get("summary", "") for a in page if isinstance(a, dict))
        nxt = re.search(r'<([^>]+)>;\s*rel="next"', link)
        url = nxt.group(1) if nxt else ""
    return out


def main() -> int:
    findings_dir = Path(sys.argv[1])
    env = {k: os.environ[k] for k in ("GH_TOKEN", "REPO", "RUN_URL", "RUN_ID")}
    api = os.environ.get("API_URL", "https://api.github.com").rstrip("/")
    if not findings_dir.is_dir():
        # The fuzz job failed without a finding (a build error, say): nothing to file.
        print("no finding artifacts in this run")
        return 0
    accepted, rejected, skipped = collect(findings_dir)
    for line in rejected:
        print(f"::error::rejected {line}")
    filed = duplicates = 0
    if accepted:
        known = existing_summaries(api, env["REPO"], env["GH_TOKEN"])
        for finding in accepted:
            title = summary(finding, env["RUN_ID"])
            if title in known:
                duplicates += 1
                continue
            request("POST", f"{api}/repos/{env['REPO']}/security-advisories", env["GH_TOKEN"], {
                "summary": title,
                "description": description(finding, env["RUN_URL"]),
                "vulnerabilities": [{"package": {"ecosystem": "maven", "name": f"dev.revokt:{finding.module}"}}],
            })
            known.add(title)
            filed += 1
    # Nothing about the advisories in this public log beyond the counts.
    print(f"filed {filed} draft advisories; {duplicates} already filed; {skipped} not reproduced, skipped;"
          f" {len(rejected)} artifacts rejected")
    return 1 if rejected else 0


if __name__ == "__main__":
    sys.exit(main())
