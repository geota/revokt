# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""Record a fuzz finding as a private draft repository security advisory (fuzz.yml, #115; CONTRIBUTING §6).

A draft advisory is visible only to the repository's administrators and security managers, so the reproducer never
appears in a public issue, artifact or log. The summary is `fuzz: <target> <sha8>`, the first 8 hex digits of the
reproducer's SHA-256 (the minimised input when fuzz.yml produced one, `min-<name>`); a draft with the same summary is
left as it is, so a different crash in the same target still gets its own advisory. The description holds the run
link, the libFuzzer flags and seed, the stack trace from the JUnit XML (at most 12 000 characters) and each finding:
base64-encoded when it is at most 36 KiB and the description still fits the API's 65 535 characters, otherwise its
size and SHA-256 with a note that the advisory cannot reproduce it.

Python 3.10 or later, standard library only. Usage: fuzz_advisory.py <findings dir>. Environment: GH_TOKEN
(FUZZ_ADVISORY_TOKEN: Repository security advisories read and write), REPO, RUN_URL, TARGET, PROJECT, SOURCE, FLAGS;
API_URL overrides https://api.github.com (tests only).
"""
import base64
import hashlib
import json
import os
import re
import sys
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

FINDING_PREFIXES = ("crash-", "timeout-", "oom-", "leak-", "slow-unit-")
# 36 KiB encodes to 49 152 characters; with a full 12 000-character trace and the head (under 3 000) that stays under
# 65 535. The description check below still applies, for a long head or several findings.
MAX_INLINE_BYTES = 36 * 1024
MAX_DESCRIPTION = 65535
MAX_TRACE = 12000


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


def draft_summaries(api: str, repo: str, token: str) -> set[str]:
    url = f"{api}/repos/{repo}/security-advisories?state=draft&per_page=100"
    out: set[str] = set()
    while url:
        page, link = request("GET", url, token)
        out.update(a.get("summary", "") for a in page)
        nxt = re.search(r'<([^>]+)>;\s*rel="next"', link)
        url = nxt.group(1) if nxt else ""
    return out


def stack_traces(findings: Path) -> str:
    traces = []
    for xml in sorted(findings.glob("TEST-*.xml")):
        for failure in ET.parse(xml).getroot().iter("failure"):
            traces.append((failure.text or failure.get("message") or "").strip())
    text = "\n\n".join(t for t in traces if t) or "(no JUnit failure recorded)"
    return text if len(text) <= MAX_TRACE else text[:MAX_TRACE] + "\n… (truncated)"


def seed(findings: Path) -> str:
    log = findings / "gradle.log"
    found = re.search(r"INFO: Seed: (\d+)", log.read_text(errors="replace")) if log.is_file() else None
    return found.group(1) if found else "unknown"


def findings_of(findings: Path) -> list[tuple[Path, bytes]]:
    """Each finding file with its reproducer: the minimised input when there is a non-empty one, else the file."""
    out = []
    for p in sorted(findings.iterdir()):
        if p.is_file() and p.name.startswith(FINDING_PREFIXES):
            minimised = findings / f"min-{p.name}"
            raw = minimised.read_bytes() if minimised.is_file() and minimised.stat().st_size > 0 else b""
            out.append((p, raw or p.read_bytes()))
    return out


def summary(target: str, found: list[tuple[Path, bytes]], trace: str) -> str:
    key = found[0][1] if found else trace.splitlines()[0].encode()
    return f"fuzz: {target} {hashlib.sha256(key).hexdigest()[:8]}"


def description(env: dict, findings: Path, found: list[tuple[Path, bytes]], trace: str) -> str:
    text = "\n".join([
        f"`{env['TARGET']}` (`{env['SOURCE']}`) failed under Jazzer (spec §9.1 Findings).",
        "",
        f"- Run: {env['RUN_URL']}",
        f"- libFuzzer flags: `{env['FLAGS']}`; seed {seed(findings)}",
        "",
        "Triage under SECURITY.md; the fix follows CONTRIBUTING §8. Reproduce by saving a finding below to "
        f"`{env['SOURCE'].split('/src/')[0]}/src/jvmTest/resources/<package>/<Class>Inputs/` or by passing it to the target.",
        "",
        "## Stack trace",
        "",
        "```",
        trace,
        "```",
        "",
        "## Findings",
        "",
        *([] if found else ["No finding file was written; re-run the target with the flags and seed above."]),
    ])
    for p, raw in found:
        original = p.read_bytes()
        what = f"`{p.name}`, {len(original)} bytes, SHA-256 `{hashlib.sha256(original).hexdigest()}`"
        if raw != original:
            what += f"; minimised to {len(raw)} bytes, SHA-256 `{hashlib.sha256(raw).hexdigest()}`"
        label = "minimised input" if raw != original else "input"
        inline = f"\n### {what}\n\nBase64 of the {label}:\n\n```\n{base64.b64encode(raw).decode()}\n```\n"
        listed = (f"\n### {what}\n\n**Not reproducible from this advisory**: the input is above {MAX_INLINE_BYTES // 1024} KiB "
                  "or past the description limit. Re-run the target with the flags and seed above to regenerate it.\n")
        fits = len(raw) <= MAX_INLINE_BYTES and len(text) + len(inline) <= MAX_DESCRIPTION
        text += inline if fits else listed
    return text[:MAX_DESCRIPTION]


def main() -> int:
    findings = Path(sys.argv[1])
    env = {k: os.environ[k] for k in ("GH_TOKEN", "REPO", "RUN_URL", "TARGET", "PROJECT", "SOURCE", "FLAGS")}
    api = os.environ.get("API_URL", "https://api.github.com").rstrip("/")
    found = findings_of(findings)
    trace = stack_traces(findings)
    title = summary(env["TARGET"], found, trace)
    if title in draft_summaries(api, env["REPO"], env["GH_TOKEN"]):
        print("A draft advisory for this finding already exists; not creating another.")
        return 0
    body = {
        "summary": title,
        "description": description(env, findings, found, trace),
        "vulnerabilities": [{"package": {"ecosystem": "maven", "name": "dev.revokt:" + env["PROJECT"].lstrip(":")}}],
    }
    request("POST", f"{api}/repos/{env['REPO']}/security-advisories", env["GH_TOKEN"], body)
    # Nothing about the advisory in this public log beyond that it exists.
    print("Recorded as a draft security advisory.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
