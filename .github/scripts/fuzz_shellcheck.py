# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""Shellcheck one job's `run:` blocks (ci.yml ci-extras, #115).

fuzz.yml's fuzz job runs every step under a custom shell (`/usr/bin/bash --noprofile --norc …`), and actionlint
shellchecks only the named shells, so it skips them. This writes each `run: |` block of the job to its own file, with
each `${{ … }}` replaced by a placeholder as actionlint does, and runs shellcheck as bash over all of them. A `run:`
that is not a literal block (`|`, `|-`) fails, so no step goes unchecked.

Python 3.10 or later, standard library only, and shellcheck on the PATH.
Usage: fuzz_shellcheck.py <workflow file> <job id>
"""
import re
import subprocess
import sys
import tempfile
from pathlib import Path

JOB = re.compile(r"^  ([A-Za-z0-9_-]+):\s*$")
JOB_KEY = re.compile(r"^    ([A-Za-z0-9_-]+):")
RUN = re.compile(r"^(\s*)(- )?run:\s*(.*?)\s*$")
EXPRESSION = re.compile(r"\$\{\{.*?\}\}")


def run_blocks(lines: list[str], job: str) -> list[tuple[int, str]]:
    """(line number, script) for each step's `run:` in the job; exits on one that is not a literal block."""
    blocks = []
    in_jobs = in_job = in_steps = False
    i = 0
    while i < len(lines):
        line = lines[i]
        if not line.startswith(" ") and line.strip():
            in_jobs, in_job, in_steps = line.rstrip() == "jobs:", False, False
        elif in_jobs and (m := JOB.match(line)):
            in_job, in_steps = m.group(1) == job, False
        elif in_job and (m := JOB_KEY.match(line)):
            # The job's own keys; only `steps:` holds runs (`defaults: run:` is a mapping, not a script).
            in_steps = m.group(1) == "steps"
        elif in_steps and (m := RUN.match(line)):
            key_indent = len(m.group(1)) + (2 if m.group(2) else 0)
            if m.group(3) not in ("|", "|-"):
                sys.exit(f"line {i + 1}: a run: that is not a literal block (|); it would not be checked")
            body = []
            j = i + 1
            while j < len(lines) and (not lines[j].strip() or len(lines[j]) - len(lines[j].lstrip()) > key_indent):
                body.append(lines[j])
                j += 1
            indent = min((len(b) - len(b.lstrip()) for b in body if b.strip()), default=0)
            blocks.append((i + 1, "\n".join(b[indent:] for b in body).rstrip() + "\n"))
            i = j
            continue
        i += 1
    return blocks


def main() -> int:
    workflow, job = Path(sys.argv[1]), sys.argv[2]
    blocks = run_blocks(workflow.read_text().splitlines(), job)
    if not blocks:
        sys.exit(f"no run: block in job {job} of {workflow}")
    with tempfile.TemporaryDirectory() as tmp:
        files = []
        for line, script in blocks:
            f = Path(tmp) / f"{workflow.stem}-{job}-line-{line}.sh"
            f.write_text(EXPRESSION.sub("X", script))
            files.append(str(f))
        result = subprocess.run(["shellcheck", "--shell=bash", *files], check=False)
    print(f"shellcheck: {len(blocks)} run blocks of {workflow.name} job {job}, exit {result.returncode}")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main())
