# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""Read and check the private fuzz corpus as data (fuzz.yml seed, fuzz, merge and prune jobs, #265; CONTRIBUTING §6).

The corpus repository holds corpus/<Class>-<method>/<unit> for each target, each unit named as libFuzzer names one,
the SHA-1 of its content in lowercase hex. Two commands:

- `stage <corpus dir> <out dir>`: the seed job's read of a clone's corpus/. For each known target whose directory
  exists, every entry must be a regular file (no link, no subdirectory) named by the SHA-1 of its content; anything
  else rejects the whole corpus and nothing is staged. A unit over its target's -max_len is left out and counted (the
  next prune drops it). A target over its own caps (MAX_UNITS units, MAX_TARGET_BYTES bytes) is left out with a
  warning, as is each target that would take the staged total past MAX_TOTAL_BYTES. Entries of corpus/ that are not a
  known target's directory are ignored (a renamed or removed target) and counted. The accepted units are copied to
  <out dir>/<Class>-<method>/.
- `check <dir> [--within <ref dir>]`: the check of a downloaded artifact (the staged seed, or a merged corpus), which
  a job that ran the fuzzed tree's code could have written. Every top-level entry must be a directory of a known
  target, holding only regular files named by their content's SHA-1, each within the target's -max_len, and the
  target and total caps must hold. With --within, each unit must also be in <ref dir>/<Class>-<method>/: a merge only
  selects units, so a merged corpus that is not a subset of what was read is rejected.

The targets are the TARGETS environment variable, the targets job's JSON list (name, maxLen). Names are checked before
use; nothing from a unit, and no name read from the corpus, is printed. An exit status of 1 with an `::error::` line
means rejected. Python 3.10 or later, standard library only.
"""
import hashlib
import json
import os
import re
import shutil
import stat
import sys
from pathlib import Path

TARGET = re.compile(r"[A-Za-z0-9_]{1,100}\.[A-Za-z0-9_]{1,100}")
UNIT = re.compile(r"[0-9a-f]{40}")
# libFuzzer's default -max_len cap, for a target whose source names none (as the corpus job assumes).
DEFAULT_MAX_LEN = 16 * 1024 * 1024 + 1
# A week of nightly pushes (5,000 new units a target a night) fits under MAX_UNITS before the weekly prune.
MAX_UNITS = 40_000
MAX_TARGET_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = 512 * 1024 * 1024


class Rejected(Exception):
    """The corpus is malformed; the message names the rule, never a unit or an unexpected name."""


def targets_from(text: str) -> dict[str, int]:
    """Directory name (`Class-method`) to -max_len, from the targets job's JSON list."""
    try:
        data = json.loads(text)
    except ValueError as e:
        raise Rejected("TARGETS is not JSON") from e
    if not isinstance(data, list) or not data:
        raise Rejected("TARGETS is not a non-empty list")
    out = {}
    for t in data:
        if not isinstance(t, dict) or not isinstance(t.get("name"), str) or not TARGET.fullmatch(t["name"]):
            raise Rejected("a target name in TARGETS")
        max_len = t.get("maxLen")
        if max_len is None:
            max_len = DEFAULT_MAX_LEN
        if not isinstance(max_len, int) or isinstance(max_len, bool) or max_len < 1:
            raise Rejected("a maxLen in TARGETS")
        out[t["name"].replace(".", "-")] = max_len
    return out


def sha1(path: Path) -> str:
    h = hashlib.sha1()  # libFuzzer's unit name, not a security hash
    with open(path, "rb", opener=lambda p, f: os.open(p, f | os.O_NOFOLLOW)) as f:
        for block in iter(lambda: f.read(1 << 20), b""):
            h.update(block)
    return h.hexdigest()


def units(dir_: Path, max_len: int, label: str) -> tuple[list[tuple[str, int]], int]:
    """(name, size) of each unit in [dir_] within [max_len], and the count over it; rejects anything not a unit."""
    st = os.lstat(dir_)
    if not stat.S_ISDIR(st.st_mode):
        raise Rejected(f"{label}: not a directory")
    kept, over = [], 0
    with os.scandir(dir_) as it:
        for e in it:
            est = e.stat(follow_symlinks=False)
            if not stat.S_ISREG(est.st_mode):
                raise Rejected(f"{label}: an entry that is not a regular file")
            if not UNIT.fullmatch(e.name):
                raise Rejected(f"{label}: a file not named as a corpus unit")
            if est.st_size > max_len:
                over += 1
            else:
                kept.append((e.name, est.st_size))
    kept.sort()
    return kept, over


def verify(dir_: Path, kept: list[tuple[str, int]], label: str) -> None:
    for name, _ in kept:
        if sha1(dir_ / name) != name:
            raise Rejected(f"{label}: a unit whose name is not its SHA-1")


def stage(corpus: Path, out: Path, targets: dict[str, int]) -> int:
    """Copies the accepted units of [corpus] to [out]; returns the number staged."""
    if os.path.lexists(out):
        raise Rejected("the staging directory already exists")
    if not os.path.lexists(corpus):
        out.mkdir(parents=True)
        print("the corpus repository has no corpus/ directory; nothing is staged")
        return 0
    if not stat.S_ISDIR(os.lstat(corpus).st_mode):
        raise Rejected("corpus/ is not a directory")
    present = sorted(e.name for e in os.scandir(corpus))
    ignored = sum(1 for n in present if n not in targets)
    plan, total = [], 0
    for d in sorted(targets):
        if d not in present:
            continue
        kept, over = units(corpus / d, targets[d], d)
        size = sum(s for _, s in kept)
        if len(kept) > MAX_UNITS or size > MAX_TARGET_BYTES:
            print(f"::warning::{d}: {len(kept)} units, {size} bytes, over the seed caps ({MAX_UNITS} units, "
                  f"{MAX_TARGET_BYTES} bytes); it is not seeded or pruned")
            continue
        if total + size > MAX_TOTAL_BYTES:
            print(f"::warning::{d}: the seed would pass {MAX_TOTAL_BYTES} bytes in all; it is not seeded or pruned")
            continue
        verify(corpus / d, kept, d)
        total += size
        plan.append((d, kept, over))
    out.mkdir(parents=True)
    staged = 0
    for d, kept, over in plan:
        (out / d).mkdir()
        for name, _ in kept:
            shutil.copyfile(corpus / d / name, out / d / name, follow_symlinks=False)
        staged += len(kept)
        print(f"{d}: {len(kept)} units" + (f", {over} over its -max_len left out" if over else ""))
    if ignored:
        print(f"{ignored} entries of corpus/ that are not a current target's directory are ignored")
    print(f"staged {staged} units, {total} bytes")
    return staged


def check(dir_: Path, targets: dict[str, int], within: Path | None) -> int:
    """Checks a downloaded artifact; returns its unit count."""
    if not stat.S_ISDIR(os.lstat(dir_).st_mode):
        raise Rejected("the artifact is not a directory")
    total, count = 0, 0
    for e in sorted(os.scandir(dir_), key=lambda e: e.name):
        if e.name not in targets:
            raise Rejected("an entry that is not a known target's directory")
        kept, over = units(dir_ / e.name, targets[e.name], e.name)
        if over:
            raise Rejected(f"{e.name}: a unit over its target's -max_len")
        size = sum(s for _, s in kept)
        if len(kept) > MAX_UNITS or size > MAX_TARGET_BYTES:
            raise Rejected(f"{e.name}: over the caps ({MAX_UNITS} units, {MAX_TARGET_BYTES} bytes)")
        total += size
        if total > MAX_TOTAL_BYTES:
            raise Rejected(f"more than {MAX_TOTAL_BYTES} bytes in all")
        verify(dir_ / e.name, kept, e.name)
        if within is not None:
            ref = within / e.name
            if not os.path.lexists(ref) or not stat.S_ISDIR(os.lstat(ref).st_mode):
                raise Rejected(f"{e.name}: no such directory in the corpus that was read")
            for name, _ in kept:
                p = ref / name
                if not os.path.lexists(p) or not stat.S_ISREG(os.lstat(p).st_mode):
                    raise Rejected(f"{e.name}: a unit that is not in the corpus that was read")
        count += len(kept)
    print(f"checked {count} units, {total} bytes")
    return count


def main(argv: list[str]) -> int:
    try:
        targets = targets_from(os.environ.get("TARGETS", ""))
        if len(argv) == 3 and argv[0] == "stage":
            stage(Path(argv[1]), Path(argv[2]), targets)
        elif len(argv) in (2, 4) and argv[0] == "check" and (len(argv) == 2 or argv[2] == "--within"):
            check(Path(argv[1]), targets, Path(argv[3]) if len(argv) == 4 else None)
        else:
            print("usage: fuzz_corpus.py stage <corpus dir> <out dir> | check <dir> [--within <ref dir>]", file=sys.stderr)
            return 2
    except Rejected as e:
        print(f"::error::the fuzz corpus is malformed ({e}); it is not used")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
