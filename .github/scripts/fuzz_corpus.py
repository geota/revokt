# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""Read and check the private fuzz corpus as data (fuzz.yml seed, fuzz, merge and prune jobs, #265; CONTRIBUTING §6).

The corpus repository holds corpus/<Class>-<method>/<unit> for each target, each unit named as libFuzzer names one,
the SHA-1 of its content in lowercase hex. Two caps apply: SEED for the nightly's seed, and the higher PRUNE for the
weekly prune's read and merge (--prune), so a target that outgrew the seed caps is still merged back under them.

- `stage [--prune] <corpus dir> <out dir>`: the seed job's read of a clone's corpus/. For each known target whose
  directory exists, every entry must be a regular file (no link, no subdirectory) named by the SHA-1 of its content;
  anything else rejects the whole corpus and nothing is staged. A unit over its target's -max_len is left out and
  counted; the next prune drops it, as ClusterFuzz's does, without keeping a cut-down copy (a prune never adds one).
  A target over the caps (its units, its bytes, or the staged total) is left out: with a warning for the seed, and with
  an error and exit status 3 under --prune, where the other targets are still staged and the workflow fails the run
  once they are pruned. Under --prune, a target whose units are all over its -max_len (a -max_len lowered below every
  stored unit) is an error with exit status 3 in the same way: nothing is left to merge, and the prune deletes only
  what a merge decided. Entries of corpus/ that are not a known target's directory are ignored (a renamed or removed
  target) and counted. The accepted units are copied to <out dir>/<Class>-<method>/; a target with none gets no
  directory.
- `check [--prune] <dir> [--within <ref dir>] [--lists <lists dir>]`: the check of a downloaded artifact (the staged
  seed, or the merged corpora), which a job that ran the fuzzed tree's code could have written. Every top-level entry
  must be a non-empty directory of a known target, holding only regular files named by their content's SHA-1, each
  within the target's -max_len, and the caps must hold. With --within, each unit must also be in
  <ref dir>/<Class>-<method>/, a real directory: a merge only selects units, so a merged corpus that is not a subset
  of what was read is rejected. With --lists, <lists dir> holds one file per target directory, named as it, listing
  that directory's unit names one a line, as the merge job wrote them; the units must be exactly those listed, and
  every list must have its directory, so a partial download is rejected rather than read as a smaller merge.

The targets are the TARGETS environment variable, the targets job's JSON list (name, maxLen). Names are checked before
use; nothing from a unit, and no name read from the corpus, is printed. An exit status of 1 with an `::error::` line
means rejected. Python 3.10 or later, standard library only.
"""
import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
from dataclasses import dataclass
from pathlib import Path

TARGET = re.compile(r"[A-Za-z0-9_]{1,100}\.[A-Za-z0-9_]{1,100}")
UNIT = re.compile(r"[0-9a-f]{40}")
# libFuzzer's default -max_len cap, for a target whose source names none (as the corpus job assumes).
DEFAULT_MAX_LEN = 16 * 1024 * 1024 + 1


@dataclass(frozen=True)
class Caps:
    units: int
    target_bytes: int
    total_bytes: int

    def __str__(self) -> str:
        return f"{self.units} units and {self.target_bytes} bytes a target, {self.total_bytes} bytes in all"


# A week of nightly pushes (5,000 new units a target a night) fits under the seed's units before the weekly prune; the
# prune reads up to five times as much, so a target that outgrew the seed (a skipped or failed prune) still shrinks.
SEED = Caps(40_000, 128 * 1024 * 1024, 512 * 1024 * 1024)
PRUNE = Caps(200_000, 512 * 1024 * 1024, 2 * 1024 * 1024 * 1024)
OVER_CAPS = 3


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


def stage(corpus: Path, out: Path, targets: dict[str, int], prune: bool = False) -> tuple[int, int]:
    """Copies the accepted units of [corpus] to [out]; returns the units staged and the targets the prune leaves out."""
    caps = PRUNE if prune else SEED
    if os.path.lexists(out):
        raise Rejected("the staging directory already exists")
    if not os.path.lexists(corpus):
        out.mkdir(parents=True)
        print("the corpus repository has no corpus/ directory; nothing is staged")
        return 0, 0
    if not stat.S_ISDIR(os.lstat(corpus).st_mode):
        raise Rejected("corpus/ is not a directory")
    present = sorted(e.name for e in os.scandir(corpus))
    ignored = sum(1 for n in present if n not in targets)
    plan, total, over_caps = [], 0, 0
    for d in sorted(targets):
        if d not in present:
            continue
        kept, over = units(corpus / d, targets[d], d)
        size = sum(s for _, s in kept)
        if len(kept) > caps.units or size > caps.target_bytes or total + size > caps.total_bytes:
            over_caps += 1
            if prune:
                print(f"::error::{d}: {len(kept)} units, {size} bytes, over the prune's caps ({caps}); it is not "
                      "pruned, and needs trimming by hand (CONTRIBUTING §6)")
            else:
                print(f"::warning::{d}: {len(kept)} units, {size} bytes, over the seed's caps ({caps}); it starts "
                      "from its committed inputs until the weekly prune shrinks it")
            continue
        if prune and over and not kept:
            over_caps += 1
            print(f"::error::{d}: all {over} units are over its -max_len; it is not pruned, and needs trimming by hand "
                  "(CONTRIBUTING §6)")
            continue
        verify(corpus / d, kept, d)
        total += size
        if kept:
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
    return staged, over_caps


def real_dir(p: Path) -> bool:
    return os.path.lexists(p) and stat.S_ISDIR(os.lstat(p).st_mode)


def read_lists(lists: Path, targets: dict[str, int], caps: Caps) -> dict[str, set[str]]:
    """The merge jobs' unit lists: one regular file per target, a unit name a line."""
    if not real_dir(lists):
        raise Rejected("the unit lists are not a directory")
    out = {}
    with os.scandir(lists) as it:
        for e in it:
            if e.name not in targets:
                raise Rejected("a unit list that is not a known target's")
            est = e.stat(follow_symlinks=False)
            if not stat.S_ISREG(est.st_mode) or est.st_size > 41 * caps.units:
                raise Rejected(f"{e.name}: its unit list is not a regular file within the caps")
            names = (lists / e.name).read_bytes().decode("ascii", "replace").splitlines()
            if not names or not all(UNIT.fullmatch(n) for n in names):
                raise Rejected(f"{e.name}: its unit list is empty or holds a line that is not a unit name")
            out[e.name] = set(names)
    return out


def check(dir_: Path, targets: dict[str, int], within: Path | None, lists: Path | None = None,
          prune: bool = False) -> int:
    """Checks a downloaded artifact; returns its unit count."""
    caps = PRUNE if prune else SEED
    if not real_dir(dir_):
        raise Rejected("the artifact is not a directory")
    listed = read_lists(lists, targets, caps) if lists is not None else None
    total, count, seen = 0, 0, set()
    for e in sorted(os.scandir(dir_), key=lambda e: e.name):
        if e.name not in targets:
            raise Rejected("an entry that is not a known target's directory")
        kept, over = units(dir_ / e.name, targets[e.name], e.name)
        if over:
            raise Rejected(f"{e.name}: a unit over its target's -max_len")
        if not kept:
            raise Rejected(f"{e.name}: an empty target directory")
        size = sum(s for _, s in kept)
        if len(kept) > caps.units or size > caps.target_bytes:
            raise Rejected(f"{e.name}: over the caps ({caps})")
        total += size
        if total > caps.total_bytes:
            raise Rejected(f"over the caps ({caps})")
        verify(dir_ / e.name, kept, e.name)
        if within is not None:
            ref = within / e.name
            if not real_dir(ref):
                raise Rejected(f"{e.name}: no such directory in the corpus that was read")
            for name, _ in kept:
                p = ref / name
                if not os.path.lexists(p) or not stat.S_ISREG(os.lstat(p).st_mode):
                    raise Rejected(f"{e.name}: a unit that is not in the corpus that was read")
        if listed is not None and listed.get(e.name) != {n for n, _ in kept}:
            raise Rejected(f"{e.name}: its units are not exactly the merge job's list (a partial download?)")
        seen.add(e.name)
        count += len(kept)
    if listed is not None and set(listed) != seen:
        raise Rejected("a unit list without its target directory (a partial download?)")
    print(f"checked {count} units, {total} bytes")
    return count


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(prog="fuzz_corpus.py")
    sub = parser.add_subparsers(dest="command", required=True)
    st = sub.add_parser("stage")
    st.add_argument("--prune", action="store_true")
    st.add_argument("corpus", type=Path)
    st.add_argument("out", type=Path)
    ch = sub.add_parser("check")
    ch.add_argument("--prune", action="store_true")
    ch.add_argument("dir", type=Path)
    ch.add_argument("--within", type=Path)
    ch.add_argument("--lists", type=Path)
    args = parser.parse_args(argv)
    try:
        targets = targets_from(os.environ.get("TARGETS", ""))
        if args.command == "stage":
            _, over_caps = stage(args.corpus, args.out, targets, args.prune)
            if over_caps and args.prune:
                return OVER_CAPS
        else:
            check(args.dir, targets, args.within, args.lists, args.prune)
    except Rejected as e:
        print(f"::error::the fuzz corpus is malformed ({e}); it is not used")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
