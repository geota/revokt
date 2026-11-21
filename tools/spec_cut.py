# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""Cut a spec revision from the changelog fragments (#272, CONTRIBUTING §1).

A PR that changes the spec adds `docs/spec/changes/<issue>.md` with its changelog bullets. When the maintainer
decides a revision is done, this script:
- reads the core's status line (`Status: **draft spec, revision N** ... · Date: YYYY-MM-DD`) and cuts revision N+1;
- concatenates the fragments in issue order under `### Changes in revision N+1 (<summary>, <date>)`, inserted above
  the newest block of `docs/spec/CHANGELOG.md`;
- sets the status line to revision N+1 and the date;
- deletes the fragments.
It refuses, changing nothing, when there is no fragment, a file in `docs/spec/changes/` is not `<issue>.md`, a fragment
is empty, the status line is not found exactly once, or the changelog's newest block is already revision N+1 or later.

The cut is its own PR, titled `spec(<scope>): cut revision <N+1>`; pr-lint lets only that title edit the newest block
and the status line.

Python 3.10 or later, standard library only. Run from the repository root:
  uv run --no-project python -I tools/spec_cut.py --summary "<what the revision is about>" [--date YYYY-MM-DD]
  [--dry-run] [--root <dir>]
"""
from __future__ import annotations

import argparse
import datetime
import re
import sys
from pathlib import Path

STATUS = re.compile(r"^(Status: \*\*draft spec, revision )(\d+)(\*\*.*· Date: )(\d{4}-\d{2}-\d{2})$", re.M)
HEADING = re.compile(r"^### Changes in revision (\d+)\b.*$", re.M)
FRAGMENT = re.compile(r"^([1-9]\d*)\.md$")
SPDX = re.compile(r"^<!-- SPDX-[A-Za-z-]+: .* -->\n", re.M)


class CutError(Exception):
    """A precondition of the cut failed; nothing was written."""


def fragments(changes: Path) -> list[tuple[int, Path]]:
    if not changes.is_dir():
        raise CutError(f"{changes} does not exist: no fragments to cut")
    found = []
    for p in changes.iterdir():
        m = FRAGMENT.match(p.name)
        if not m or not p.is_file() or p.is_symlink():
            raise CutError(f"{p}: only regular files named <issue>.md belong in docs/spec/changes/")
        found.append((int(m.group(1)), p))
    if not found:
        raise CutError(f"{changes} holds no fragments")
    return sorted(found)


def fragment_text(path: Path) -> str:
    text = SPDX.sub("", path.read_text(encoding="utf-8")).strip()
    if not text:
        raise CutError(f"{path} is empty")
    return text


def cut(root: Path, summary: str, date: str) -> tuple[int, str, str, list[Path]]:
    """Returns the new revision, the new core text, the new changelog text and the fragments to delete."""
    summary = summary.strip()
    if not summary or "\n" in summary:
        raise CutError("--summary must be one non-empty line")
    datetime.date.fromisoformat(date)
    spec_dir = root / "docs" / "spec"
    core_path, log_path = spec_dir / "revokt-spec.md", spec_dir / "CHANGELOG.md"
    core, log = core_path.read_text(encoding="utf-8"), log_path.read_text(encoding="utf-8")

    status = STATUS.findall(core)
    if len(status) != 1:
        raise CutError(f"{core_path}: expected one status line, found {len(status)}")
    revision = int(status[0][1]) + 1
    newest = HEADING.search(log)
    if newest is None:
        raise CutError(f"{log_path}: no '### Changes in revision N' heading")
    if int(newest.group(1)) >= revision:
        raise CutError(f"{log_path}: the newest block is revision {newest.group(1)}, not below {revision}")

    frags = fragments(spec_dir / "changes")
    body = "\n".join(fragment_text(p) for _, p in frags)
    block = f"### Changes in revision {revision} ({summary}, {date})\n\n{body}\n\n"
    new_log = log[: newest.start()] + block + log[newest.start():]
    new_core = STATUS.sub(lambda m: f"{m.group(1)}{revision}{m.group(3)}{date}", core, count=1)
    return revision, new_core, new_log, [p for _, p in frags]


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Cut a spec revision from docs/spec/changes/ (#272).")
    ap.add_argument("--summary", required=True, help="what the revision is about, as in the older headings")
    ap.add_argument("--date", default=datetime.date.today().isoformat(), help="the cut date, YYYY-MM-DD (default today)")
    ap.add_argument("--root", type=Path, default=Path.cwd(), help="the repository root (default the working directory)")
    ap.add_argument("--dry-run", action="store_true", help="print the new block and change nothing")
    args = ap.parse_args(argv)
    try:
        revision, new_core, new_log, frags = cut(args.root, args.summary, args.date)
    except (CutError, ValueError, OSError) as e:
        print(f"spec_cut: {e}", file=sys.stderr)
        return 1
    if args.dry_run:
        start = new_log.index(f"### Changes in revision {revision} ")
        end = HEADING.search(new_log, start + 1)
        sys.stdout.write(new_log[start: end.start() if end else len(new_log)])
        return 0
    spec_dir = args.root / "docs" / "spec"
    (spec_dir / "CHANGELOG.md").write_text(new_log, encoding="utf-8")
    (spec_dir / "revokt-spec.md").write_text(new_core, encoding="utf-8")
    for p in frags:
        p.unlink()
    print(f"spec_cut: revision {revision} cut from {len(frags)} fragment(s); open it as 'spec(<scope>): cut revision {revision}'")
    return 0


if __name__ == "__main__":
    sys.exit(main())
