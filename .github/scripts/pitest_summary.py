#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""Markdown job summary of a Pitest mutations.xml (#215): the totals per package, then every surviving mutant.

Usage: pitest_summary.py <mutations.xml>; prints Markdown for $GITHUB_STEP_SUMMARY. Survivors are where a test could
be added, not a gate: the run never fails on them.
"""
import sys
import xml.etree.ElementTree as ET
from collections import Counter, defaultdict


def main(path: str) -> None:
    root = ET.parse(path).getroot()
    totals = defaultdict(Counter)
    survivors = []
    for m in root.iter("mutation"):
        cls = m.findtext("mutatedClass") or ""
        package = cls.rsplit(".", 1)[0].removeprefix("dev.revokt.engine.")
        status = m.get("status") or "?"
        totals[package][status] += 1
        if status in ("SURVIVED", "NO_COVERAGE"):
            survivors.append(
                (
                    package,
                    m.findtext("sourceFile") or "",
                    int(m.findtext("lineNumber") or 0),
                    m.findtext("mutatedMethod") or "",
                    (m.findtext("mutator") or "").rsplit(".", 1)[-1],
                    m.findtext("description") or "",
                    status,
                )
            )
    print("## Pitest: surviving mutants\n")
    print("| Package | Mutants | Killed | Survived | No coverage | Timed out | Killed % |")
    print("|---|---:|---:|---:|---:|---:|---:|")
    for package in sorted(totals):
        c = totals[package]
        n = sum(c.values())
        killed = c["KILLED"] + c["TIMED_OUT"] + c["MEMORY_ERROR"]
        print(
            f"| `{package}` | {n} | {c['KILLED']} | {c['SURVIVED']} | {c['NO_COVERAGE']} | {c['TIMED_OUT']} | "
            f"{round(100 * killed / max(n, 1))} |"
        )
    print(f"\n{len(survivors)} survived or not covered (a lead for a test, or an equivalent mutant):\n")
    print("| Package | File:line | Method | Mutator | Description | Status |")
    print("|---|---|---|---|---|---|")
    for package, source, line, method, mutator, description, status in sorted(survivors):
        print(f"| `{package}` | `{source}:{line}` | `{method}` | {mutator} | {description} | {status} |")


if __name__ == "__main__":
    main(sys.argv[1])
