# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""Tests for tools/spec_cut.py (#272): the cut of a spec revision from the changelog fragments.

Run: python3 -I -m unittest discover -s .github/scripts -p 'test_*.py' (ci.yml static). Standard library only; each
test works in its own temporary directory.
"""
import importlib.util
import io
import shutil
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "spec_cut", Path(__file__).resolve().parents[2] / "tools" / "spec_cut.py")
sc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(sc)

CORE = "# revokt\n\nStatus: **draft spec, revision 61** · Target: JVM 17+ · Date: 2026-11-19\n\nBody.\n"
# A header line as a fragment may carry; split so that reuse does not read it as this file's own.
HEADER = "<!-- SPDX-" + "License-Identifier: Apache-2.0 -->\n"
LOG = ("# Spec changelog\n\nIntro.\n\n### Changes in revision 61 (the last cut, 2026-11-20)\n\n- **#1:** old.\n\n"
       "### Changes in revision 60 (older)\n\n- **#0:** older.\n")


class SpecCutTest(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.spec = self.root / "docs" / "spec"
        (self.spec / "changes").mkdir(parents=True)
        (self.spec / "revokt-spec.md").write_text(CORE, encoding="utf-8")
        (self.spec / "CHANGELOG.md").write_text(LOG, encoding="utf-8")

    def tearDown(self):
        shutil.rmtree(self.root, ignore_errors=True)

    def frag(self, name, text):
        (self.spec / "changes" / name).write_text(text, encoding="utf-8")

    def run_cut(self, *extra):
        out, err = io.StringIO(), io.StringIO()
        with redirect_stdout(out), redirect_stderr(err):
            code = sc.main(["--root", str(self.root), "--summary", "two fixes", "--date", "2026-12-01", *extra])
        return code, out.getvalue(), err.getvalue()

    def read(self, name):
        return (self.spec / name).read_text(encoding="utf-8")

    def test_cut_orders_by_issue_number_bumps_status_and_deletes_fragments(self):
        self.frag("300.md", "- **#300:** third.\n")
        self.frag("27.md", HEADER + "- **#27:** first.\n  - nested.\n")
        self.frag("280.md", "\n- **#280:** second.\n\n")
        code, _, err = self.run_cut()
        self.assertEqual(code, 0, err)
        self.assertEqual(self.read("CHANGELOG.md"), (
            "# Spec changelog\n\nIntro.\n\n### Changes in revision 62 (two fixes, 2026-12-01)\n\n"
            "- **#27:** first.\n  - nested.\n- **#280:** second.\n- **#300:** third.\n\n"
            "### Changes in revision 61 (the last cut, 2026-11-20)\n\n- **#1:** old.\n\n"
            "### Changes in revision 60 (older)\n\n- **#0:** older.\n"))
        self.assertEqual(self.read("revokt-spec.md"), CORE.replace("revision 61", "revision 62").replace("2026-11-19", "2026-12-01"))
        self.assertEqual(list((self.spec / "changes").iterdir()), [])

    def test_dry_run_prints_the_block_and_writes_nothing(self):
        self.frag("5.md", "- **#5:** x.\n")
        code, out, _ = self.run_cut("--dry-run")
        self.assertEqual(code, 0)
        self.assertEqual(out, "### Changes in revision 62 (two fixes, 2026-12-01)\n\n- **#5:** x.\n\n")
        self.assertEqual(self.read("CHANGELOG.md"), LOG)
        self.assertEqual(self.read("revokt-spec.md"), CORE)
        self.assertTrue((self.spec / "changes" / "5.md").exists())

    def assert_refused(self, message, *extra):
        code, _, err = self.run_cut(*extra)
        self.assertEqual(code, 1)
        self.assertIn(message, err)
        self.assertEqual(self.read("CHANGELOG.md"), LOG)
        self.assertEqual(self.read("revokt-spec.md"), CORE)

    def test_refuses_without_fragments(self):
        self.assert_refused("holds no fragments")

    def test_refuses_a_file_not_named_by_issue(self):
        self.frag("5.md", "- **#5:** x.\n")
        self.frag("notes.md", "- x\n")
        self.assert_refused("only regular files named <issue>.md")

    def test_refuses_an_empty_fragment(self):
        self.frag("5.md", HEADER + "\n")
        self.assert_refused("is empty")

    def test_refuses_when_the_newest_block_is_not_older_than_the_cut(self):
        self.frag("5.md", "- **#5:** x.\n")
        (self.spec / "CHANGELOG.md").write_text(LOG.replace("revision 61 (the last", "revision 62 (the last"), encoding="utf-8")
        code, _, err = self.run_cut()
        self.assertEqual(code, 1)
        self.assertIn("the newest block is revision 62", err)

    def test_refuses_two_status_lines(self):
        self.frag("5.md", "- **#5:** x.\n")
        (self.spec / "revokt-spec.md").write_text(CORE + CORE, encoding="utf-8")
        code, _, err = self.run_cut()
        self.assertEqual(code, 1)
        self.assertIn("expected one status line, found 2", err)

    def test_refuses_a_bad_date_or_summary(self):
        self.frag("5.md", "- **#5:** x.\n")
        self.assert_refused("spec_cut:", "--date", "2026-13-01")
        code, _, err = self.run_cut("--summary", " ")
        self.assertEqual(code, 1)
        self.assertIn("--summary must be one non-empty line", err)


if __name__ == "__main__":
    unittest.main()
