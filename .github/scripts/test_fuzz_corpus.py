# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""Tests for fuzz_corpus.py (#265): staging the corpus repository and checking downloaded corpus artifacts.

Run: python3 -I -m unittest discover -s .github/scripts -p 'test_*.py' (ci.yml static). Standard library only.
"""
import contextlib
import hashlib
import importlib.util
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest import mock

_spec = importlib.util.spec_from_file_location("fuzz_corpus", Path(__file__).with_name("fuzz_corpus.py"))
fc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fc)

TARGETS = {"Foo-bar": 8, "Baz-qux": fc.DEFAULT_MAX_LEN}


def put(d: Path, data: bytes, name: str | None = None) -> str:
    d.mkdir(parents=True, exist_ok=True)
    name = name or hashlib.sha1(data).hexdigest()
    (d / name).write_bytes(data)
    return name


class Case(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.corpus = self.root / "corpus"
        self.out = self.root / "out"
        quiet = contextlib.redirect_stdout(io.StringIO())
        self.stdout = quiet.__enter__()
        self.addCleanup(quiet.__exit__, None, None, None)

    def stage(self, prune: bool = False) -> int:
        staged, _ = fc.stage(self.corpus, self.out, TARGETS, prune)
        return staged

    def staged(self, d: str) -> list[str]:
        return sorted(p.name for p in (self.out / d).iterdir())

    def rejected(self, call) -> str:
        with self.assertRaises(fc.Rejected) as cm:
            call()
        return str(cm.exception)


class Targets(Case):
    def test_names_and_default_max_len(self):
        text = json.dumps([{"name": "Foo.bar", "maxLen": 8}, {"name": "Baz.qux", "maxLen": None}])
        self.assertEqual(fc.targets_from(text), TARGETS)

    def test_bad_targets_rejected(self):
        for text in ["", "{}", "[]", '[{"name": "a/b.c"}]', '[{"name": "Foo.bar", "maxLen": "8"}]',
                     '[{"name": "Foo.bar", "maxLen": 0}]', '[{"name": "Foo.bar", "maxLen": true}]', '[{"name": "Foo"}]']:
            with self.subTest(text=text):
                self.rejected(lambda: fc.targets_from(text))


class Stage(Case):
    def test_copies_each_known_target(self):
        a = put(self.corpus / "Foo-bar", b"one")
        b = put(self.corpus / "Baz-qux", b"two")
        self.assertEqual(self.stage(), 2)
        self.assertEqual(self.staged("Foo-bar"), [a])
        self.assertEqual(self.staged("Baz-qux"), [b])
        self.assertEqual((self.out / "Foo-bar" / a).read_bytes(), b"one")

    def test_no_corpus_dir_stages_nothing(self):
        self.assertEqual(self.stage(), 0)
        self.assertEqual(list(self.out.iterdir()), [])

    def test_unknown_entries_are_ignored(self):
        put(self.corpus / "Gone-target", b"x")
        (self.corpus / "README").write_bytes(b"not a target")
        os.symlink("/etc", self.corpus / "Other-link")
        self.assertEqual(self.stage(), 0)
        self.assertEqual(list(self.out.iterdir()), [])

    def test_unit_over_max_len_left_out(self):
        put(self.corpus / "Foo-bar", b"123456789")
        kept = put(self.corpus / "Foo-bar", b"12345678")
        self.assertEqual(self.stage(), 1)
        self.assertEqual(self.staged("Foo-bar"), [kept])

    def test_target_over_unit_cap_left_out(self):
        put(self.corpus / "Foo-bar", b"a")
        put(self.corpus / "Foo-bar", b"b")
        kept = put(self.corpus / "Baz-qux", b"c")
        with mock.patch.object(fc, "SEED", fc.Caps(1, 1 << 20, 1 << 20)):
            self.assertEqual(fc.stage(self.corpus, self.out, TARGETS), (1, 1))
        self.assertFalse((self.out / "Foo-bar").exists())
        self.assertEqual(self.staged("Baz-qux"), [kept])
        self.assertIn("::warning::Foo-bar", self.stdout.getvalue())

    def test_total_cap_leaves_out_the_rest(self):
        put(self.corpus / "Baz-qux", b"12345")
        put(self.corpus / "Foo-bar", b"12345")
        with mock.patch.object(fc, "SEED", fc.Caps(10, 1 << 20, 7)):
            self.assertEqual(self.stage(), 1)
        self.assertTrue((self.out / "Baz-qux").is_dir())
        self.assertFalse((self.out / "Foo-bar").exists())

    def test_prune_reads_a_target_over_the_seed_caps(self):
        a = put(self.corpus / "Foo-bar", b"a")
        b = put(self.corpus / "Foo-bar", b"b")
        with mock.patch.object(fc, "SEED", fc.Caps(1, 1 << 20, 1 << 20)), \
                mock.patch.object(fc, "PRUNE", fc.Caps(2, 1 << 20, 1 << 20)):
            self.assertEqual(fc.stage(self.corpus, self.out, TARGETS, prune=True), (2, 0))
        self.assertEqual(self.staged("Foo-bar"), sorted([a, b]))

    def test_prune_over_its_caps_is_an_error_and_stages_the_rest(self):
        put(self.corpus / "Foo-bar", b"a")
        put(self.corpus / "Foo-bar", b"b")
        kept = put(self.corpus / "Baz-qux", b"c")
        with mock.patch.object(fc, "PRUNE", fc.Caps(1, 1 << 20, 1 << 20)):
            self.assertEqual(fc.stage(self.corpus, self.out, TARGETS, prune=True), (1, 1))
        self.assertEqual(self.staged("Baz-qux"), [kept])
        self.assertIn("::error::Foo-bar", self.stdout.getvalue())

    def test_target_with_only_oversized_units_gets_no_directory(self):
        put(self.corpus / "Foo-bar", b"123456789")
        self.assertEqual(self.stage(), 0)
        self.assertFalse((self.out / "Foo-bar").exists())

    def test_malformed_rejects_everything(self):
        cases = {
            "symlink unit": lambda d: os.symlink("/etc/passwd", d / ("0" * 40)),
            "subdirectory": lambda d: (d / ("1" * 40)).mkdir(),
            "bad name": lambda d: put(d, b"x", "crash-1"),
            "upper-case name": lambda d: put(d, b"x", hashlib.sha1(b"x").hexdigest().upper()),
            "wrong hash": lambda d: put(d, b"x", "2" * 40),
        }
        for label, make in cases.items():
            with self.subTest(label):
                shutil.rmtree(self.corpus, ignore_errors=True)
                shutil.rmtree(self.out, ignore_errors=True)
                put(self.corpus / "Baz-qux", b"fine")
                put(self.corpus / "Foo-bar", b"fine")
                make(self.corpus / "Foo-bar")
                self.rejected(self.stage)
                self.assertFalse(self.out.exists())

    def test_symlinked_target_dir_rejected(self):
        put(self.root / "elsewhere", b"x")
        self.corpus.mkdir()
        os.symlink(self.root / "elsewhere", self.corpus / "Foo-bar")
        self.rejected(self.stage)

    def test_symlinked_corpus_dir_rejected(self):
        put(self.root / "elsewhere" / "Foo-bar", b"x")
        os.symlink(self.root / "elsewhere", self.corpus)
        self.rejected(self.stage)

    def test_existing_out_dir_rejected(self):
        self.out.mkdir()
        self.rejected(self.stage)


class Check(Case):
    def test_good_artifact(self):
        put(self.out / "Foo-bar", b"one")
        put(self.out / "Baz-qux", b"two")
        self.assertEqual(fc.check(self.out, TARGETS, None), 2)

    def test_malformed_artifacts(self):
        # Baz-qux has the default -max_len, so a link or a directory is caught by the regular-file rule alone.
        target = hashlib.sha1(b"linked").hexdigest()

        def link_unit():
            # A link named by its target's SHA-1, so only the regular-file rule (and O_NOFOLLOW) stands in its way.
            put(self.root / "target", b"linked")
            (self.out / "Baz-qux").mkdir()
            os.symlink(self.root / "target" / target, self.out / "Baz-qux" / target)

        cases = {
            "unknown target": lambda: put(self.out / "Gone-target", b"x"),
            "file at the top": lambda: put(self.out, b"x"),
            "link at the top": lambda: os.symlink("/etc", self.out / "Foo-bar"),
            "empty target directory": lambda: (self.out / "Foo-bar").mkdir(),
            "nested directory": lambda: (self.out / "Baz-qux" / hashlib.sha1(b"").hexdigest()).mkdir(parents=True),
            "link unit": link_unit,
            "bad name": lambda: put(self.out / "Foo-bar", b"x", "x" * 40),
            "wrong hash": lambda: put(self.out / "Foo-bar", b"x", "5" * 40),
            "over max_len": lambda: put(self.out / "Foo-bar", b"123456789"),
        }
        for label, make in cases.items():
            with self.subTest(label):
                shutil.rmtree(self.out, ignore_errors=True)
                shutil.rmtree(self.root / "target", ignore_errors=True)
                self.out.mkdir()
                make()
                self.rejected(lambda: fc.check(self.out, TARGETS, None))

    def test_caps(self):
        put(self.out / "Foo-bar", b"a")
        put(self.out / "Foo-bar", b"b")
        with mock.patch.object(fc, "SEED", fc.Caps(1, 1 << 20, 1 << 20)):
            self.rejected(lambda: fc.check(self.out, TARGETS, None))
            self.assertEqual(fc.check(self.out, TARGETS, None, prune=True), 2)
        with mock.patch.object(fc, "SEED", fc.Caps(10, 1 << 20, 1)):
            self.rejected(lambda: fc.check(self.out, TARGETS, None))

    def test_within_accepts_a_subset(self):
        a = put(self.corpus / "Foo-bar", b"a")
        put(self.corpus / "Foo-bar", b"b")
        put(self.out / "Foo-bar", b"a")
        self.assertEqual(fc.check(self.out, TARGETS, self.corpus), 1)
        self.assertEqual(self.staged("Foo-bar"), [a])

    def test_within_rejects_a_new_unit(self):
        put(self.corpus / "Foo-bar", b"a")
        put(self.out / "Foo-bar", b"new")
        self.rejected(lambda: fc.check(self.out, TARGETS, self.corpus))

    def test_within_rejects_a_target_not_read(self):
        put(self.out / "Foo-bar", b"a")
        self.corpus.mkdir()
        self.rejected(lambda: fc.check(self.out, TARGETS, self.corpus))

    def test_within_rejects_a_linked_reference_unit(self):
        name = put(self.root / "elsewhere", b"a")
        (self.corpus / "Foo-bar").mkdir(parents=True)
        os.symlink(self.root / "elsewhere" / name, self.corpus / "Foo-bar" / name)
        put(self.out / "Foo-bar", b"a")
        self.rejected(lambda: fc.check(self.out, TARGETS, self.corpus))

    def test_within_rejects_a_linked_reference_directory(self):
        put(self.root / "elsewhere", b"a")
        self.corpus.mkdir()
        os.symlink(self.root / "elsewhere", self.corpus / "Foo-bar")
        put(self.out / "Foo-bar", b"a")
        self.rejected(lambda: fc.check(self.out, TARGETS, self.corpus))


class Lists(Case):
    """The prune's check of the merged corpora against the merge jobs' unit lists: a partial download is rejected."""

    def setUp(self):
        super().setUp()
        self.lists = self.root / "lists"
        self.lists.mkdir()
        self.a = put(self.out / "Foo-bar", b"a")
        self.b = put(self.out / "Foo-bar", b"b")
        self.c = put(self.out / "Baz-qux", b"c")
        (self.lists / "Foo-bar").write_text(f"{self.a}\n{self.b}\n")
        (self.lists / "Baz-qux").write_text(f"{self.c}\n")

    def test_complete_download_accepted(self):
        self.assertEqual(fc.check(self.out, TARGETS, None, self.lists), 3)

    def test_a_missing_unit_rejected(self):
        (self.out / "Foo-bar" / self.b).unlink()
        self.rejected(lambda: fc.check(self.out, TARGETS, None, self.lists))

    def test_a_missing_target_directory_rejected(self):
        shutil.rmtree(self.out / "Baz-qux")
        self.rejected(lambda: fc.check(self.out, TARGETS, None, self.lists))

    def test_a_directory_without_a_list_rejected(self):
        (self.lists / "Baz-qux").unlink()
        self.rejected(lambda: fc.check(self.out, TARGETS, None, self.lists))

    def test_an_unlisted_unit_rejected(self):
        (self.lists / "Foo-bar").write_text(f"{self.a}\n")
        self.rejected(lambda: fc.check(self.out, TARGETS, None, self.lists))

    def test_malformed_lists_rejected(self):
        cases = {
            "empty": lambda: (self.lists / "Foo-bar").write_text(""),
            "bad line": lambda: (self.lists / "Foo-bar").write_text(f"{self.a}\n../x\n"),
            "unknown target": lambda: (self.lists / "Gone-target").write_text(f"{self.a}\n"),
            "link": lambda: (self.lists / "Foo-bar").unlink() or os.symlink(self.lists / "Baz-qux", self.lists / "Foo-bar"),
        }
        for label, make in cases.items():
            with self.subTest(label):
                (self.lists / "Gone-target").unlink(missing_ok=True)
                if (self.lists / "Foo-bar").is_symlink():
                    (self.lists / "Foo-bar").unlink()
                (self.lists / "Foo-bar").write_text(f"{self.a}\n{self.b}\n")
                make()
                self.rejected(lambda: fc.check(self.out, TARGETS, None, self.lists))


class Main(Case):
    def run_main(self, *argv: str, targets=None) -> int:
        env = {"TARGETS": json.dumps(targets or [{"name": "Foo.bar", "maxLen": 8}])}
        with mock.patch.dict(os.environ, env, clear=True):
            return fc.main(list(argv))

    def test_stage_and_check(self):
        put(self.corpus / "Foo-bar", b"one")
        self.assertEqual(self.run_main("stage", str(self.corpus), str(self.out)), 0)
        self.assertEqual(self.run_main("check", str(self.out)), 0)
        self.assertEqual(self.run_main("check", str(self.out), "--within", str(self.corpus)), 0)

    def test_rejected_is_exit_1_without_names(self):
        put(self.corpus / "Foo-bar", b"x", "6" * 40)
        self.assertEqual(self.run_main("stage", str(self.corpus), str(self.out)), 1)
        self.assertIn("::error::", self.stdout.getvalue())
        self.assertNotIn("6" * 40, self.stdout.getvalue())

    def test_prune_over_caps_is_exit_3(self):
        put(self.corpus / "Foo-bar", b"a")
        put(self.corpus / "Foo-bar", b"b")
        with mock.patch.object(fc, "PRUNE", fc.Caps(1, 1 << 20, 1 << 20)):
            self.assertEqual(self.run_main("stage", "--prune", str(self.corpus), str(self.out)), fc.OVER_CAPS)

    def test_check_with_lists(self):
        name = put(self.out / "Foo-bar", b"a")
        lists = self.root / "lists"
        lists.mkdir()
        (lists / "Foo-bar").write_text(name + "\n")
        self.assertEqual(self.run_main("check", "--prune", str(self.out), "--lists", str(lists)), 0)

    def test_usage(self):
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                self.run_main("check")
            with self.assertRaises(SystemExit):
                self.run_main("check", "a", "--into", "b")


if __name__ == "__main__":
    unittest.main()
