# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""Tests for cflite_build.py (#119): target checks, the launcher and .options files, and staging the classpath.

Run: python3 -I -m unittest discover -s .github/scripts -p 'test_*.py' (ci.yml static). Standard library only, and
bash on the PATH (each launcher is syntax-checked with bash -n).
"""
import contextlib
import importlib.util
import io
import json
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

_spec = importlib.util.spec_from_file_location("cflite_build", Path(__file__).with_name("cflite_build.py"))
cb = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(cb)


def target(**over) -> dict:
    t = {"name": "FooFuzzTest.read", "project": ":revokt-engine", "module": "revokt-engine",
         "class": "dev.revokt.engine.parse.FooFuzzTest", "method": "read",
         "source": "revokt-engine/src/jvmTest/kotlin/dev/revokt/engine/parse/FooFuzzTest.kt", "maxLen": 4097,
         "timeout": 10}
    t.update(over)
    return t


class Case(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)
        self.repo = self.root / "repo"
        self.out = self.root / "out"
        self.repo.mkdir()
        self.out.mkdir()

    def targets(self, *targets) -> Path:
        path = self.repo / "build/fuzz/targets.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(list(targets)))
        return path

    def module(self, module="revokt-engine", jars=("okio-jvm-3.18.2.jar", "jazzer-junit-0.30.0.jar",
                                                   "jazzer-0.30.0.jar", "jazzer-api-0.30.0.jar")) -> None:
        """A module with test and main class directories, a resources directory that does not exist, and jars."""
        build = self.repo / module / "build"
        test_classes = build / "classes/kotlin/jvm/test/dev/revokt"
        main_classes = build / "classes/kotlin/jvm/main/dev/revokt"
        test_classes.mkdir(parents=True)
        main_classes.mkdir(parents=True)
        (test_classes / "FooFuzzTest.class").write_bytes(b"\xca\xfe\xba\xbe test")
        (main_classes / "Foo.class").write_bytes(b"\xca\xfe\xba\xbe main")
        libs = self.root / "gradle-cache"
        libs.mkdir(exist_ok=True)
        entries = [build / "classes/kotlin/jvm/test", build / "processedResources/jvm/test",
                   build / "classes/kotlin/jvm/main"]
        for jar in jars:
            (libs / jar).write_bytes(jar.encode())
            entries.append(libs / jar)
        listing = build / "cflite/classpath.txt"
        listing.parent.mkdir(parents=True)
        listing.write_text("".join(f"{e}\n" for e in entries))
        kotlin = self.repo / module / "src/commonMain/kotlin/dev/revokt"
        kotlin.mkdir(parents=True)
        (kotlin / "Foo.kt").write_text("package dev.revokt\n")

    def base_image_files(self) -> None:
        """What OSS-Fuzz's compile and build.sh put in $OUT before cflite_build.py runs."""
        (self.out / "jazzer_driver").write_bytes(b"driver")
        (self.out / "jazzer_agent_deploy.jar").write_bytes(b"agent")
        (self.out / "jdk/lib/server").mkdir(parents=True)
        (self.out / "jdk/lib/server/libjvm.so").write_bytes(b"jvm")


class Targets(Case):
    def test_all_and_one(self):
        path = self.targets(target(), target(name="BarFuzzTest.parse", method="parse"))
        self.assertEqual(len(cb.load_targets(path, "all")), 2)
        self.assertEqual(len(cb.load_targets(path, "")), 2)
        self.assertEqual([t["name"] for t in cb.load_targets(path, "BarFuzzTest.parse")], ["BarFuzzTest.parse"])

    def test_unknown_target(self):
        with self.assertRaisesRegex(cb.BuildError, "no fuzz target named Nope.nope"):
            cb.load_targets(self.targets(target()), "Nope.nope")

    def test_no_max_len_is_a_build_error_naming_every_such_target(self):
        path = self.targets(target(maxLen=None), target(name="BarFuzzTest.parse", maxLen=None), target(name="Ok.ok"))
        with self.assertRaises(cb.BuildError) as cm:
            cb.load_targets(path, "all")
        self.assertIn("FooFuzzTest.read", str(cm.exception))
        self.assertIn("BarFuzzTest.parse", str(cm.exception))
        self.assertIn("names no -max_len", str(cm.exception))
        self.assertNotIn("Ok.ok", str(cm.exception))

    def test_a_target_without_max_len_does_not_block_another_built_alone(self):
        path = self.targets(target(maxLen=None), target(name="Ok.ok"))
        self.assertEqual([t["name"] for t in cb.load_targets(path, "Ok.ok")], ["Ok.ok"])

    def test_bad_values(self):
        for over in [{"name": "Foo.read\n::error::x"}, {"name": "Foo-read"}, {"name": "Foo"},
                     {"class": "dev.revokt.$Foo"}, {"module": "../etc"}, {"module": "a b"},
                     {"timeout": 0}, {"timeout": 26}, {"timeout": True}, {"timeout": "10"},
                     {"maxLen": 0}, {"maxLen": "4097"}, {"maxLen": True}]:
            with self.subTest(over=over), self.assertRaises(cb.BuildError):
                cb.load_targets(self.targets(target(**over)), "all")

    def test_empty_or_not_a_list(self):
        with self.assertRaises(cb.BuildError):
            cb.load_targets(self.targets(), "all")
        path = self.repo / "build/fuzz/targets.json"
        path.write_text("{}")
        with self.assertRaises(cb.BuildError):
            cb.load_targets(path, "all")


class Files(Case):
    def test_binary_name(self):
        self.assertEqual(cb.binary_name("X5uPemFuzzTest.read"), "X5uPemFuzzTest-read")
        self.assertRegex(cb.binary_name("A_b.c_d"), r"\A[a-zA-Z0-9_-]+\Z")

    def test_options(self):
        self.assertEqual(cb.options(target(maxLen=262145, timeout=1)),
                         "[libfuzzer]\nmax_len = 262145\ntimeout = 1\nrss_limit_mb = 1024\n")

    def test_launcher(self):
        text = cb.launcher(target(), ["cp/revokt-engine/1", "cp/lib/okio-jvm-3.18.2.jar"])
        self.assertTrue(text.startswith("#!/bin/bash\n"))
        self.assertIn("LLVMFuzzerTestOneInput", text)
        self.assertIn("--target_class=dev.revokt.engine.parse.FooFuzzTest \\", text)
        self.assertIn('--cp="$this_dir/cp/revokt-engine/1:$this_dir/cp/lib/okio-jvm-3.18.2.jar"', text)
        self.assertIn("--jvm_args=-Xmx256m", text)
        self.assertIn("'--instrumentation_includes=dev.revokt.**'", text)
        self.assertIn('"$@"', text)
        script = self.root / "launcher"
        script.write_text(text)
        subprocess.run(["bash", "-n", str(script)], check=True)


class Classpath(Case):
    def test_staged_once_without_jazzer(self):
        self.module()
        jars = {}
        entries = cb.stage_classpath(self.repo, self.out, "revokt-engine", jars)
        self.assertEqual(entries, ["cp/revokt-engine/1", "cp/revokt-engine/2", "cp/lib/okio-jvm-3.18.2.jar"])
        self.assertTrue((self.out / "cp/revokt-engine/1/dev/revokt/FooFuzzTest.class").is_file())
        self.assertTrue((self.out / "cp/revokt-engine/2/dev/revokt/Foo.class").is_file())
        self.assertEqual(sorted(p.name for p in (self.out / "cp/lib").iterdir()), ["okio-jvm-3.18.2.jar"])

    def test_same_jar_from_two_modules_is_one_copy(self):
        self.module()
        self.module("revokt-clubcard", jars=("okio-jvm-3.18.2.jar",))
        jars = {}
        cb.stage_classpath(self.repo, self.out, "revokt-engine", jars)
        self.assertEqual(cb.stage_classpath(self.repo, self.out, "revokt-clubcard", jars)[-1],
                         "cp/lib/okio-jvm-3.18.2.jar")

    def test_two_different_jars_with_one_name(self):
        self.module()
        jars = {}
        cb.stage_classpath(self.repo, self.out, "revokt-engine", jars)
        other = self.root / "elsewhere/okio-jvm-3.18.2.jar"
        other.parent.mkdir()
        other.write_bytes(b"different")
        listing = self.repo / "revokt-clubcard/build/cflite/classpath.txt"
        listing.parent.mkdir(parents=True)
        listing.write_text(f"{other}\n")
        with self.assertRaisesRegex(cb.BuildError, "two different jars named okio-jvm-3.18.2.jar"):
            cb.stage_classpath(self.repo, self.out, "revokt-clubcard", jars)

    def test_odd_jar_name_and_missing_listing(self):
        with self.assertRaisesRegex(cb.BuildError, "cfliteClasspath"):
            cb.stage_classpath(self.repo, self.out, "revokt-engine", {})
        self.module(jars=("we$ird.jar",))
        with self.assertRaisesRegex(cb.BuildError, "jar name"):
            cb.stage_classpath(self.repo, self.out, "revokt-engine", {})


class Build(Case):
    def test_end_to_end(self):
        self.module()
        self.base_image_files()
        self.targets(target())
        inputs = self.repo / "revokt-engine/src/jvmTest/resources/dev/revokt/engine/parse/FooFuzzTestInputs"
        (inputs / "read").mkdir(parents=True)
        (inputs / "empty").write_bytes(b"")
        (inputs / "read/one").write_bytes(b"\x30\x00")
        lines = cb.build(self.repo, self.out, "/src", "all", coverage=True)
        self.assertEqual(lines, ["FooFuzzTest-read: -max_len=4097 -timeout=10, 2 seed inputs"])
        launcher = self.out / "FooFuzzTest-read"
        self.assertTrue(launcher.stat().st_mode & 0o111)
        self.assertIn("LLVMFuzzerTestOneInput", launcher.read_text())
        self.assertIn("max_len = 4097", (self.out / "FooFuzzTest-read.options").read_text())
        with zipfile.ZipFile(self.out / "FooFuzzTest-read_seed_corpus.zip") as z:
            self.assertEqual(sorted(z.namelist()), ["0000", "0001"])
        cov = self.out / "src/revokt/revokt-engine"
        self.assertTrue((cov / "classes/dev/revokt/Foo.class").is_file())
        self.assertFalse((cov / "classes/dev/revokt/FooFuzzTest.class").exists())
        self.assertTrue((cov / "src/commonMain/java/dev/revokt/Foo.kt").is_file())

    def test_no_seeds_writes_no_zip(self):
        self.module()
        self.base_image_files()
        self.targets(target())
        cb.build(self.repo, self.out, "/src", "all", coverage=False)
        self.assertFalse((self.out / "FooFuzzTest-read_seed_corpus.zip").exists())
        self.assertFalse((self.out / "src").exists())

    def test_needs_the_driver_and_jdk(self):
        self.module()
        self.targets(target())
        with self.assertRaisesRegex(cb.BuildError, "jazzer_driver"):
            cb.build(self.repo, self.out, "/src", "all", coverage=False)

    def test_main_reports_a_missing_max_len_and_fails(self):
        self.targets(target(maxLen=None))
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            code = cb.main(["--root", str(self.repo), "--out", str(self.out)])
        self.assertEqual(code, 1)
        self.assertIn("FooFuzzTest.read", err.getvalue())
        self.assertIn("names no -max_len", err.getvalue())
        self.assertEqual(list(self.out.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
