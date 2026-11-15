# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""Tests for fuzz_advisory.py (#115): the artifact checks against hostile input, and filing against a local stub API.

Run: python3 -I -m unittest discover -s .github/scripts -p 'test_*.py' (ci.yml static). Standard library only; the
stub API listens on 127.0.0.1, and nothing goes to GitHub.
"""
import base64
import contextlib
import importlib.util
import io
import json
import os
import shutil
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from unittest import mock

_spec = importlib.util.spec_from_file_location("fuzz_advisory", Path(__file__).with_name("fuzz_advisory.py"))
fa = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(fa)


def armour(payload: bytes = b"ciphertext stand-in") -> bytes:
    """age-shaped armour around arbitrary bytes: BEGIN, base64 in 64-column lines, END."""
    b64 = base64.b64encode(payload)
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return b"\n".join([fa.BEGIN, *lines, fa.END]) + b"\n"


class Case(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def artifact(self, target="Foo.bar", files=None, manifest=None, name=None) -> Path:
        files = {"finding-1.tar.age": armour()} if files is None else files
        d = self.root / (name or f"fuzz-finding-{target}")
        d.mkdir()
        for fname, data in files.items():
            (d / fname).write_bytes(data)
        if manifest is None:
            manifest = {"target": target, "module": "revokt-engine", "hash": "1234abcd5678ef90", "files": sorted(files)}
        (d / "manifest.json").write_bytes(manifest if isinstance(manifest, bytes) else json.dumps(manifest).encode())
        return d

    def rejected(self, d: Path, target="Foo.bar") -> str:
        with self.assertRaises(fa.Rejected) as cm:
            fa.check_artifact(d, target)
        return str(cm.exception)


class GoodArtifact(Case):
    def test_accepted(self):
        f = fa.check_artifact(self.artifact(), "Foo.bar")
        self.assertEqual((f.target, f.module, f.hash), ("Foo.bar", "revokt-engine", "1234abcd5678ef90"))
        self.assertEqual([n for n, _ in f.files], ["finding-1.tar.age"])
        self.assertTrue(f.files[0][1].startswith("-----BEGIN AGE ENCRYPTED FILE-----\n"))

    def test_empty_hash_is_allowed(self):
        m = {"target": "Foo.bar", "module": "revokt-engine", "hash": "", "files": ["finding-1.tar.age"]}
        self.assertEqual(fa.check_artifact(self.artifact(manifest=m), "Foo.bar").hash, "")

    def test_a_long_armour_with_exact_lines(self):
        self.assertTrue(fa.check_armour(armour(os.urandom(5000))))


class HostileManifest(Case):
    def manifest(self, **over):
        m = {"target": "Foo.bar", "module": "revokt-engine", "hash": "1234abcd5678ef90", "files": ["finding-1.tar.age"]}
        m.update(over)
        return m

    def test_bad_values(self):
        for over in [
            {"target": "Foo.bar\n::error::x"},
            {"target": "Foo.bar`"},
            {"target": "Other.target"},
            {"module": "revokt-engine:x"},
            {"module": ""},
            {"module": 5},
            {"hash": "ABCDEF12"},
            {"hash": "1234567"},
            {"hash": "1234abcd5678ef90zz"},
            {"hash": "a" * 65},
            {"hash": None},
            {"files": ["../finding-1.tar.age"]},
            {"files": ["finding-1.tar.age", "finding-1.tar.age"]},
            {"files": []},
            {"files": "finding-1.tar.age"},
            {"files": [f"finding-{i}.tar.age" for i in range(1, 10)]},
            {"files": ["finding-0.tar.age"]},
        ]:
            with self.subTest(over=over):
                self.setUp()
                self.rejected(self.artifact(manifest=self.manifest(**over)))

    def test_extra_or_missing_keys(self):
        extra = self.manifest(note="hi")
        missing = self.manifest()
        del missing["module"]
        for m in (extra, missing, ["not", "an", "object"]):
            with self.subTest(m=m):
                self.setUp()
                self.rejected(self.artifact(manifest=m))

    def test_not_json_and_too_large(self):
        for m in (b"{not json", b"\xff\xfe", json.dumps(self.manifest(module="m" * 5000)).encode()):
            with self.subTest(m=m[:20]):
                self.setUp()
                self.rejected(self.artifact(manifest=m))

    def test_message_quotes_nothing_from_the_artifact(self):
        reason = self.rejected(self.artifact(manifest=self.manifest(target="Foo.bar\n::error::planted")))
        self.assertNotIn("planted", reason)


class Oversized(Case):
    def test_finding_file_above_cap(self):
        big = armour(os.urandom(fa.MAX_FILE))
        self.assertIn("above", self.rejected(self.artifact(files={"finding-1.tar.age": big})))

    def test_total_above_cap(self):
        # Each file is about 0.93 of MAX_FILE, so four fit in MAX_TOTAL and the fifth does not.
        payload = os.urandom(int(fa.MAX_FILE * 0.7))
        for i in range(5):
            self.artifact(target=f"T{i}.x", files={"finding-1.tar.age": armour(payload)})
        accepted, rejected = fa.collect(self.root)
        self.assertEqual([f.target for f in accepted], ["T0.x", "T1.x", "T2.x", "T3.x"])
        self.assertEqual(len(rejected), 1)
        self.assertIn("fuzz-finding-T4.x", rejected[0])
        self.assertIn(f"more than {fa.MAX_TOTAL} bytes", rejected[0])


class BadArmour(Case):
    def test_shapes(self):
        good = armour(os.urandom(200))
        lines = good.split(b"\n")
        for label, data in [
            ("CRLF", good.replace(b"\n", b"\r\n")),
            ("non-base64 character", good.replace(lines[1], lines[1][:-1] + b"*")),
            ("backtick fence breaker", good.replace(lines[1], b"```" + lines[1][3:])),
            ("missing END", b"\n".join(lines[:-2]) + b"\n"),
            ("wrong BEGIN", good.replace(fa.BEGIN, b"-----BEGIN PGP MESSAGE-----")),
            ("short inner line", b"\n".join([lines[0], lines[1][:10], *lines[2:]])),
            ("padding inside", b"\n".join([lines[0], lines[1][:-1] + b"=", *lines[2:]])),
            ("non-ASCII", good.replace(lines[1][:2], "é".encode())),
            ("text after END", good + b"hello\n"),
            ("only the frame", fa.BEGIN + b"\n" + fa.END + b"\n"),
            ("empty", b""),
        ]:
            with self.subTest(label=label):
                with self.assertRaises(fa.Rejected):
                    fa.check_armour(data)


class ArtifactShape(Case):
    def test_extra_file(self):
        d = self.artifact()
        (d / "notes.txt").write_text("x")
        self.rejected(d)

    def test_listed_file_missing(self):
        listed = ["finding-1.tar.age", "finding-2.tar.age"]
        m = {"target": "Foo.bar", "module": "revokt-engine", "hash": "", "files": listed}
        self.rejected(self.artifact(manifest=m))

    def test_symlink_and_subdirectory(self):
        d = self.artifact()
        os.symlink("/etc/passwd", d / "finding-2.tar.age")
        self.rejected(d)
        self.setUp()
        d = self.artifact()
        (d / "sub").mkdir()
        self.rejected(d)

    def test_unexpected_artifact_name_is_not_printed(self):
        (self.root / "planted\n::error::x").mkdir()
        accepted, rejected = fa.collect(self.root)
        self.assertEqual(accepted, [])
        self.assertEqual(len(rejected), 1)
        self.assertNotIn("planted", rejected[0])


class SingleArtifactLayout(Case):
    def test_files_at_the_top_level(self):
        d = self.artifact()
        for f in d.iterdir():
            f.rename(self.root / f.name)
        d.rmdir()
        accepted, rejected = fa.collect(self.root)
        self.assertEqual(([f.target for f in accepted], rejected), (["Foo.bar"], []))

    def test_top_level_files_with_a_directory_are_rejected(self):
        d = self.artifact()
        for f in d.iterdir():
            f.rename(self.root / f.name)
        accepted, rejected = fa.collect(self.root)
        self.assertEqual(accepted, [])
        self.assertEqual(len(rejected), 1)


class TooManyFindings(Case):
    def test_cap_across_artifacts(self):
        files = {f"finding-{i}.tar.age": armour() for i in (1, 2, 3)}
        for t in ("A.a", "B.b", "C.c"):
            self.artifact(target=t, files=dict(files))
        accepted, rejected = fa.collect(self.root)
        self.assertEqual([f.target for f in accepted], ["A.a", "B.b"])
        self.assertEqual(len(rejected), 1)
        self.assertIn("C.c", rejected[0])
        self.assertIn(f"more than {fa.MAX_FINDINGS} findings", rejected[0])


class StubApi(BaseHTTPRequestHandler):
    pages = {}
    posted = []

    def do_GET(self):
        page = 2 if "page=2" in self.path else 1
        body = json.dumps(self.pages.get(page, [])).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        if page == 1 and 2 in self.pages:
            self.send_header("Link", f'<http://127.0.0.1:{self.server.server_port}{self.path}&page=2>; rel="next"')
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        StubApi.posted.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
        self.send_response(201)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b"{}")

    def log_message(self, *args):
        pass


class Filing(Case):
    def setUp(self):
        super().setUp()
        StubApi.pages, StubApi.posted = {}, []
        self.server = HTTPServer(("127.0.0.1", 0), StubApi)
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        self.addCleanup(self.server.server_close)
        self.addCleanup(self.server.shutdown)
        env = {"GH_TOKEN": "t", "REPO": "o/r", "RUN_URL": "https://example.invalid/run/7", "RUN_ID": "7",
               "API_URL": f"http://127.0.0.1:{self.server.server_port}"}
        patcher = mock.patch.dict(os.environ, env)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_main(self) -> tuple[int, str]:
        out = io.StringIO()
        argv = fa.sys.argv
        fa.sys.argv = ["fuzz_advisory.py", str(self.root)]
        try:
            with contextlib.redirect_stdout(out):
                rc = fa.main()
        finally:
            fa.sys.argv = argv
        return rc, out.getvalue()

    def test_files_new_and_skips_known(self):
        self.artifact(target="New.one")
        m = {"target": "Old.one", "module": "revokt-clubcard", "hash": "deadbeef", "files": ["finding-1.tar.age"]}
        self.artifact(target="Old.one", manifest=m)
        StubApi.pages = {1: [{"summary": "something else"}], 2: [{"summary": "fuzz: Old.one deadbeef"}]}
        rc, out = self.run_main()
        self.assertEqual(rc, 0)
        self.assertEqual(len(StubApi.posted), 1)
        body = StubApi.posted[0]
        self.assertEqual(body["summary"], "fuzz: New.one 1234abcd5678ef90")
        self.assertIn("```\n-----BEGIN AGE ENCRYPTED FILE-----\n", body["description"])
        self.assertIn("rage -d -i <identity-file> finding.age > finding.bin", body["description"])
        package = {"ecosystem": "maven", "name": "dev.revokt:revokt-engine"}
        self.assertEqual(body["vulnerabilities"][0]["package"], package)
        self.assertEqual(out.strip(), "filed 1 draft advisories; 1 already filed; 0 artifacts rejected")

    def test_no_hash_is_never_deduplicated(self):
        m = {"target": "Foo.bar", "module": "revokt-engine", "hash": "", "files": ["finding-1.tar.age"]}
        self.artifact(manifest=m)
        StubApi.pages = {1: [{"summary": "fuzz: Foo.bar "}]}
        rc, _ = self.run_main()
        self.assertEqual((rc, StubApi.posted[0]["summary"]), (0, "fuzz: Foo.bar run 7"))

    def test_rejected_artifact_fails_but_others_are_filed(self):
        self.artifact(target="Good.one")
        bad = self.artifact(target="Bad.one")
        (bad / "finding-1.tar.age").write_bytes(b"not armour\n")
        rc, out = self.run_main()
        self.assertEqual(rc, 1)
        self.assertEqual([p["summary"] for p in StubApi.posted], ["fuzz: Good.one 1234abcd5678ef90"])
        self.assertIn("::error::rejected fuzz-finding-Bad.one:", out)
        self.assertNotIn("not armour", out)

    def test_no_artifacts_is_not_a_failure(self):
        shutil.rmtree(self.root)
        rc, out = self.run_main()
        self.assertEqual((rc, StubApi.posted), (0, []))
        self.assertIn("no finding artifacts", out)

    def test_too_large_to_inline_points_to_the_artifact(self):
        payload = os.urandom(60000)
        self.artifact(files={"finding-1.tar.age": armour(payload)})
        self.run_main()
        desc = StubApi.posted[0]["description"]
        self.assertLessEqual(len(desc), fa.MAX_DESCRIPTION)
        self.assertIn("Too large to inline here", desc)


if __name__ == "__main__":
    unittest.main()
