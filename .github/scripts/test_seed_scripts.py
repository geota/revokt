# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""Tests of the seed job's scripts (release-seed.yml): seed_predicate.sh and seed_floor.sh.

The jars are built here with zipfile in the seed jar's layout; `gh` is a fake on PATH that serves canned releases,
assets and verified attestations from a directory, and fails unless called with the signer workflow and source ref the
floor check must pass. Nothing reaches the network.
"""

import hashlib
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PREDICATE = HERE / "seed_predicate.sh"
FLOOR = HERE / "seed_floor.sh"
REPO = "geota/revokt"
SIGNER = f"{REPO}/.github/workflows/release-seed.yml"
PREDICATE_TYPE = "https://github.com/geota/revokt/blob/main/docs/attestation/seed-v1.md"

FAKE_GH = r"""#!/usr/bin/env bash
# A fake gh for test_seed_scripts.py: serves $FAKE_GH_DIR.
set -euo pipefail
d=${FAKE_GH_DIR:?}
case "$1 ${2:-}" in
  "api --paginate")
    cat "$d/releases.json" ;;
  "release download")
    tag=$3; shift 3
    pattern="" out=""
    while [ $# -gt 0 ]; do
      case $1 in --pattern) pattern=$2; shift 2 ;; --dir) out=$2; shift 2 ;; *) shift ;; esac
    done
    [ -f "$d/assets/$tag/$pattern" ] || { echo "no assets match" >&2; exit 1; }
    cp "$d/assets/$tag/$pattern" "$out/" ;;
  "attestation verify")
    file=$3; shift 3
    args=" $* "
    [[ $args == *" --repo $FAKE_REPO "* && $args == *" --signer-workflow $FAKE_SIGNER "* &&
       $args == *" --source-ref refs/heads/main "* && $args == *" --deny-self-hosted-runners "* ]] ||
      { echo "unexpected verify flags: $*" >&2; exit 3; }
    [ ! -e "$d/attest-fails" ] || exit 1
    if [[ $args == *" --predicate-type "* ]]; then
      [[ $args == *" --predicate-type $FAKE_PREDICATE_TYPE --format json "* ]] || exit 3
      cat "$d/verified/$(basename "$file").json"
    fi ;;
  *) echo "fake gh: unexpected $*" >&2; exit 3 ;;
esac
"""


def seed_zip(channel, ts, attachments, header_ts=None, header_channel=None, hash_override=None, extra_records=()):
    """A seed archive: seed.json, records.json and attachments/<f> for each (record id, filename, bytes)."""
    records = []
    for rid, name, data in attachments:
        digest = hash_override.get(name) if hash_override else None
        records.append({
            "attachment": {"filename": name, "hash": digest or hashlib.sha256(data).hexdigest(), "size": len(data)},
            "channel": channel,
            "id": rid,
        })
    records.extend(extra_records)
    header = {
        "seedFormat": 1,
        "channel": (header_channel or channel).upper(),
        "dataset": "CRLITE",
        "filterFormat": "V3",
        "recordsLastModified": header_ts if header_ts is not None else ts,
        "engineFloor": 1,
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(zipfile.ZipInfo("seed.json"), json.dumps(header, separators=(",", ":")))
        z.writestr("records.json", json.dumps({"data": records, "last_modified": str(ts)}, separators=(",", ":")))
        z.writestr("signature", "sig")
        z.writestr("x5u.pem", "pem")
        z.writestr("index.bin", b"\0")
        for _, name, data in attachments:
            z.writestr("attachments/" + name, data)
    return buf.getvalue()


def seed_jar(path, channel, archive):
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as z:
        z.writestr("META-INF/MANIFEST.MF", "Manifest-Version: 1.0\r\n\r\n")
        z.writestr(f"revokt/seed-{channel}.zip", archive)
        z.writestr("META-INF/LICENSE-DATA", "No copyright claimed; contains Mozilla Remote Settings data\n")


def default_attachments(channel):
    return [
        ("id-full", f"20261017-1-{channel}.filter", b"full filter " + channel.encode()),
        ("id-delta", f"20261021-1-{channel}.filter.delta", b"delta " + channel.encode()),
    ]


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_script(self, *args, env=None):
        full = dict(os.environ)
        full.update(env or {})
        return subprocess.run(["bash", *map(str, args)], capture_output=True, text=True, env=full, check=False)


class PredicateTest(Base):
    def jar(self, channel="compat", **kw):
        path = self.tmp / f"revokt-seed-{channel}-2026.11.30.jar"
        archive = seed_zip(channel, 1792587631204, kw.pop("attachments", default_attachments(channel)), **kw)
        seed_jar(path, channel, archive)
        return path, archive

    def predicate(self, jar, channel="compat"):
        env = {"JDK_RUNTIME_VERSION": "21.0.13.1+2-LTS", "JDK_ARCHIVE": "jdk.tar.gz", "JDK_ARCHIVE_SHA256": "ab" * 32,
               "ImageOS": "ubuntu24", "ImageVersion": "20261116.1"}
        return self.run_script(PREDICATE, "predicate", jar, channel, "2026.11.30", env=env)

    def test_predicate_lists_the_placed_records_in_archive_order(self):
        jar, archive = self.jar()
        out = self.predicate(jar)
        self.assertEqual(out.returncode, 0, out.stderr)
        p = json.loads(out.stdout)
        self.assertEqual(p["channel"], "compat")
        self.assertEqual(p["version"], "2026.11.30")
        self.assertEqual(p["seedFormat"], 1)
        self.assertEqual(p["recordsLastModified"], 1792587631204)
        self.assertEqual(p["archive"], {"name": "revokt/seed-compat.zip", "sha256": hashlib.sha256(archive).hexdigest()})
        self.assertEqual([r["id"] for r in p["records"]], ["id-full", "id-delta"])
        data = default_attachments("compat")[0][2]
        self.assertEqual(p["records"][0], {"id": "id-full", "filename": "20261017-1-compat.filter", "size": len(data),
                                           "sha256": hashlib.sha256(data).hexdigest()})
        self.assertEqual(p["jdk"], {"vendor": "Eclipse Adoptium", "runtimeVersion": "21.0.13.1+2-LTS",
                                    "archive": "jdk.tar.gz", "archiveSha256": "ab" * 32})
        self.assertEqual(p["runner"], {"imageOs": "ubuntu24", "imageVersion": "20261116.1"})

    def test_ts_prints_the_signed_timestamp(self):
        jar, _ = self.jar()
        out = self.run_script(PREDICATE, "ts", jar, "compat", "2026.11.30")
        self.assertEqual((out.returncode, out.stdout), (0, "1792587631204\n"), out.stderr)

    def test_refuses_an_attachment_that_is_not_its_signed_hash(self):
        jar, _ = self.jar(hash_override={"20261017-1-compat.filter": "00" * 32})
        out = self.predicate(jar)
        self.assertEqual(out.returncode, 1)
        self.assertIn("is not its signed record's size and SHA-256", out.stderr)

    def test_refuses_a_header_timestamp_other_than_the_signed_one(self):
        jar, _ = self.jar(header_ts=1792587631205)
        out = self.run_script(PREDICATE, "ts", jar, "compat", "2026.11.30")
        self.assertEqual(out.returncode, 1)
        self.assertIn("is not records.json's last_modified", out.stderr)

    def test_refuses_another_channel(self):
        jar, _ = self.jar(header_channel="default")
        out = self.run_script(PREDICATE, "ts", jar, "compat", "2026.11.30")
        self.assertEqual(out.returncode, 1)
        self.assertIn("is not a compat header", out.stderr)
        out = self.run_script(PREDICATE, "ts", jar, "default", "2026.11.30")
        self.assertEqual(out.returncode, 1)
        self.assertIn("holds no revokt/seed-default.zip", out.stderr)

    def test_refuses_an_attachment_no_signed_record_names(self):
        other = {"attachment": {"filename": "a.filter", "hash": hashlib.sha256(b"x").hexdigest(), "size": 1},
                 "id": "id-other"}
        jar, _ = self.jar(attachments=[("id-full", "a.filter", b"x")], extra_records=[other])
        out = self.predicate(jar)
        self.assertEqual(out.returncode, 1)
        self.assertIn("not exactly one signed record names a.filter", out.stderr)

    def test_refuses_an_unexpected_entry_name(self):
        jar, _ = self.jar(attachments=[("id-full", "a[1].filter", b"x")])
        out = self.predicate(jar)
        self.assertEqual(out.returncode, 1)
        self.assertIn("unexpected entry name", out.stderr)

    def test_refuses_an_archive_with_no_attachment(self):
        jar, _ = self.jar(attachments=[])
        out = self.predicate(jar)
        self.assertEqual(out.returncode, 1)
        self.assertIn("places no attachment", out.stderr)

    def test_predicate_needs_the_jdk_facts(self):
        jar, _ = self.jar()
        env = {k: v for k, v in os.environ.items() if not k.startswith("JDK_")}
        out = subprocess.run(["bash", str(PREDICATE), "predicate", str(jar), "compat", "2026.11.30"],
                             capture_output=True, text=True, env=env, check=False)
        self.assertNotEqual(out.returncode, 0)


class FloorTest(Base):
    NEW = "2026.11.30"
    PREV = "2026.11.23"

    def setUp(self):
        super().setUp()
        self.gh = self.tmp / "gh"
        (self.gh / "bin").mkdir(parents=True)
        fake = self.gh / "bin" / "gh"
        fake.write_text(FAKE_GH)
        fake.chmod(0o755)
        self.new = self.tmp / "new"
        self.new.mkdir()
        self.output = self.tmp / "github_output"
        self.output.write_text("")
        self.releases([])

    def releases(self, entries):
        (self.gh / "releases.json").write_text(json.dumps(entries))

    def new_jars(self, ts):
        for ch in ("compat", "default"):
            seed_jar(self.new / f"revokt-seed-{ch}-{self.NEW}.jar", ch, seed_zip(ch, ts, default_attachments(ch)))

    def prev_release(self, ts, attested_ts=None, skip=(), version=None):
        version = version or self.PREV
        tag = f"seed-{version}"
        assets = self.gh / "assets" / tag
        assets.mkdir(parents=True, exist_ok=True)
        (self.gh / "verified").mkdir(exist_ok=True)
        for ch in ("compat", "default"):
            if ch in skip:
                continue
            name = f"revokt-seed-{ch}-{version}.jar"
            seed_jar(assets / name, ch, seed_zip(ch, ts, default_attachments(ch)))
            predicate = {"channel": ch, "version": version,
                         "recordsLastModified": attested_ts if attested_ts is not None else ts}
            (self.gh / "verified" / f"{name}.json").write_text(
                json.dumps([{"verificationResult": {"statement": {"predicate": predicate}}}]))
        return tag

    def floor(self):
        env = {
            "PATH": f"{self.gh / 'bin'}{os.pathsep}{os.environ['PATH']}",
            "FAKE_GH_DIR": str(self.gh),
            "FAKE_REPO": REPO,
            "FAKE_SIGNER": SIGNER,
            "FAKE_PREDICATE_TYPE": PREDICATE_TYPE,
            "GH_TOKEN": "unused",
            "GITHUB_REPOSITORY": REPO,
            "GITHUB_OUTPUT": str(self.output),
            "PREDICATE_TYPE": PREDICATE_TYPE,
            "SIGNER_WORKFLOW": SIGNER,
        }
        return self.run_script(FLOOR, self.NEW, self.new, env=env)

    def published(self):
        return self.output.read_text()

    def test_first_release_has_no_floor(self):
        self.new_jars(2000)
        self.releases([{"tag_name": "v0.2.0", "draft": False}])
        out = self.floor()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("no earlier seed release", out.stdout)
        self.assertEqual(self.published(), "publish=true\n")

    def test_newer_seed_publishes(self):
        self.new_jars(2000)
        self.releases([{"tag_name": self.prev_release(1000), "draft": False}])
        out = self.floor()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(self.published(), "publish=true\n")

    def test_equal_seed_skips_publishing(self):
        self.new_jars(1000)
        self.releases([{"tag_name": self.prev_release(1000), "draft": False}])
        out = self.floor()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("nothing new to publish", out.stdout)
        self.assertEqual(self.published(), "publish=false\n")

    def test_older_seed_fails(self):
        self.new_jars(999)
        self.releases([{"tag_name": self.prev_release(1000), "draft": False}])
        out = self.floor()
        self.assertEqual(out.returncode, 1)
        self.assertIn("refusing an older seed", out.stderr)
        self.assertEqual(self.published(), "")

    def test_the_highest_published_seed_release_is_the_floor(self):
        self.new_jars(1500)
        older = self.prev_release(2000, version="2026.11.16")
        newest = self.prev_release(1000)
        draft = self.prev_release(9000, version="2026.11.29")
        self.releases([{"tag_name": draft, "draft": True}, {"tag_name": "v0.2.0", "draft": False},
                       {"tag_name": newest, "draft": False}, {"tag_name": older, "draft": False},
                       {"tag_name": "seed-latest", "draft": False}])
        out = self.floor()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(self.published(), "publish=true\n")

    def test_a_previous_release_without_a_channel_jar_fails_closed(self):
        self.new_jars(2000)
        self.releases([{"tag_name": self.prev_release(1000, skip=("default",)), "draft": False}])
        out = self.floor()
        self.assertEqual(out.returncode, 1)
        self.assertIn("has no revokt-seed-default-2026.11.23.jar", out.stderr)

    def test_an_unverifiable_previous_release_fails_closed(self):
        self.new_jars(2000)
        self.releases([{"tag_name": self.prev_release(1000), "draft": False}])
        (self.gh / "attest-fails").write_text("")
        out = self.floor()
        self.assertEqual(out.returncode, 1)
        self.assertIn("has no provenance from", out.stderr)

    def test_an_attested_timestamp_other_than_the_jar_s_fails(self):
        self.new_jars(2000)
        self.releases([{"tag_name": self.prev_release(1000, attested_ts=1001), "draft": False}])
        out = self.floor()
        self.assertEqual(out.returncode, 1)
        self.assertIn("holds <ts> 1000, its attestation 1001", out.stderr)

    def test_a_previous_release_not_older_than_the_version_fails(self):
        self.new_jars(2000)
        self.releases([{"tag_name": self.prev_release(1000, version=self.NEW), "draft": False}])
        out = self.floor()
        self.assertEqual(out.returncode, 1)
        self.assertIn("is not older than", out.stderr)


if __name__ == "__main__":
    unittest.main()
