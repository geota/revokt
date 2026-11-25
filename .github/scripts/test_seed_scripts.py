# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""Tests of the seed job's scripts (release-seed.yml): seed_predicate.sh, seed_floor.sh and seed_verify.sh.

The jars are built here with zipfile in the seed jar's layout; `gh` is a fake on PATH that serves canned releases,
assets and verified attestations from a directory, and fails unless called with the signer workflow and source ref the
floor check must pass. SEED_VERIFY is a fake that prints the jar's records.json <ts> unless told otherwise, and
seed_verify.sh runs over a fake gradlew. Nothing reaches the network and no Gradle runs.
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
VERIFY = HERE / "seed_verify.sh"
REPO = "geota/revokt"
SIGNER = f"{REPO}/.github/workflows/release-seed.yml"
PREDICATE_TYPE = "https://github.com/geota/revokt/blob/main/docs/attestation/seed-v1.md"

FAKE_GH = r"""#!/usr/bin/env bash
# A fake gh for test_seed_scripts.py: serves $FAKE_GH_DIR.
set -euo pipefail
d=${FAKE_GH_DIR:?}
case "$1 ${2:-}" in
  "api --paginate")
    [ ! -e "$d/api-fails" ] || { echo "HTTP 502" >&2; exit 1; }
    case $3 in
      *matching-refs*) if [ -f "$d/refs.json" ]; then cat "$d/refs.json"; else echo '[]'; fi ;;
      *) cat "$d/releases.json" ;;
    esac ;;
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
    [ ! -e "$d/unattested/$(basename "$file")" ] || exit 1
    if [[ $args == *" --predicate-type "* ]]; then
      [[ $args == *" --predicate-type $FAKE_PREDICATE_TYPE --format json "* ]] || exit 3
      [ ! -e "$d/seed-attest-fails" ] || exit 1
      cat "$d/verified/$(basename "$file").json"
    fi ;;
  *) echo "fake gh: unexpected $*" >&2; exit 3 ;;
esac
"""

FAKE_VERIFY = r"""#!/usr/bin/env bash
# A fake SEED_VERIFY for test_seed_scripts.py: logs each call to $FAKE_VERIFY_DIR/calls, then fails, prints the
# file $FAKE_VERIFY_DIR/prints, or prints the jar's records.json <ts>.
set -euo pipefail
d=${FAKE_VERIFY_DIR:?}
[ $# -eq 2 ] || exit 3
echo "$1 $(basename "$2")" >>"$d/calls"
[ ! -e "$d/fails" ] || { echo "not verified" >&2; exit 1; }
if [ -f "$d/prints" ]; then cat "$d/prints"; exit 0; fi
tmp=$(mktemp)
trap 'rm -f -- "$tmp"' EXIT
unzip -p "$2" "revokt/seed-$1.zip" >|"$tmp"
unzip -p "$tmp" records.json | jq -r .last_modified
"""

FAKE_GRADLEW = r"""#!/usr/bin/env bash
# A fake gradlew for test_seed_scripts.py: logs its arguments, prints Gradle-like noise, and writes $FAKE_TS (when set)
# to the -Prevokt.seedTimestampOut file; fails when $FAKE_GRADLE_FAILS is set.
set -euo pipefail
printf '%s\n' "$@" >|"${FAKE_GRADLE_LOG:?}"
echo "BUILD SUCCESSFUL in 1s"
[ -z "${FAKE_GRADLE_FAILS:-}" ] || exit 1
for a in "$@"; do
  case $a in -Prevokt.seedTimestampOut=*) out=${a#-Prevokt.seedTimestampOut=} ;; esac
done
[ -z "${FAKE_TS+x}" ] || printf '%b' "$FAKE_TS" >|"$out"
"""


def seed_zip(channel, ts, attachments, header_ts=None, header_channel=None, hash_override=None, extra_records=(),
             size_override=None):
    """A seed archive: seed.json, records.json and attachments/<f> for each (record id, filename, bytes)."""
    records = []
    for rid, name, data in attachments:
        digest = hash_override.get(name) if hash_override else None
        records.append({
            "attachment": {"filename": name, "hash": digest or hashlib.sha256(data).hexdigest(),
                           "size": (size_override or {}).get(name, len(data))},
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

    def run_script(self, *args, env=None, drop=()):
        full = dict(os.environ)
        full.update({k: v for k, v in (env or {}).items() if v is not None})
        for name in drop:
            full.pop(name, None)
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

    def test_refuses_an_attachment_that_is_not_its_signed_size(self):
        jar, _ = self.jar(size_override={"20261017-1-compat.filter": 1})
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
        self.verify = self.tmp / "verify"
        self.verify.mkdir()
        (self.verify / "seed_verify.sh").write_text(FAKE_VERIFY)

    def releases(self, entries):
        (self.gh / "releases.json").write_text(json.dumps(entries))

    def new_jars(self, ts):
        for ch in ("compat", "default"):
            seed_jar(self.new / f"revokt-seed-{ch}-{self.NEW}.jar", ch, seed_zip(ch, ts, default_attachments(ch)))

    def prev_release(self, ts, attested_ts=None, skip=(), version=None, predicates=None, attested=True):
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
            if not attested:
                (self.gh / "unattested").mkdir(exist_ok=True)
                (self.gh / "unattested" / name).write_text("")
            predicate = {"channel": ch, "version": version,
                         "recordsLastModified": attested_ts if attested_ts is not None else ts}
            listed = predicates(ch, version, predicate) if predicates else [predicate]
            (self.gh / "verified" / f"{name}.json").write_text(
                json.dumps([{"verificationResult": {"statement": {"predicate": q}}} for q in listed]))
        return tag

    def floor(self, **overrides):
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
            "SEED_VERIFY": str(self.verify / "seed_verify.sh"),
            "FAKE_VERIFY_DIR": str(self.verify),
        }
        env.update(overrides)
        return self.run_script(FLOOR, self.NEW, self.new, env=env, drop=[k for k, v in overrides.items() if v is None])

    def verified(self):
        calls = self.verify / "calls"
        return calls.read_text().splitlines() if calls.exists() else []

    def published(self):
        return self.output.read_text()

    def test_first_release_has_no_floor(self):
        self.new_jars(2000)
        self.releases([{"tag_name": "v0.2.0", "draft": False}])
        out = self.floor()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn("no earlier seed release or tag", out.stdout)
        self.assertEqual(self.published(), "publish=true\n")
        self.assertEqual(self.verified(), [], "nothing to re-verify without a previous release")

    def test_newer_seed_publishes(self):
        self.new_jars(2000)
        self.releases([{"tag_name": self.prev_release(1000), "draft": False}])
        out = self.floor()
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(self.published(), "publish=true\n")
        self.assertEqual(self.verified(), [f"compat revokt-seed-compat-{self.PREV}.jar",
                                           f"default revokt-seed-default-{self.PREV}.jar"])

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

    def test_an_attestation_for_another_channel_fails(self):
        self.new_jars(2000)
        swap = {"compat": "default", "default": "compat"}
        tag = self.prev_release(1000, predicates=lambda ch, v, p: [dict(p, channel=swap[ch])])
        self.releases([{"tag_name": tag, "draft": False}])
        out = self.floor()
        self.assertEqual(out.returncode, 1)
        self.assertIn("is not for compat 2026.11.23", out.stderr)

    def test_an_older_genuine_jar_renamed_to_a_newer_release_fails(self):
        # A genuine 2026.11.16 attestation under a hand-made seed-2026.11.23 release: the version binding refuses it.
        self.new_jars(2000)
        tag = self.prev_release(1000, predicates=lambda ch, v, p: [dict(p, version="2026.11.16")])
        self.releases([{"tag_name": tag, "draft": False}])
        out = self.floor()
        self.assertEqual(out.returncode, 1)
        self.assertIn("is not for compat 2026.11.23", out.stderr)

    def test_two_attestations_with_different_timestamps_fail(self):
        self.new_jars(2000)
        tag = self.prev_release(1000, predicates=lambda ch, v, p: [p, dict(p, recordsLastModified=1500)])
        self.releases([{"tag_name": tag, "draft": False}])
        out = self.floor()
        self.assertEqual(out.returncode, 1)
        self.assertIn("with one <ts>", out.stderr)

    def test_a_failed_seed_attestation_after_provenance_passes_fails(self):
        self.new_jars(2000)
        self.releases([{"tag_name": self.prev_release(1000), "draft": False}])
        (self.gh / "seed-attest-fails").write_text("")
        out = self.floor()
        self.assertEqual(out.returncode, 1)
        self.assertIn("has no seed-v1 attestation from", out.stderr)

    def test_a_previous_release_whose_content_signature_does_not_verify_fails_closed(self):
        self.new_jars(2000)
        self.releases([{"tag_name": self.prev_release(1000), "draft": False}])
        (self.verify / "fails").write_text("")
        out = self.floor()
        self.assertEqual(out.returncode, 1)
        self.assertIn("revokt-seed-compat-2026.11.23.jar does not verify under Mozilla's pins", out.stderr)
        self.assertEqual(self.published(), "")

    def test_a_verification_that_prints_no_single_timestamp_fails_closed(self):
        for printed in ("", "garbage\n", "1000\n1000\n", "10 00\n", "-1000\n", "12345678901234567\n"):
            with self.subTest(printed=printed):
                self.new_jars(2000)
                self.releases([{"tag_name": self.prev_release(1000), "draft": False}])
                (self.verify / "prints").write_text(printed)
                self.output.write_text("")
                out = self.floor()
                self.assertEqual(out.returncode, 1, out.stderr)
                self.assertIn("printed no single <ts>", out.stderr)
                self.assertEqual(self.published(), "")

    def test_a_verified_timestamp_other_than_the_attested_one_fails(self):
        # The attestation and records.json agree on 1000; the content signature verifies another <ts>.
        self.new_jars(2000)
        self.releases([{"tag_name": self.prev_release(1000), "draft": False}])
        (self.verify / "prints").write_text("1001\n")
        out = self.floor()
        self.assertEqual(out.returncode, 1)
        self.assertIn("verifies at <ts> 1001, its attestation 1000", out.stderr)
        self.assertEqual(self.published(), "")

    def test_an_older_new_seed_fails_on_the_verified_floor(self):
        self.new_jars(999)
        self.releases([{"tag_name": self.prev_release(1000), "draft": False}])
        out = self.floor()
        self.assertEqual(out.returncode, 1)
        self.assertIn("refusing an older seed", out.stderr)
        self.assertEqual(len(self.verified()), 1, "the floor is verified before it is compared")

    def test_no_seed_verify_fails_closed(self):
        for releases in ([], ["prev"]):
            for verify in (None, "", str(self.tmp / "absent.sh")):
                with self.subTest(releases=releases, verify=verify):
                    self.new_jars(2000)
                    self.releases([{"tag_name": self.prev_release(1000), "draft": False}] if releases else [])
                    self.output.write_text("")
                    out = self.floor(SEED_VERIFY=verify)
                    if verify == str(self.tmp / "absent.sh") and not releases:
                        # A path is set; with no previous release there is nothing to verify (the first release).
                        self.assertEqual(out.returncode, 0, out.stderr)
                        continue
                    self.assertNotEqual(out.returncode, 0)
                    self.assertEqual(self.published(), "")
                    if verify is None or verify == "":
                        self.assertIn("SEED_VERIFY", out.stderr)

    def test_a_failing_release_listing_fails(self):
        self.new_jars(2000)
        (self.gh / "api-fails").write_text("")
        out = self.floor()
        self.assertEqual(out.returncode, 1)
        self.assertIn("cannot list the releases", out.stderr)
        self.assertEqual(self.published(), "")

    def test_a_hand_made_higher_dated_prerelease_fails_closed(self):
        self.new_jars(2000)
        genuine = self.prev_release(1000)
        forged = self.prev_release(500, version="2026.11.27", attested=False)
        self.releases([{"tag_name": genuine, "draft": False},
                       {"tag_name": forged, "draft": False, "prerelease": True}])
        out = self.floor()
        self.assertEqual(out.returncode, 1)
        self.assertIn("seed-2026.11.27's revokt-seed-compat-2026.11.27.jar has no provenance", out.stderr)

    def test_seed_tags_without_a_published_seed_release_fail(self):
        self.new_jars(2000)
        self.releases([{"tag_name": "v0.2.0", "draft": False}])
        (self.gh / "refs.json").write_text(json.dumps([{"ref": "refs/tags/seed-2026.11.23"}]))
        out = self.floor()
        self.assertEqual(out.returncode, 1)
        self.assertIn("seed tags exist but no published seed release does", out.stderr)
        self.assertEqual(self.published(), "")

    def test_a_previous_release_not_older_than_the_version_fails(self):
        self.new_jars(2000)
        self.releases([{"tag_name": self.prev_release(1000, version=self.NEW), "draft": False}])
        out = self.floor()
        self.assertEqual(out.returncode, 1)
        self.assertIn("is not older than", out.stderr)


class VerifyTest(Base):
    """seed_verify.sh over a fake gradlew at the root of a copied tree, as $root/gradlew sits beside .github."""

    def setUp(self):
        super().setUp()
        self.tmp = self.tmp.resolve()  # the script's paths are physical (cd && pwd under macOS's /private)
        self.root = self.tmp / "repo"
        (self.root / ".github" / "scripts").mkdir(parents=True)
        self.script = self.root / ".github" / "scripts" / "seed_verify.sh"
        shutil.copy(VERIFY, self.script)
        gradlew = self.root / "gradlew"
        gradlew.write_text(FAKE_GRADLEW)
        gradlew.chmod(0o755)
        self.log = self.tmp / "gradle.log"
        self.jar = self.tmp / "jars" / "revokt-seed-compat-2026.11.23.jar"
        self.jar.parent.mkdir()
        self.jar.write_bytes(b"jar")

    def run_verify(self, *args, ts="1792587631204\n", **env):
        base = {"JAVA_HOME": "/opt/temurin-21", "FAKE_GRADLE_LOG": str(self.log), "FAKE_TS": ts}
        base.update(env)
        return self.run_script(self.script, *args, env=base, drop=[k for k, v in base.items() if v is None])

    def gradle_args(self):
        return self.log.read_text().splitlines()

    def test_runs_the_channel_s_task_on_the_pinned_jdk_and_prints_the_ts_alone(self):
        for channel, task in (("compat", "seedTimestampCompat"), ("default", "seedTimestampDefault")):
            with self.subTest(channel=channel):
                out = self.run_verify(channel, self.jar)
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assertEqual(out.stdout, "1792587631204\n")
                self.assertIn("BUILD SUCCESSFUL", out.stderr)
                args = self.gradle_args()
                self.assertEqual(args[:3], ["-p", str(self.root.resolve()), f":revokt-seed:{task}"])
                self.assertIn(f"-Prevokt.seedJar={self.jar.resolve()}", args)
                self.assertIn("-Porg.gradle.java.installations.auto-detect=false", args)
                self.assertIn("-Porg.gradle.java.installations.paths=/opt/temurin-21", args)
                for flag in ("--no-daemon", "--no-build-cache", "--no-configuration-cache"):
                    self.assertIn(flag, args)

    def test_a_relative_jar_is_passed_as_an_absolute_path(self):
        full = dict(os.environ, JAVA_HOME="/opt/temurin-21", FAKE_GRADLE_LOG=str(self.log), FAKE_TS="5\n")
        out = subprocess.run(["bash", str(self.script), "compat", self.jar.name], capture_output=True, text=True,
                             env=full, cwd=self.jar.parent, check=False)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertIn(f"-Prevokt.seedJar={self.jar.resolve()}", self.gradle_args())

    def test_a_failing_task_fails(self):
        out = self.run_verify("compat", self.jar, FAKE_GRADLE_FAILS="1")
        self.assertEqual(out.returncode, 1)
        self.assertIn("does not verify as a compat seed", out.stderr)
        self.assertEqual(out.stdout, "")

    def test_no_single_ts_fails(self):
        for ts in (None, "", "garbage\n", "1\n2\n", "12345678901234567\n"):
            with self.subTest(ts=ts):
                out = self.run_verify("compat", self.jar, ts=ts)
                self.assertEqual(out.returncode, 1, out.stdout)
                self.assertEqual(out.stdout, "")

    def test_usage_and_missing_inputs_fail(self):
        self.assertEqual(self.run_verify("COMPAT", self.jar).returncode, 2)
        self.assertEqual(self.run_verify("compat").returncode, 2)
        missing = self.run_verify("compat", self.tmp / "absent.jar")
        self.assertEqual(missing.returncode, 1)
        self.assertIn("no file", missing.stderr)
        no_jdk = self.run_verify("compat", self.jar, JAVA_HOME=None)
        self.assertNotEqual(no_jdk.returncode, 0)
        self.assertIn("JAVA_HOME", no_jdk.stderr)
        self.assertFalse(self.log.exists(), "Gradle ran on a refused call")


if __name__ == "__main__":
    unittest.main()
