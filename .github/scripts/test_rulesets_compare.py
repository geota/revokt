# SPDX-FileCopyrightText: 2026 revokt contributors
# SPDX-License-Identifier: Apache-2.0
"""Tests of rulesets_compare.sh's exclusion rule (#241), run by ci.yml's static job with the other test_*.py.

Only the allow-listed members that need an admin read (a ruleset's bypass_actors, seven merge settings) are ever left
out, and only when they come back absent or null without the admin token; anything else absent or null, a removed
protection included, is a difference, and so is an allow-listed member that is unreadable with the token. Python 3.10 or later, standard library only, with bash and jq on the PATH.
"""
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

SCRIPT = Path(__file__).with_name("rulesets_compare.sh")

RULESET = {"id": 1, "name": "main", "enforcement": "active", "bypass_actors": [], "rules": [{"type": "deletion"}]}
REPOSITORY = {"allow_squash_merge": True, "allow_merge_commit": False, "has_issues": True, "web_commit_signoff_required": False}


class RulesetsCompareTest(unittest.TestCase):
    def run_compare(self, committed: dict, live: dict, admin: bool = False) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for side, files in (("committed", committed), ("live", live)):
                (root / side).mkdir()
                for name, value in files.items():
                    (root / side / name).write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
            news = root / "news.md"
            done = subprocess.run(
                ["bash", str(SCRIPT), str(root / "committed"), str(root / "live"), str(news)],
                capture_output=True, text=True, check=False,
                env=dict(os.environ, ADMIN="true" if admin else "false"),
            )
            return done.returncode, done.stdout, news.read_text() if news.exists() else ""

    def files(self, ruleset=None, repository=None) -> dict:
        return {"ruleset-1.json": ruleset or RULESET, "repository.json": repository or REPOSITORY}

    def test_equal_files_report_no_change(self):
        code, out, news = self.run_compare(self.files(), self.files())
        self.assertEqual(code, 0)
        self.assertIn("no change", out)
        self.assertEqual(news, "")

    def test_a_readable_bypass_list_that_changed_is_a_difference(self):
        live = dict(RULESET, bypass_actors=[{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}])
        code, _, news = self.run_compare(self.files(), self.files(ruleset=live))
        self.assertEqual(code, 0)
        self.assertIn("actor_id", news)
        self.assertNotIn("Not compared", news)

    def test_a_bypass_list_the_token_cannot_read_is_left_out_and_named(self):
        live = {k: v for k, v in RULESET.items() if k != "bypass_actors"}
        code, out, news = self.run_compare(self.files(), self.files(ruleset=live))
        self.assertEqual(code, 0)
        self.assertIn("no change", out)
        self.assertIn("::warning::", out)
        self.assertIn("bypass_actors", out)
        self.assertEqual(news, "")

    def test_an_unreadable_member_does_not_hide_a_readable_change(self):
        live = {k: v for k, v in RULESET.items() if k != "bypass_actors"}
        live["enforcement"] = "disabled"
        code, _, news = self.run_compare(self.files(), self.files(ruleset=live))
        self.assertEqual(code, 0)
        self.assertIn("disabled", news)
        self.assertIn("Not compared", news)
        self.assertIn("bypass_actors", news)

    def test_null_merge_settings_are_left_out_and_readable_ones_compared(self):
        live = {"allow_squash_merge": None, "allow_merge_commit": None, "has_issues": False, "web_commit_signoff_required": False}
        code, out, news = self.run_compare(self.files(), self.files(repository=live))
        self.assertEqual(code, 0)
        self.assertIn("has_issues", news)
        self.assertIn("allow_squash_merge", out)
        self.assertIn("::warning::", out)
        self.assertNotIn('"allow_squash_merge": true', news.split("```diff")[1])

    def test_a_removed_rule_is_reported(self):
        live = dict(RULESET, rules=[])
        code, _, news = self.run_compare(self.files(), self.files(ruleset=live))
        self.assertEqual(code, 0)
        self.assertIn("deletion", news)

    def test_a_removed_member_outside_the_allow_list_is_reported(self):
        live = {k: v for k, v in RULESET.items() if k != "rules"}
        code, _, news = self.run_compare(self.files(), self.files(ruleset=live))
        self.assertEqual(code, 0)
        self.assertIn('"rules"', news)
        self.assertNotIn("Not compared", news)

    def test_a_null_member_outside_the_allow_list_is_reported(self):
        live = dict(REPOSITORY, has_issues=None, web_commit_signoff_required=None)
        code, _, news = self.run_compare(self.files(), self.files(repository=live))
        self.assertEqual(code, 0)
        self.assertIn("has_issues", news)
        self.assertIn("web_commit_signoff_required", news)

    def test_with_the_admin_token_an_unreadable_allow_listed_member_is_a_difference(self):
        live = {k: v for k, v in RULESET.items() if k != "bypass_actors"}
        code, out, news = self.run_compare(self.files(), self.files(ruleset=live), admin=True)
        self.assertEqual(code, 0)
        self.assertNotIn("no change", out)
        self.assertIn("Unreadable although RULESETS_AUDIT_TOKEN was set", news)
        self.assertIn("bypass_actors", news.split("```diff")[1])

    def test_with_the_admin_token_null_merge_settings_are_a_difference(self):
        live = dict(REPOSITORY, allow_squash_merge=None)
        code, _, news = self.run_compare(self.files(), self.files(repository=live), admin=True)
        self.assertEqual(code, 0)
        self.assertIn("allow_squash_merge", news.split("```diff")[1])

    def test_a_ruleset_missing_from_the_live_export_is_a_difference(self):
        live = {"repository.json": REPOSITORY}
        code, _, news = self.run_compare(self.files(), live)
        self.assertEqual(code, 0)
        self.assertIn("ruleset-1.json", news)

    def test_a_malformed_live_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "committed").mkdir()
            (root / "live").mkdir()
            (root / "committed" / "repository.json").write_text(json.dumps(REPOSITORY))
            (root / "live" / "repository.json").write_text("{not json")
            done = subprocess.run(
                ["bash", str(SCRIPT), str(root / "committed"), str(root / "live"), str(root / "news.md")],
                capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(done.returncode, 0)


if __name__ == "__main__":
    unittest.main()
