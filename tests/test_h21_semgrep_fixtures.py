"""Cheap repo regression gate for the pinned offline Semgrep proof-of-concept.

These tests do not run Semgrep. The 5 real Semgrep rule tests were separately
executed in a pinned, networkless Docker sandbox on 2026-10-16.
"""
from __future__ import annotations

import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1] / "evals" / "semgrep_offline"
CASES = {
    "shell-true": ("hermes-subprocess-shell-true", 3, 2),
    "tls-disable": ("hermes-requests-verify-false", 4, 2),
    "shell-os-system": ("hermes-direct-os-system", 1, 1),
    "jwt-no-verify": ("hermes-jwt-verify-disabled", 1, 1),
    "token-log": ("hermes-environment-secret-logged", 3, 2),
}


class SemgrepFixtureContractTests(unittest.TestCase):
    def test_all_rule_and_fixture_pairs_are_complete(self):
        self.assertEqual({p.stem for p in ROOT.glob("*.yaml")}, set(CASES))
        self.assertEqual({p.stem for p in ROOT.glob("*.py")}, set(CASES))

    def test_rule_ids_and_positive_negative_assertions_align(self):
        for stem, (rule, positive, negative) in CASES.items():
            with self.subTest(stem=stem):
                conf = (ROOT / (stem + ".yaml")).read_text(encoding="utf-8")
                code = (ROOT / (stem + ".py")).read_text(encoding="utf-8")
                self.assertRegex(conf, r"(?m)^\s*- id:\s*" + re.escape(rule) + r"\s*$")
                self.assertEqual(code.count("ruleid: " + rule), positive)
                self.assertEqual(code.count("ok: " + rule), negative)
                self.assertNotIn("nosemgrep", code)

    def test_python_only_rules_require_explicit_local_review(self):
        for stem in CASES:
            with self.subTest(stem=stem):
                conf = (ROOT / (stem + ".yaml")).read_text(encoding="utf-8")
                self.assertRegex(conf, r"(?m)^\s*languages:\s*\[python\]\s*$")
                self.assertRegex(conf, r"(?m)^\s*severity:\s*(WARNING|ERROR)\s*$")
                self.assertLess(len(conf), 2500)
                self.assertNotRegex(conf.lower(),
                                    r"https?://|\bregistry\b|\bauto\b|\binterfile\b")
                for line in conf.splitlines():
                    self.assertFalse(line.lstrip().startswith(
                        ("paths:", "fix:", "metadata:", "options:", "mode:",
                         "pattern-sources:", "pattern-sinks:")))

    def test_synthetic_fixtures_contain_no_tokens_or_network_urls(self):
        for stem in CASES:
            src = (ROOT / (stem + ".py")).read_text(encoding="utf-8")
            self.assertNotIn("ACCESS_TOKEN=", src)
            self.assertNotIn("PRIVATE KEY", src)
            self.assertNotIn("https://", src)
            self.assertNotIn("http://", src)
            self.assertLess(len(src), 2000)

    def test_no_ci_installation_or_real_project_scan_is_required(self):
        doc = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("semgrep test /work", doc)
        self.assertIn("docker", doc.lower())
        self.assertIn("--network none", doc)
        self.assertIn("5/5", doc)


if __name__ == "__main__":
    unittest.main()
