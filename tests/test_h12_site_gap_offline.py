"""Offline site-gap admission: no scanning, Wordstat, direct paths or publishing."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from statejnik_integration import offline_gap, runner


SITE = {
    "url": "https://example.org",
    "pages": [
        {"url": "https://example.org/blog/krossovki", "kind": "article",
         "title": "Как выбрать беговые кроссовки", "h1": "Выбор кроссовок"}
    ],
    "article_sections": [{"path": "/blog"}],
    "article_urls": ["https://example.org/blog/krossovki"],
    "urls": [],
}
KEYWORDS = [
    {"phrase": "как выбрать беговые кроссовки",
     "cluster": "беговые кроссовки", "count": 0, "sources": []},
    {"phrase": "бег и обувь для начинающих", "sources": []},
]


class SiteGapOfflineTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name)
        runner.initialize_workspace(self.work)
        self.put("site.json", SITE)
        self.put("keywords.json", KEYWORDS)

    def put(self, filename, data):
        (self.work / filename).write_text(json.dumps(data, ensure_ascii=False),
                                         encoding="utf-8")

    def test_catalog_reports_exact_scope_without_fake_metrics(self):
        self.assertEqual(len(runner.ALL_TOOLS), 12)
        self.assertEqual(runner.HERMES_OFFLINE_TOOLS, frozenset({"site-gap"}))
        c = runner.catalog()
        self.assertEqual(c["registered_entrypoints"], 12)
        self.assertEqual(c["hermes_offline_additions"], ["site-gap"])
        self.assertFalse(c["network_enabled"])
        self.assertFalse(c["verified_wordstat_volume_enabled"])
        g = offline_gap.catalog()
        self.assertFalse(g["measured_search_volumes"])
        self.assertFalse(g["publication_allowed"])

    def test_site_gap_maps_only_to_pinned_offline_vendor_script(self):
        command = runner.docker_command("site-gap", self.work, [])
        self.assertIn("--network", command)
        self.assertIn("none", command)
        self.assertIn("--read-only", command)
        self.assertIn("65534:65534", command)
        self.assertIn("--pull=never", command)
        self.assertIn(runner.IMAGE, command)
        self.assertIn("/statejnik/skills/statejnik/scripts/site.py", command)
        self.assertEqual(command[-9:], ["gap", "site.json", "keywords.json",
                                        "--out", "gap.json", "--plan", "plan.md",
                                        "--top", "25"])
        self.assertNotIn("scan", command)
        self.assertNotIn("WORDSTAT_TOKEN", command)
        self.assertNotIn("--allow-private", command)

    def test_unauthorized_switches_and_original_site_scan_rejected(self):
        for tool, args in (("site", ["scan", "https://example.org"]),
                           ("site-gap", ["scan"]),
                           ("site-gap", ["--config", "/etc/passwd"]),
                           ("site-gap", ["--out", "../../escape.json"]),
                           ("site-gap", ["--allow-private"]),
                           ("site-gap", ["--help"])):
            with self.subTest(tool=tool, args=args), self.assertRaises(
                    runner.StatejnikDenied):
                runner.docker_command(tool, self.work, args)

    def test_only_fixed_input_names_no_output_overwrite(self):
        (self.work / "gap.json").write_text("prior output", encoding="utf-8")
        with self.assertRaisesRegex(runner.StatejnikDenied, "site_gap_input_denied"):
            runner.docker_command("site-gap", self.work, [])
        self.assertEqual((self.work / "gap.json").read_text(), "prior output")

    def test_hidden_config_or_extra_workspace_files_denied(self):
        for filename in ("statejnik.yaml", ".env", "out.txt"):
            extra = self.work / filename
            extra.write_text("synthetic", encoding="utf-8")
            try:
                with self.subTest(filename=filename), self.assertRaisesRegex(
                        runner.StatejnikDenied, "site_gap_input_denied"):
                    runner.docker_command("site-gap", self.work, [])
            finally:
                extra.unlink()

    def test_invalid_data_and_arbitrary_search_volume_are_denied(self):
        examples = (
            ("keywords.json", [{"phrase": "тема", "count": 123}]),
            ("keywords.json", [{"phrase": "тема", "count": True}]),
            ("keywords.json", [{"phrase": "тема", "sources": ["wordstat"]}]),
            ("keywords.json", [{"phrase": "тема\n| malformed"}]),
            ("keywords.json", [{"phrase": "тема", "article_fit": 10}]),
            ("keywords.json", [{"phrase": "тема", "article_fit": float("nan")}]),
            ("keywords.json", []),
            ("site.json", {"pages": "not an array"}),
            ("site.json", {"pages": [{"url": "https://x.org\nmalicious"}]}),
        )
        for name, value in examples:
            with self.subTest(name=name, value=repr(value)[:50]):
                old = (self.work / name).read_bytes()
                try:
                    self.put(name, value)
                    with self.assertRaisesRegex(runner.StatejnikDenied,
                                                "site_gap_input_denied"):
                        runner.docker_command("site-gap", self.work, [])
                finally:
                    (self.work / name).write_bytes(old)

    def test_missing_symlinked_or_large_input_denied(self):
        infile = self.work / "site.json"
        original = infile.read_bytes()
        infile.unlink()
        with self.assertRaises(runner.StatejnikDenied):
            runner.docker_command("site-gap", self.work, [])
        infile.write_bytes(b"x" * (offline_gap.MAX_BYTES + 1))
        with self.assertRaises(runner.StatejnikDenied):
            runner.docker_command("site-gap", self.work, [])
        infile.unlink()
        other = self.work / "other.json"
        other.write_bytes(original)
        try:
            infile.symlink_to(other)
        except (NotImplementedError, OSError):
            self.skipTest("symlinks unavailable on this platform")
        with self.assertRaises(runner.StatejnikDenied):
            runner.docker_command("site-gap", self.work, [])

    def test_run_is_one_bounded_sandbox_no_outbound_or_output_leak(self):
        completed = type("Completed", (), {"returncode": 0})()
        with patch("statejnik_integration.runner.run_bounded",
                   return_value=completed) as execution:
            self.assertEqual(runner.run("site-gap", self.work, []), 0)
        execution.assert_called_once()
        self.assertEqual(execution.call_args.kwargs["timeout"], 120)
        self.assertEqual(execution.call_args.kwargs["stdout_limit"], 65_536)
        self.assertEqual(set(execution.call_args.kwargs["env"]), {"PATH"})

    def test_default_runner_does_not_run_site_gap(self):
        with patch("statejnik_integration.runner.run_bounded") as execution:
            self.assertEqual(runner.main([]), 0)
        execution.assert_not_called()


if __name__ == "__main__":
    unittest.main()
