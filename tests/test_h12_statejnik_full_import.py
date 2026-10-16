"""H-12: every original statejnik file is preserved, no silent publication."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from statejnik_integration import provenance, runner


class FullSourceIntegrationTests(unittest.TestCase):
    def test_all_licensed_source_files_match_pinned_manifest(self):
        outcome = provenance.verify()
        self.assertEqual(outcome["status"], "VENDORED_BYTES_MATCH_MANIFEST")
        self.assertEqual(outcome["upstream_commit"],
                         "4de2944a31eaffdba4463cdbea115191cb551300")
        self.assertGreaterEqual(outcome["file_count"], 60)
        self.assertFalse(outcome["resident_agent_allowed"])
        self.assertFalse(outcome["signature_verified"])

    def test_full_workflow_documents_and_publishers_are_present(self):
        root = provenance.ROOT / "skills" / "statejnik"
        self.assertTrue((root / "references" / "process" / "INDEX.md").is_file())
        for stage in ("01-demand", "02-clusters", "03-plan", "04-research",
                      "05-write", "06-review", "07-delivery", "08-feedback"):
            self.assertTrue((root / "references" / "process" / (stage + ".md")).is_file())
        self.assertTrue((root / "references" / "publishers.md").is_file())
        self.assertTrue((root / "templates" / "statejnik.example.yaml").is_file())
        self.assertTrue((root / "templates" / "env.example").is_file())
        self.assertTrue((provenance.ROOT / "LICENSE").is_file())

    def test_every_entrypoint_is_available_but_network_publishing_denied(self):
        self.assertEqual(len(runner.ALL_TOOLS), 12)
        self.assertEqual(len(runner.OFFLINE_TOOLS), 8)
        self.assertEqual(len(runner.SOURCE_TOOLS), 3)
        self.assertEqual(len(runner.PUBLISH_TOOLS), 1)
        for name in runner.ALL_TOOLS:
            self.assertTrue((provenance.ROOT / "skills" / "statejnik" /
                             "scripts" / (name + ".py")).is_file())
        catalog = runner.catalog()
        self.assertEqual(catalog["registered_entrypoints"], 12)
        for flag in ("network_enabled", "paid_providers_enabled",
                     "automatic_publication_enabled", "yfc_write_enabled",
                     "resident_agent_allowed"):
            self.assertFalse(catalog[flag])

    def test_default_cli_never_uses_docker(self):
        with patch("statejnik_integration.runner.subprocess.run") as invocation:
            self.assertEqual(runner.main([]), 0)
        invocation.assert_not_called()

    def test_offline_docker_argv_is_bounded_and_has_no_network_or_secrets(self):
        with tempfile.TemporaryDirectory() as folder:
            runner.initialize_workspace(Path(folder))
            command = runner.docker_command("structure-check", Path(folder), ["--help"])
        for token in ("--network", "none", "--read-only", "--cap-drop", "ALL",
                      "--pull=never", "--user", "65534:65534",
                      "--security-opt", "no-new-privileges",
                      "--memory", "768m", "--pids-limit", "64"):
            self.assertIn(token, command)
        self.assertIn(runner.IMAGE, command)
        self.assertIn("/statejnik/skills/statejnik/scripts/structure-check.py", command)
        for forbidden in ("--privileged", "--env-file", "--publish", "-p", "-v",
                          "--network=host", "HERMES_ALERT_BOT_TOKEN", "WORDSTAT_TOKEN"):
            self.assertNotIn(forbidden, command)

    def test_no_external_network_or_publication_tools_even_when_explicit(self):
        with tempfile.TemporaryDirectory() as folder:
            for name in sorted(runner.SOURCE_TOOLS | runner.PUBLISH_TOOLS):
                with self.subTest(name=name), self.assertRaisesRegex(
                    runner.StatejnikDenied, "tool_requires_separate_permission"
                ):
                    runner.docker_command(name, Path(folder), [])

    def test_invalid_tool_workspace_and_arguments_are_denied(self):
        with tempfile.TemporaryDirectory() as folder:
            for name, workspace, args in (
                ("unknown", Path(folder), []),
                ("status", Path(folder) / "missing", []),
                ("status", provenance.ROOT, []),
                ("status", Path(folder), ["x" * 600]),
                ("status", Path(folder), ["x"] * 33),
                ("status", Path(folder), ["\x00"]),
            ):
                with self.subTest(name=name, args=len(args)), self.assertRaises(
                    runner.StatejnikDenied
                ):
                    runner.docker_command(name, workspace, args)

    def test_workspace_requires_explicit_empty_directory_admission(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            with self.assertRaisesRegex(runner.StatejnikDenied,
                                        "workspace_not_admitted"):
                runner.docker_command("status", root, [])
            runner.initialize_workspace(root)
            self.assertTrue((root / runner.WORKSPACE_MARKER).is_file())
            self.assertIn(runner.IMAGE, runner.docker_command("status", root, []))
            with self.assertRaisesRegex(runner.StatejnikDenied,
                                        "workspace_not_empty"):
                runner.initialize_workspace(root)

    def test_offline_runner_cannot_execute_if_checksum_modified(self):
        with tempfile.TemporaryDirectory() as folder:
            with (
                patch("statejnik_integration.runner.verify",
                      side_effect=provenance.ProvenanceDenied("synthetic_corruption")),
                patch("statejnik_integration.runner.subprocess.run") as docker,
            ):
                with self.assertRaisesRegex(runner.StatejnikDenied,
                                            "offline_admission_denied"):
                    runner.run("status", Path(folder), [])
                docker.assert_not_called()

    def test_operator_execution_does_not_inherit_secrets_and_never_retries(self):
        with tempfile.TemporaryDirectory() as folder:
            runner.initialize_workspace(Path(folder))
            completed = type("Completed", (), {"returncode": 0})()
            with patch("statejnik_integration.runner.subprocess.run",
                       return_value=completed) as docker:
                self.assertEqual(runner.run("status", Path(folder), []), 0)
            self.assertEqual(docker.call_count, 1)
            keyword = docker.call_args.kwargs
            self.assertEqual(keyword["timeout"], 120)
            self.assertFalse(keyword["check"])
            self.assertEqual(set(keyword["env"]), {"PATH"})
            self.assertTrue(keyword["capture_output"])

    def test_manifest_tamper_rejected_without_echoing_content(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / "LICENSE").write_text("synthetic", encoding="utf-8")
            (root / "skills" / "statejnik").mkdir(parents=True)
            (root / "skills" / "statejnik" / "SKILL.md").write_text(
                "synthetic", encoding="utf-8")
            recorded = provenance.metadata(root)
            (root / provenance.MANIFEST.name).write_text(
                json.dumps(recorded), encoding="utf-8")
            self.assertEqual(provenance.verify(root)["status"],
                             "VENDORED_BYTES_MATCH_MANIFEST")
            (root / "LICENSE").write_text("tampered", encoding="utf-8")
            with self.assertRaisesRegex(provenance.ProvenanceDenied,
                                        "vendor_source_mismatch"):
                provenance.verify(root)

    def test_no_credentials_or_live_provider_calls_on_source_import(self):
        with patch("statejnik_integration.runner.subprocess.run") as docker:
            data = runner.catalog()
            self.assertFalse(data["network_enabled"])
            self.assertFalse(data["automatic_publication_enabled"])
            self.assertFalse(data["resident_agent_allowed"])
            docker.assert_not_called()


if __name__ == "__main__":
    unittest.main()
