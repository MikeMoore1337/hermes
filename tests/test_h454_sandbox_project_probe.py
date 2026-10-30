"""Read-only sandbox preflight: no network, real credentials or project writes."""
from __future__ import annotations

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

if os.name != "posix":
    raise unittest.SkipTest("Linux sandbox preflight")

from control_center.brc_onboarding import PreviewRejected, preview
from control_center.brc_snapshot import PROJECTS
from scripts import h454_sandbox_project_probe as probe

REMOTE = b"ref: refs/heads/main\tHEAD\n" + b"a" * 40 + b"\tHEAD\n"


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="h454-probe-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "projects"
        self.root.mkdir()
        self.calls = []

    def remote(self, repository):
        self.calls.append(repository)
        return REMOTE

    def test_read_only_preflight_reports_unreserved_snapshot(self):
        result = probe.probe("https://github.com/Example/Project.git", root=self.root, remote=self.remote)
        self.assertEqual(result, {
            "schema": 1, "status": "preflight_ok",
            "repository": "https://github.com/Example/project.git",
            "root": "/workspace/projects/project", "branch": "main", "head": "a" * 40,
            "filesystem": "absent_at_check", "remote": "public_head_verified",
            "reservation": False, "can_connect": False,
        })
        self.assertEqual(self.calls, ["https://github.com/Example/project.git"])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_url_policy_matches_existing_preview(self):
        self.assertEqual(probe.RESERVED, frozenset(PROJECTS))
        for url in ("https://github.com/example/project", "https://github.com/Example/Project.git/"):
            self.assertEqual(probe.parse_url(url)[1], preview(url)["repository"])
        for url in ("https://github.com/example/project?token=secret",
                    "https://name:secret@github.com/example/project",
                    "https://github.com/example/../hermes", "https://evil.invalid/example/project",
                    "https://github.com/example/project_with_underscore"):
            with self.subTest(url=url):
                with self.assertRaises(PreviewRejected):
                    preview(url)
                with self.assertRaises(probe.ProbeRejected):
                    probe.parse_url(url)

    def test_reserved_existing_case_variant_and_symlink_never_call_git(self):
        with self.assertRaisesRegex(probe.ProbeRejected, "name_reserved"):
            probe.probe("https://github.com/example/hermes", root=self.root, remote=self.remote)
        with self.assertRaisesRegex(probe.ProbeRejected, "name_reserved"):
            probe.probe("https://github.com/example/com1", root=self.root, remote=self.remote)
        (self.root / "PrOjEcT").mkdir()
        with self.assertRaisesRegex(probe.ProbeRejected, "name_conflict"):
            probe.probe("https://github.com/example/project", root=self.root, remote=self.remote)
        (self.root / "PrOjEcT").rmdir()
        (self.root / "project").symlink_to("/nonexistent")
        with self.assertRaisesRegex(probe.ProbeRejected, "name_conflict"):
            probe.probe("https://github.com/example/project", root=self.root, remote=self.remote)
        self.assertEqual(self.calls, [])

    def test_root_symlink_and_excessive_directory_entries_fail_closed(self):
        link = Path(self.temp.name) / "linked"
        link.symlink_to(self.root, target_is_directory=True)
        with self.assertRaises(probe.ProbeRejected):
            probe.probe("https://github.com/example/project", root=link, remote=self.remote)
        for i in range(probe.MAX_ENTRIES + 1):
            (self.root / ("fixture-%03d" % i)).touch()
        with self.assertRaisesRegex(probe.ProbeRejected, "workspace_too_many_entries"):
            probe.probe("https://github.com/example/project", root=self.root, remote=self.remote)
        self.assertEqual(self.calls, [])

    def test_conflict_or_root_swap_during_remote_check_is_refused(self):
        def create_target(_):
            (self.root / "project").mkdir()
            return REMOTE
        with self.assertRaisesRegex(probe.ProbeRejected, "name_conflict"):
            probe.probe("https://github.com/example/project", root=self.root, remote=create_target)
        (self.root / "project").rmdir()

        def replace_root(_):
            self.root.rename(self.root.with_name("old-projects"))
            self.root.mkdir()
            return REMOTE
        with self.assertRaisesRegex(probe.ProbeRejected, "workspace_changed"):
            probe.probe("https://github.com/example/project", root=self.root, remote=replace_root)

    def test_remote_parser_rejects_ambiguous_or_unsafe_heads(self):
        for raw in (b"", b"x" * (probe.MAX_OUTPUT + 1),
                    b"ref: refs/tags/main\tHEAD\n" + b"a"*40 + b"\tHEAD\n",
                    b"ref: refs/heads/main..bad\tHEAD\n" + b"a"*40 + b"\tHEAD\n",
                    b"ref: refs/heads/main.lock\tHEAD\n" + b"a"*40 + b"\tHEAD\n",
                    b"ref: refs/heads/main\tHEAD\n" + b"z"*40 + b"\tHEAD\n",
                    REMOTE + b"extra\n", b"\xff"):
            with self.subTest(raw=raw[:40]), self.assertRaises(probe.ProbeRejected):
                probe.parse_remote(raw)

    def test_git_runner_has_clean_environment_and_bounded_output(self):
        actual_popen = subprocess.Popen
        seen = {}
        def fake_git(_args, **kwargs):
            seen.update(kwargs)
            return actual_popen([sys.executable, "-c", "import sys; sys.stdout.write('x'*20000)"], **kwargs)
        with patch.object(probe.subprocess, "Popen", side_effect=fake_git):
            with self.assertRaisesRegex(probe.ProbeRejected, "remote_unavailable"):
                probe.git_remote("https://github.com/example/project.git")
        self.assertEqual(seen["env"]["GIT_ALLOW_PROTOCOL"], "https")
        self.assertEqual(seen["env"]["GIT_TERMINAL_PROMPT"], "0")
        self.assertEqual(seen["env"]["GIT_CONFIG_GLOBAL"], "/dev/null")
        self.assertNotIn("GITHUB_TOKEN", seen["env"])
        self.assertTrue(seen["start_new_session"])

    def test_timed_out_git_process_is_reaped(self):
        actual_popen = subprocess.Popen
        children = []
        def fake_git(_args, **kwargs):
            child = actual_popen([sys.executable, "-c", "import time; time.sleep(60)"], **kwargs)
            children.append(child)
            return child
        with patch.object(probe, "TIMEOUT_SECONDS", 0.2), patch.object(probe.subprocess, "Popen", side_effect=fake_git):
            with self.assertRaisesRegex(probe.ProbeRejected, "remote_unavailable"):
                probe.git_remote("https://github.com/example/project.git")
        self.assertIsNotNone(children[0].returncode)

    def test_nonzero_exit_does_not_signal_reaped_process_group(self):
        actual_popen = subprocess.Popen
        def fake_git(_args, **kwargs):
            return actual_popen([sys.executable, "-c", "raise SystemExit(1)"], **kwargs)
        with patch.object(probe.subprocess, "Popen", side_effect=fake_git), patch.object(probe.os, "killpg") as killpg:
            with self.assertRaisesRegex(probe.ProbeRejected, "remote_unavailable"):
                probe.git_remote("https://github.com/example/project.git")
        killpg.assert_not_called()

    def test_duplicate_json_keys_are_refused_without_reflection(self):
        with self.assertRaisesRegex(probe.ProbeRejected, "invalid_request"):
            json.loads('{"repository_url":"one","repository_url":"two"}', object_pairs_hook=probe._unique_pairs)


if __name__ == "__main__":
    unittest.main()
