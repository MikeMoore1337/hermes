"""Read-only sandbox preflight: no network, real credentials or project writes."""
from __future__ import annotations

import json
import io
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

if os.name != "posix":
    raise unittest.SkipTest("Linux sandbox preflight")

from control_center.brc_onboarding import PreviewRejected, WINDOWS_DEVICES, preview
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

    def existing(self, *, origin="https://github.com/Example/Project.git", branch="main"):
        project = self.root / "project"
        git = project / ".git"
        ref = git / "refs" / "heads" / branch
        ref.parent.mkdir(parents=True)
        ref.write_text("b" * 40 + "\n", encoding="ascii")
        (git / "HEAD").write_text("ref: refs/heads/" + branch + "\n", encoding="ascii")
        (git / "config").write_text('[remote "origin"]\n\turl = ' + origin + '\n', encoding="ascii")
        (project / "existing.txt").write_text("owner data", encoding="ascii")
        return project, git, ref

    def inspect(self, remote=None):
        return probe.inspect_existing("https://github.com/Example/Project", root=self.root,
                                      remote=remote or self.remote)

    def test_existing_repository_is_read_without_changing_its_files(self):
        project, _, _ = self.existing(origin="https://github.com/example/project", branch="feature/change")
        before = {p.relative_to(project): p.read_bytes() for p in project.rglob("*") if p.is_file()}
        result = self.inspect()
        after = {p.relative_to(project): p.read_bytes() for p in project.rglob("*") if p.is_file()}
        self.assertEqual(before, after)
        self.assertEqual((result["branch"], result["head"]), ("feature/change", "b" * 40))
        self.assertEqual((result["remote_branch"], result["remote_head"]), ("main", "a" * 40))
        self.assertEqual((result["filesystem"], result["can_connect"]), ("existing_not_modified", False))
        self.assertEqual(self.calls, ["https://github.com/Example/project.git"])

    def test_existing_repository_refuses_wrong_multiple_or_indirect_origins(self):
        _, git, _ = self.existing()
        config = git / "config"
        for text in (
            '[remote "origin"]\nurl=https://github.com/other/project\n',
            '[remote "origin"]\nurl=https://github.com/example/project\nurl=https://github.com/other/project\n',
            '[include]\npath=/nonexistent/private\n',
            '[remote "origin"]\nurl=https://user:secret@github.com/example/project\n',
        ):
            config.write_text(text, encoding="ascii")
            with self.subTest(text=text.splitlines()[0]), self.assertRaises(probe.ProbeRejected) as error:
                self.inspect()
            self.assertNotIn("secret", str(error.exception))
        self.assertEqual(self.calls, [])

    def test_existing_repository_refuses_symlink_and_hardlink_metadata(self):
        _, git, ref = self.existing()
        config = git / "config"
        data = config.read_bytes()
        config.unlink()
        config.symlink_to(Path(self.temp.name) / "outside")
        with self.assertRaises(probe.ProbeRejected):
            self.inspect()
        config.unlink()
        outside = Path(self.temp.name) / "outside"
        outside.write_bytes(data)
        os.link(outside, config)
        with self.assertRaises(probe.ProbeRejected):
            self.inspect()
        config.unlink()
        config.write_bytes(data)
        ref.unlink()
        ref.symlink_to(outside)
        with self.assertRaises(probe.ProbeRejected):
            self.inspect()
        self.assertEqual(self.calls, [])

    def test_existing_repository_refuses_fifo_metadata_without_waiting_for_writer(self):
        _, git, _ = self.existing()
        config = git / "config"
        config.unlink()
        os.mkfifo(config)
        with self.assertRaises(probe.ProbeRejected):
            self.inspect()
        self.assertEqual(self.calls, [])

    def test_existing_repository_detects_metadata_and_ref_directory_swaps(self):
        _, git, ref = self.existing(branch="feature/topic")
        def change_config(_):
            (git / "config").write_text('[remote "origin"]\nurl=https://github.com/other/project\n')
            return REMOTE
        with self.assertRaisesRegex(probe.ProbeRejected, "repository_changed"):
            self.inspect(change_config)
        (git / "config").write_text('[remote "origin"]\nurl=https://github.com/Example/Project.git\n')
        def swap_ref_directory(_):
            folder = ref.parent
            folder.rename(folder.with_name("old-feature"))
            folder.mkdir()
            (folder / ref.name).write_text("b" * 40 + "\n")
            return REMOTE
        with self.assertRaises(probe.ProbeRejected):
            self.inspect(swap_ref_directory)

    def test_packed_reference_must_be_unique_and_not_shadowed(self):
        _, git, ref = self.existing()
        ref.unlink()
        packed = git / "packed-refs"
        packed.write_text("# pack-refs\n" + "b" * 40 + " refs/heads/main\n", encoding="ascii")
        self.assertEqual(self.inspect()["head"], "b" * 40)
        packed.write_text(("b" * 40 + " refs/heads/main\n") * 2, encoding="ascii")
        with self.assertRaisesRegex(probe.ProbeRejected, "repository_head_unavailable"):
            self.inspect()
        packed.write_text("b" * 40 + " refs/heads/main\n", encoding="ascii")
        def shadow_packed(_):
            ref.write_text("c" * 40 + "\n", encoding="ascii")
            return REMOTE
        with self.assertRaisesRegex(probe.ProbeRejected, "repository_changed"):
            self.inspect(shadow_packed)

    def test_existing_repository_rejects_unsafe_local_branch(self):
        _, git, _ = self.existing()
        for ref in ("ref: refs/heads/feature./unsafe\n", "ref: refs/heads/main.lock\n",
                    "ref: refs/heads/../private\n", "a" * 40 + "\n"):
            (git / "HEAD").write_text(ref, encoding="ascii")
            with self.subTest(ref=ref), self.assertRaises(probe.ProbeRejected):
                self.inspect()
        self.assertEqual(self.calls, [])

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
        self.assertEqual(probe.WINDOWS_DEVICES, WINDOWS_DEVICES)
        for url in ("https://github.com/example/project", "https://github.com/Example/Project.git/",
                    "https://github.com/Example/v2_engine.test.git", "https://github.com/example/p"):
            self.assertEqual(probe.parse_url(url)[1], preview(url)["repository"])
        for url in ("https://github.com/example/project?token=secret",
                    "https://name:secret@github.com/example/project",
                    "https://github.com/example/../hermes", "https://evil.invalid/example/project",
                    "https://github.com/example/project..name", "https://github.com/example/project."):
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
        with self.assertRaisesRegex(probe.ProbeRejected, "name_reserved"):
            probe.probe("https://github.com/example/CoM1.txt", root=self.root, remote=self.remote)
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
                    b"ref: refs/heads/-invalid\tHEAD\n" + b"a"*40 + b"\tHEAD\n",
                    b"ref: refs/heads/main..bad\tHEAD\n" + b"a"*40 + b"\tHEAD\n",
                    b"ref: refs/heads/main.lock\tHEAD\n" + b"a"*40 + b"\tHEAD\n",
                    b"ref: refs/heads/main\tHEAD\n" + b"z"*40 + b"\tHEAD\n",
                    REMOTE + b"extra\n", b"\xff"):
            with self.subTest(raw=raw[:40]), self.assertRaises(probe.ProbeRejected):
                probe.parse_remote(raw)

    def test_preflight_accepts_underscore_prefixed_default_branch(self):
        remote = b"ref: refs/heads/_integration/2026\tHEAD\n" + b"a" * 40 + b"\tHEAD\n"
        result = probe.probe("https://github.com/example/project", root=self.root, remote=lambda _: remote)
        self.assertEqual((result["branch"], result["head"]), ("_integration/2026", "a" * 40))
        self.assertEqual(list(self.root.iterdir()), [])

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

    def test_cli_rejects_extra_arguments_and_malformed_input_before_probe(self):
        requests = ((["unexpected"], b'{"repository_url":"secret"}'),
                    ([], b'{"repository_url":"secret","repository_url":"other"}'),
                    ([], b'{"repository_url":NaN}'),
                    ([], b'x' * (probe.MAX_INPUT + 1)))
        for args, raw in requests:
            with self.subTest(args=args, size=len(raw)):
                stdin = io.TextIOWrapper(io.BytesIO(raw), encoding="utf-8")
                stdout = io.StringIO()
                with patch.object(sys, "argv", ["preflight", *args]), patch.object(sys, "stdin", stdin), \
                     patch.object(sys, "stdout", stdout), patch.object(probe.os, "getuid", return_value=65534), \
                     patch.object(probe.Path, "is_file", return_value=True), \
                     patch.object(probe.os.path, "lexists", return_value=False), patch.object(probe, "probe") as call:
                    self.assertEqual(probe.main(), 2)
                call.assert_not_called()
                self.assertEqual(json.loads(stdout.getvalue()),
                                 {"status": "refused", "reason": "invalid_request", "can_connect": False})

    def test_cli_requires_explicit_existing_inspection_operation(self):
        stdin = io.TextIOWrapper(io.BytesIO(b'{"repository_url":"https://github.com/example/project",'
                                             b'"operation":"inspect_existing"}'), encoding="utf-8")
        stdout = io.StringIO()
        with patch.object(sys, "argv", ["preflight"]), patch.object(sys, "stdin", stdin), \
             patch.object(sys, "stdout", stdout), patch.object(probe.os, "getuid", return_value=65534), \
             patch.object(probe.Path, "is_file", return_value=True), \
             patch.object(probe.os.path, "lexists", return_value=False), \
             patch.object(probe, "inspect_existing", return_value={"can_connect": False}) as inspect, \
             patch.object(probe, "probe") as original:
            self.assertEqual(probe.main(), 0)
        inspect.assert_called_once_with("https://github.com/example/project")
        original.assert_not_called()
        self.assertEqual(json.loads(stdout.getvalue()), {"can_connect": False})


if __name__ == "__main__":
    unittest.main()
