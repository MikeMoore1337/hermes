"""#454: disposable Git contract for parallel H-15 development sessions."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from scripts import h454_task_worktree as module

from scripts.h454_task_worktree import TaskDenied, check_task


def run(*args):
    return subprocess.check_output(
        ["git", *map(str, args)], text=True, stderr=subprocess.DEVNULL
    ).strip()


class TaskWorktreeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="h454-session-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.projects = self.root / "projects"
        self.projects.mkdir()
        self.tasks = self.root / "task-worktrees"
        self.base = self.projects / "hermes"
        self.base.mkdir()
        run("init", "-q", "-b", "main", self.base)
        run("-C", self.base, "config", "user.name", "Fixture")
        run("-C", self.base, "config", "user.email", "fixture@example.invalid")
        run("-C", self.base, "remote", "add", "origin",
            "https://github.com/MikeMoore1337/hermes.git")
        (self.base / "README.md").write_text("fixture\n", encoding="utf-8")
        run("-C", self.base, "add", "README.md")
        run("-C", self.base, "-c", "commit.gpgsign=false", "commit", "-qm", "fixture")
        self.before = run("-C", self.base, "rev-parse", "HEAD")

    def check(self, project="hermes", task="454", slug="sandbox", **kwargs):
        return check_task(project, task, slug, workspace_root=self.projects,
                          task_root=self.tasks, **kwargs)

    def test_prepare_creates_distinct_branch_without_touching_base(self):
        result = self.check(prepare=True)
        self.assertEqual(result["status"], "created")
        self.assertEqual(result["branch"], "work/issue454-sandbox")
        self.assertEqual(result["head"], self.before)
        self.assertEqual(run("-C", self.base, "branch", "--show-current"), "main")
        self.assertEqual(run("-C", self.base, "rev-parse", "HEAD"), self.before)
        self.assertEqual(run("-C", self.base, "status", "--porcelain"), "")
        self.assertEqual(run("-C", result["root"], "branch", "--show-current"),
                         "work/issue454-sandbox")
        self.assertFalse((self.base / "work").exists())

    def test_replay_reuses_identical_worktree_only(self):
        a = self.check(prepare=True)
        (Path(a["root"]) / "scratch.txt").write_text("unfinished\n")
        b = self.check(prepare=True)
        self.assertEqual(b["status"], "reused")
        self.assertEqual(b["root"], a["root"])
        self.assertTrue((Path(a["root"]) / "scratch.txt").exists())
        self.assertEqual(len(run("-C", self.base, "worktree", "list",
                                 "--porcelain").split("worktree "))-1, 2)

    def test_different_task_slug_does_not_reuse_workspace(self):
        x = self.check(prepare=True)
        y = self.check(task="455", slug="different", prepare=True)
        self.assertNotEqual(x["branch"], y["branch"])
        self.assertNotEqual(x["root"], y["root"])
        self.assertEqual(run("-C", self.base, "branch", "--show-current"), "main")

    def test_inspect_is_non_mutating(self):
        self.assertEqual(self.check()["status"], "not_created")
        self.assertFalse(self.tasks.exists())
        self.assertEqual(self.check(prepare=True)["status"], "created")
        self.assertEqual(self.check(prepare=False)["status"], "reused")

    def test_reject_unknown_and_path_injection(self):
        for project, task, slug in [
            ("production", "454", "sandbox"),
            ("../../hermes", "454", "sandbox"),
            ("hermes", "0", "sandbox"),
            ("hermes", "454; touch /tmp/a", "sandbox"),
            ("hermes", "454", "../secrets"),
            ("hermes", "454", "a/b"),
            ("hermes", "454", "bad_slug"),
            ("hermes", "454", "x" * 50),
        ]:
            with self.subTest(project=project, task=task, slug=slug):
                with self.assertRaises(TaskDenied):
                    self.check(project=project, task=task, slug=slug, prepare=True)
        self.assertFalse(self.tasks.exists())

    def test_wrong_origin_or_default_branch_denied(self):
        run("-C", self.base, "remote", "set-url", "origin", "https://example.com/fake")
        with self.assertRaisesRegex(TaskDenied, "origin_mismatch"):
            self.check(prepare=True)
        run("-C", self.base, "remote", "set-url", "origin",
            "https://github.com/MikeMoore1337/hermes.git")
        run("-C", self.base, "checkout", "-q", "-b", "unexpected")
        with self.assertRaisesRegex(TaskDenied, "baseline_branch_mismatch"):
            self.check(prepare=True)

    def test_symlinked_workspace_or_output_refused(self):
        external = self.root / "outside"
        external.mkdir()
        self.tasks.symlink_to(external, target_is_directory=True)
        with self.assertRaisesRegex(TaskDenied, "symlink_path_refused"):
            self.check(prepare=True)
        self.assertEqual(list(external.iterdir()), [])

    def test_untracked_task_path_is_not_adopted(self):
        place = self.tasks / "hermes" / "issue454-sandbox"
        place.mkdir(parents=True)
        (place / "owner-data").write_text("untouched")
        with self.assertRaisesRegex(TaskDenied, "task_path_collision"):
            self.check(prepare=True)
        self.assertEqual((place / "owner-data").read_text(), "untouched")

    def test_sync_requires_explicit_create(self):
        with self.assertRaisesRegex(TaskDenied, "sync_requires_prepare"):
            self.check(sync=True)
        self.assertFalse(self.tasks.exists())

    def test_fetch_failure_preserves_original_and_no_task_checkout(self):
        actual_git = module.git
        def decline_fetch(root, *args, **kwargs):
            if args and args[0] == "fetch":
                raise TaskDenied("git_not_ready")
            return actual_git(root, *args, **kwargs)
        with patch.object(module, "git", side_effect=decline_fetch):
            with self.assertRaisesRegex(TaskDenied, "git_not_ready"):
                self.check(prepare=True, sync=True)
        self.assertEqual(run("-C", self.base, "rev-parse", "HEAD"), self.before)
        self.assertFalse((self.tasks / "hermes" / "issue454-sandbox").exists())

    def test_no_sync_never_fetches(self):
        actual_git = module.git
        seen = []
        def track_git(root, *args, **kwargs):
            seen.append(args[0])
            return actual_git(root, *args, **kwargs)
        with patch.object(module, "git", side_effect=track_git):
            self.assertEqual(self.check(prepare=True)["status"], "created")
        self.assertNotIn("fetch", seen)

    def test_original_checkout_symlink_git_denied(self):
        (self.base / ".git").rename(self.base / ".git-real")
        (self.base / ".git").symlink_to(self.base / ".git-real")
        with self.assertRaisesRegex(TaskDenied, "symlink_path_refused|missing_or_unsafe_checkout"):
            self.check(prepare=True)


if __name__ == "__main__":
    unittest.main()
