"""Offline H-15 workspace resolver tests; never access owner's live repositories."""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from scripts import h15_workspace_resolver as subject


class WorkspaceResolverTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.sandbox = Path(self.tmp.name) / "workspace" / "projects"
        self.sandbox.mkdir(parents=True)
        self.registry = subject.load_registry()
        for entry in self.registry["workspaces"]:
            root = self.sandbox / Path(entry["root"]).name
            git = root / ".git"
            git.mkdir(parents=True)
            (git / "HEAD").write_text("ref: refs/heads/" + entry["branch"] + "\n", encoding="utf-8")
            (git / "config").write_text(
                '[core]\nrepositoryformatversion = 0\n'
                '[remote "origin"]\nurl = ' + entry["origin"] + '\n', encoding="utf-8"
            )

    def test_exact_aliases_and_all_four_realistic_git_configs(self):
        cases = {"гермес": "hermes", "YFC": "yfc", "second brain": "second-brain",
                 "Ai-Development-Toolkit": "toolkit"}
        for alias, expected in cases.items():
            with self.subTest(alias=alias):
                result = subject.resolve(alias, self.registry, sandbox=self.sandbox)
                self.assertEqual(result["key"], expected)
                self.assertEqual(result["cloneMetadata"], "VERIFIED")
                self.assertEqual(result["deviceOnline"], "NOT_CHECKED")
                self.assertEqual(result["gitTrackedClean"], "NOT_CHECKED")
                self.assertEqual(result["deviceId"], "h15-win-05be75515428")
                self.assertTrue(result["root"].startswith("/workspace/projects/"))

    def test_alias_is_exact_never_natural_language_arbitrary_path(self):
        for name in ("yfc ../../etc", "/workspace/projects/hermes",
                     "YFC and please read host private", "unknown", ""):
            with self.subTest(name=name), self.assertRaises(subject.WorkspaceRefused):
                subject.resolve(name, self.registry, sandbox=self.sandbox)

    def test_branch_and_origin_mismatch_denied(self):
        spec = subject.find_workspace(self.registry, "yfc")
        git = self.sandbox / "your-fitness-coach" / ".git"
        (git / "HEAD").write_text("ref: refs/heads/main\n", encoding="utf-8")
        with self.assertRaisesRegex(subject.WorkspaceRefused, "WORKSPACE_BRANCH_MISMATCH"):
            subject.verify_clone(spec, sandbox=self.sandbox)
        (git / "HEAD").write_text("ref: refs/heads/master\n", encoding="utf-8")
        (git / "config").write_text('[remote "origin"]\nurl = https://evil.invalid/a.git\n',
                                    encoding="utf-8")
        with self.assertRaisesRegex(subject.WorkspaceRefused, "WORKSPACE_ORIGIN_MISMATCH"):
            subject.verify_clone(spec, sandbox=self.sandbox)

    def test_git_symlink_and_missing_workspace_denied(self):
        spec = subject.find_workspace(self.registry, "toolkit")
        git = self.sandbox / "ai-development-toolkit" / ".git"
        (git / "HEAD").unlink()
        (git / "HEAD").symlink_to(self.sandbox / "hermes" / ".git" / "HEAD")
        with self.assertRaisesRegex(subject.WorkspaceRefused, "UNTRUSTED_WORKSPACE_METADATA"):
            subject.verify_clone(spec, sandbox=self.sandbox)
        (git / "HEAD").unlink()
        with self.assertRaises(subject.WorkspaceRefused):
            subject.verify_clone(spec, sandbox=self.sandbox)

    def test_root_symlink_denied(self):
        spec = subject.find_workspace(self.registry, "hermes")
        root = self.sandbox / "hermes"
        renamed = self.sandbox / "hermes-staging"
        root.rename(renamed)
        root.symlink_to(renamed, target_is_directory=True)
        with self.assertRaisesRegex(subject.WorkspaceRefused, "WORKSPACE_NOT_PLAIN_DIRECTORY"):
            subject.verify_clone(spec, sandbox=self.sandbox)

    def test_registry_duplicate_json_key_denied(self):
        file = Path(self.tmp.name) / "duplicate.json"
        file.write_text('{"schema_version":1,"schema_version":1}', encoding="utf-8")
        with self.assertRaisesRegex(subject.WorkspaceRefused, "DUPLICATE_JSON_KEY"):
            subject.load_registry(file)

    def test_unapproved_host_path_and_duplicate_alias_denied(self):
        file = Path(self.tmp.name) / "registry.json"
        copy = json.loads(json.dumps(self.registry))
        copy["workspaces"][0]["root"] = "/host-private/owner"
        file.write_text(json.dumps(copy), encoding="utf-8")
        with self.assertRaisesRegex(subject.WorkspaceRefused, "REGISTRY_ROOT_OUTSIDE_SANDBOX"):
            subject.load_registry(file)

        copy = json.loads(json.dumps(self.registry))
        copy["workspaces"][1]["aliases"].append("hermes")
        file.write_text(json.dumps(copy), encoding="utf-8")
        with self.assertRaisesRegex(subject.WorkspaceRefused, "REGISTRY_DUPLICATE_ALIAS"):
            subject.load_registry(file)

    def test_other_device_cannot_host_project_clones(self):
        copy = json.loads(json.dumps(self.registry))
        copy["workspaces"][0]["device"] = "yfc-sandbox"
        file = Path(self.tmp.name) / "registry.json"
        file.write_text(json.dumps(copy), encoding="utf-8")
        with self.assertRaisesRegex(subject.WorkspaceRefused, "REGISTRY_UNAPPROVED_DEVICE"):
            subject.load_registry(file)

    def test_invalid_git_config_denied_without_running_git(self):
        spec = subject.find_workspace(self.registry, "hermes")
        (self.sandbox / "hermes" / ".git" / "config").write_text(
            '[remote "origin"]\nurl = https://github.com/MikeMoore1337/hermes.git\n'
            '[remote "origin"]\nurl = https://evil.invalid\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(subject.WorkspaceRefused, "WORKSPACE_GIT_CONFIG_INVALID"):
            subject.verify_clone(spec, sandbox=self.sandbox)


if __name__ == "__main__":
    unittest.main()
