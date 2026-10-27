"""H-15 #454: offline, fail-closed project routing tests."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import tempfile
import unittest

from scripts.h15_workspace_router import RouteDenied, load_registry, resolve


class WorkspaceRouterTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name) / "projects"
        self.root.mkdir()
        self.registry = load_registry()
        self.path = self.root / "your-fitness-coach"
        self.path.mkdir()
        subprocess.run(["git", "init", "-q", "-b", "master", str(self.path)], check=True)
        subprocess.run(["git", "-C", str(self.path), "config", "user.name", "Fixture"], check=True)
        subprocess.run(["git", "-C", str(self.path), "config", "user.email", "fixture@example.test"], check=True)
        subprocess.run(["git", "-C", str(self.path), "remote", "add", "origin",
                        "https://github.com/MikeMoore1337/your-fitness-coach.git"], check=True)
        (self.path / "README.md").write_text("fixture\n", encoding="utf-8")
        subprocess.run(["git", "-C", str(self.path), "add", "README.md"], check=True)
        subprocess.run(["git", "-C", str(self.path), "-c", "commit.gpgsign=false", "commit", "-qm", "fixture"], check=True)
        self.devices = {"devices": [
            {"name": "H15 Windows permanent sandbox", "deviceId": "h15-win-05be75515428", "online": True, "paused": False},
            {"name": "H15 Hermes VPS sandbox", "deviceId": "h15-hermes-ab005bc0e0ea", "online": True, "paused": False},
        ]}

    def tearDown(self):
        self.tmp.cleanup()

    def route(self, alias="yfc", devices=None):
        return resolve(alias, registry=self.registry, root=self.root, devices=devices)

    def test_alias_and_exact_origin_branch(self):
        for alias in ("yfc", "YFC", "your fitness coach", " your-fitness-coach "):
            r = self.route(alias)
            self.assertEqual(r["workspace"], "your-fitness-coach")
            self.assertEqual(r["branch"], "master")
            self.assertEqual(r["device_status"], "not_checked")
            self.assertIs(r["process_execution_verified"], False)
            self.assertEqual(len(r["head"]), 40)
            self.assertEqual(r["tracked_clean"], "not_checked")

    def test_live_device_resolution_exact_name(self):
        r = self.route(devices=self.devices)
        self.assertEqual(r["device_id"], "h15-win-05be75515428")
        self.assertEqual(r["device_status"], "online")
        self.assertIs(r["process_execution_verified"], False)

    def test_no_guessed_or_unrecognized_aliases(self):
        for alias in ("C:/", "../../secrets", "prod", "YFC Production", "", "yfc\nsecret"):
            with self.subTest(alias=alias), self.assertRaises(RouteDenied):
                self.route(alias)

    def test_wrong_origin_denied(self):
        subprocess.run(["git", "-C", str(self.path), "remote", "set-url", "origin",
                        "https://github.com/OtherOwner/your-fitness-coach.git"], check=True)
        with self.assertRaisesRegex(RouteDenied, "repository_origin_mismatch"):
            self.route()

    def test_wrong_branch_denied(self):
        subprocess.run(["git", "-C", str(self.path), "switch", "-q", "-c", "wrong"], check=True)
        with self.assertRaisesRegex(RouteDenied, "repository_branch_mismatch"):
            self.route()

    def test_missing_workspace_denied(self):
        with self.assertRaisesRegex(RouteDenied, "workspace_missing_or_unsafe"):
            self.route("toolkit")

    def test_symlink_workspace_denied(self):
        other = self.root / "hermes"
        other.symlink_to(self.path, target_is_directory=True)
        with self.assertRaisesRegex(RouteDenied, "workspace_missing_or_unsafe"):
            self.route("hermes")

    def test_symlink_git_denied(self):
        other = self.root / "second-brain"
        other.mkdir()
        (other / ".git").symlink_to(self.path / ".git", target_is_directory=True)
        with self.assertRaisesRegex(RouteDenied, "workspace_missing_or_unsafe"):
            self.route("second-brain")

    def test_offline_paused_and_ambiguous_device_denied(self):
        for mutation in (lambda x: x.update(online=False), lambda x: x.update(paused=True)):
            data = json.loads(json.dumps(self.devices))
            mutation(data["devices"][0])
            with self.assertRaisesRegex(RouteDenied, "device_not_ready"):
                self.route(devices=data)
        data = json.loads(json.dumps(self.devices))
        data["devices"].append(dict(data["devices"][0]))
        with self.assertRaisesRegex(RouteDenied, "missing_or_ambiguous_device"):
            self.route(devices=data)

    def test_invalid_device_identity_and_shape_denied(self):
        data = json.loads(json.dumps(self.devices))
        data["devices"][0]["deviceId"] = "foo; rm /"
        with self.assertRaisesRegex(RouteDenied, "invalid_device_id"):
            self.route(devices=data)
        with self.assertRaisesRegex(RouteDenied, "invalid_device_discovery"):
            self.route(devices={"devices": "not a list"})

    def test_duplicate_alias_registry_denied(self):
        data = json.loads(json.dumps(self.registry))
        data["workspaces"][1]["aliases"].append("hermes")
        file = Path(self.tmp.name) / "bad.json"
        file.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(RouteDenied, "duplicate_registry_alias"):
            load_registry(file)

    def test_modified_registry_scope_denied(self):
        data = json.loads(json.dumps(self.registry))
        data["workspace_root"] = "/host-private"
        file = Path(self.tmp.name) / "bad.json"
        file.write_text(json.dumps(data), encoding="utf-8")
        with self.assertRaisesRegex(RouteDenied, "invalid_registry_scope"):
            load_registry(file)

    def test_read_only_repo_no_changed_files(self):
        before = subprocess.check_output(["git", "-C", str(self.path), "status", "--porcelain"])
        self.route(devices=self.devices)
        after = subprocess.check_output(["git", "-C", str(self.path), "status", "--porcelain"])
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
