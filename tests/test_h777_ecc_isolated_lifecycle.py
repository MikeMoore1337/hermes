"""H777 managed isolation - fail-closed, no Docker or production in unit tests."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest
from unittest.mock import patch

from scripts import h777_ecc_isolated_lifecycle as managed


class TestManagedPathAndOwnership(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="h777-managed-tests-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.base = self.root / "isolated-base"
        self.base.mkdir(mode=0o700)
        self.base.chmod(0o700)

    def test_base_rejects_shared_home_projects_and_symlink(self):
        for value in (Path.home(), self.root / ".hermes", self.root / "yfc"):
            with self.subTest(value=value):
                if not value.exists() and value != Path.home():
                    value.mkdir()
                with self.assertRaises(ValueError):
                    managed.validate_base(value)
        link = self.root / "linked-base"
        link.symlink_to(self.base, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "Symlink"):
            managed.validate_base(link)

    def test_world_writable_base_rejected(self):
        self.base.chmod(0o777)
        with self.assertRaisesRegex(ValueError, "group/world"):
            managed.validate_base(self.base)

    def test_plan_fails_closed_outside_hermes_and_on_traversal(self):
        valid = {"plan": {"operations": [
            {"destinationPath": "/test-home/.hermes/skills/verification-loop/SKILL.md"}]}}
        self.assertEqual(managed.planned_files(json.dumps(valid)), {
            ".hermes/skills/verification-loop/SKILL.md"})
        for path in ("/tmp/other", "/test-home/.claude/ecc/state.db",
                     "/test-home/.hermes/../other", "/test-home/.hermes"):
            with self.subTest(path=path):
                bad = {"plan": {"operations": [{"destinationPath": path}]}}
                with self.assertRaises(ValueError):
                    managed.planned_files(json.dumps(bad))

    def test_inventory_rejects_symlink_hardlink_and_special_files(self):
        home = self.root / "owned"
        home.mkdir()
        target = home / "data.txt"
        target.write_text("original", encoding="utf-8")
        self.assertEqual(managed.inventory(home)[0]["data.txt"],
                         managed.sha256(b"original"))
        link = home / "link.txt"
        link.symlink_to(target)
        with self.assertRaises(ValueError):
            managed.inventory(home)
        link.unlink()
        linked = home / "hardlink.txt"
        os.link(target, linked)
        with self.assertRaises(ValueError):
            managed.inventory(home)

    def test_non_h777_home_cannot_pass_marker_preflight(self):
        shared = self.base / "unrelated-owner"
        shared.mkdir(mode=0o700)
        with self.assertRaisesRegex(ValueError, "Not an H777"):
            managed._verify_home(shared)

    def test_preflight_requires_unprivileged_linux_user(self):
        if os.geteuid() == 0 or managed.sys.platform != "linux":
            with self.assertRaises(ValueError):
                managed.validate_base(self.base)
        else:
            self.assertEqual(managed.validate_base(self.base), self.base)


class TestManagedLifecycleSynthetic(unittest.TestCase):
    """The real original ECC binary is tested separately by GitHub Actions."""

    def setUp(self):
        if os.geteuid() == 0 or managed.sys.platform != "linux":
            self.skipTest("Linux unprivileged lifecycle; runner uses non-root")
        self.tmp = tempfile.TemporaryDirectory(prefix="h777-managed-test-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.base = self.root / "owned-sandbox"
        self.base.mkdir(mode=0o700)
        self.base.chmod(0o700)
        self.ecc = self.root / "fake-ecc"
        self.ecc.mkdir()
        self.managed_file = ".hermes/skills/verification-loop/SKILL.md"
        self.calls: list[str] = []
        self.fail_once = False
        self.inject_sessions = False

    def fake_native(self, ecc: Path, home: Path, tool: str, *args: str) -> str:
        self.calls.append(tool)
        if tool == "install":
            if "--dry-run" in args:
                return json.dumps({"plan": {"operations": [
                    {"destinationPath": "/test-home/" + self.managed_file}]}})
            skill = home / self.managed_file
            skill.parent.mkdir(parents=True, exist_ok=True)
            skill.write_text("---\nname: verification-loop\n---\n", encoding="utf-8")
            (home / managed.CANONICAL_STATE).write_text(
                '{"test": "synthetic"}', encoding="utf-8")
            db = home / managed.KNOWN_RESIDUAL
            if not db.exists():
                db.parent.mkdir(parents=True, exist_ok=True)
                with sqlite3.connect(db) as connection:
                    connection.execute("CREATE TABLE schema_migrations (version INTEGER)")
                    connection.execute("INSERT INTO schema_migrations VALUES (1)")
                    connection.execute(
                        "CREATE TABLE install_state (target_id TEXT, target_root TEXT)")
                    connection.execute(
                        "INSERT INTO install_state VALUES ('hermes-home', '/test-home/.hermes')")
            return json.dumps({"status": "ok"})
        if tool == "doctor":
            return json.dumps({"summary": {"errorCount": 0}})
        if tool == "uninstall":
            skill = home / self.managed_file
            skill.unlink(missing_ok=True)
            (home / managed.CANONICAL_STATE).unlink(missing_ok=True)
            db = home / managed.KNOWN_RESIDUAL
            with sqlite3.connect(db) as connection:
                connection.execute("DELETE FROM install_state")
                if self.inject_sessions:
                    connection.execute("CREATE TABLE sessions (secret TEXT)")
                    connection.execute("INSERT INTO sessions VALUES ('KEEP_ME')")
            if self.fail_once:
                self.fail_once = False
                raise RuntimeError("synthetic crash during upstream uninstall")
            return json.dumps({"status": "ok"})
        raise AssertionError(tool)

    def create(self) -> Path:
        with patch.object(managed, "checked_checkout",
                          return_value={"upstream_ecc_sha": managed.ECC_SHA}), \
             patch.object(managed, "_native", side_effect=self.fake_native):
            result = managed.provision(self.ecc, self.base)
        self.assertEqual(result["status"], "PASS_ISOLATED_PROVISION")
        self.assertEqual(result["managed_count"], 1)
        self.assertIn("doctor", self.calls)
        home = Path(result["home"])
        self.assertTrue(home.exists())
        self.assertTrue((home / managed.MARKER).exists())
        self.assertTrue((home / managed.KNOWN_RESIDUAL).exists())
        return home

    def retire(self, home: Path) -> dict:
        with patch.object(managed, "checked_checkout",
                          return_value={"upstream_ecc_sha": managed.ECC_SHA}), \
             patch.object(managed, "_native", side_effect=self.fake_native):
            return managed.retire(self.ecc, home)

    def test_owned_isolated_provision_and_verified_retirement(self):
        home = self.create()
        report = managed.inspect(home)
        self.assertEqual(report["status"], "PASS_INVENTORY")
        self.assertEqual(report["phase"], "READY")
        result = self.retire(home)
        self.assertEqual(result["status"], "PASS_ISOLATED_ROLLBACK")
        self.assertTrue(result["home_removed"])
        self.assertEqual(result["native_residual_before_cleanup"],
                         [managed.KNOWN_RESIDUAL])
        self.assertFalse(result["native_exact_rollback"])
        self.assertFalse(home.exists())
        self.assertTrue(self.base.is_dir())

    def test_unknown_owner_file_blocks_uninstaller_before_any_mutation(self):
        home = self.create()
        owner = home / "owner-important.txt"
        owner.write_text("PRESERVE OWNER", encoding="utf-8")
        self.assertEqual(managed.inspect(home)["status"], "BLOCKED_UNSAFE")
        before = len(self.calls)
        with self.assertRaisesRegex(ValueError, "unrelated files"):
            self.retire(home)
        self.assertEqual(len(self.calls), before)
        self.assertTrue(owner.exists())
        owner.unlink()
        self.assertTrue(self.retire(home)["home_removed"])

    def test_modified_state_db_blocks_before_native_uninstall(self):
        home = self.create()
        with sqlite3.connect(home / managed.KNOWN_RESIDUAL) as conn:
            conn.execute("CREATE TABLE sessions (secret TEXT)")
            conn.execute("INSERT INTO sessions VALUES ('user-record')")
        with self.assertRaisesRegex(ValueError, "Modified managed file"):
            self.retire(home)
        self.assertTrue((home / managed.KNOWN_RESIDUAL).exists())

    def test_new_symlink_blocks_before_native_uninstall(self):
        home = self.create()
        (home / "link").symlink_to(self.base)
        with self.assertRaisesRegex(ValueError, "Symlink"):
            self.retire(home)
        self.assertTrue(home.is_dir())

    def test_crash_during_uninstall_resumes_only_owned_root(self):
        home = self.create()
        self.fail_once = True
        with self.assertRaisesRegex(RuntimeError, "synthetic crash"):
            self.retire(home)
        self.assertEqual(managed.inspect(home)["phase"], "RETIRING")
        self.assertTrue(home.is_dir())
        self.assertTrue(self.retire(home)["home_removed"])

    def test_non_empty_sqlite_state_refuses_cleanup_without_loss(self):
        home = self.create()
        self.inject_sessions = True
        with self.assertRaisesRegex(ValueError, "non-cache data"):
            self.retire(home)
        self.assertTrue(home.exists())
        with sqlite3.connect(home / managed.KNOWN_RESIDUAL) as conn:
            self.assertEqual(conn.execute("SELECT secret FROM sessions").fetchone(),
                             ("KEEP_ME",))

    def test_forged_marker_cannot_delete_another_generated_directory(self):
        home = self.create()
        copied = self.base / ("h777-ecc-" + "0" * 32)
        copied.mkdir(mode=0o700)
        shutil_marker = copied / managed.MARKER
        shutil_marker.write_bytes((home / managed.MARKER).read_bytes())
        with self.assertRaisesRegex(ValueError, "provenance"):
            managed._verify_home(copied)
        self.assertTrue(copied.exists())


class TestPinnedContainerArguments(unittest.TestCase):
    def test_container_sandbox_is_networkless_nonroot_immutable(self):
        with tempfile.TemporaryDirectory(prefix="h777-native-args-") as root:
            ecc = Path(root) / "ecc"
            ecc.mkdir()
            home = Path(root) / "home"
            home.mkdir()
            with patch.object(managed, "checked_checkout", return_value={
                "upstream_ecc_sha": managed.ECC_SHA,
            }), patch.object(managed.subprocess, "run") as sub:
                sub.return_value.stdout = ""
                cmd = managed._native_command(ecc, home, "uninstall", [])
        self.assertEqual(cmd[cmd.index("--network") + 1], "none")
        self.assertIn("--read-only", cmd)
        self.assertEqual(cmd[cmd.index("--cap-drop") + 1], "ALL")
        self.assertIn("no-new-privileges:true", cmd)
        self.assertIn("--pull=never", cmd)
        self.assertTrue(any("dst=/ecc,readonly" in p for p in cmd))
        self.assertTrue(any("dst=/test-home" in p for p in cmd))
        self.assertEqual(cmd[-1], "--json")
        self.assertNotIn("--privileged", cmd)


if __name__ == "__main__":
    unittest.main()
