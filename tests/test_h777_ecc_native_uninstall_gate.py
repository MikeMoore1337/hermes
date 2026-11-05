"""Hermes H777 offline native-uninstall gate: deterministic guard regression."""
from __future__ import annotations

import json
import os
from pathlib import Path
import sqlite3
import tempfile
import unittest

from scripts.h777_ecc_native_uninstall_gate import (
    KNOWN_RESIDUAL, classify, fresh_home, original_command,
    planned_paths, seed_foreign_projection, snapshot, sqlite_semantic_snapshot,
)


class TestNativeRollbackClassification(unittest.TestCase):
    def test_identical_snapshot_passes_exact_rollback(self):
        before = {".hermes/owner-sentinel.txt": "SHA256:abc"}
        self.assertEqual(
            classify(before, dict(before)),
            {"status": "PASS_NATIVE_EXACT_ROLLBACK", "residual": [],
             "owner_changed": []},
        )

    def test_only_known_sqlite_cache_is_a_failure_not_pass(self):
        before = {".hermes/owner-sentinel.txt": "SHA256:abc"}
        after = {**before, KNOWN_RESIDUAL: "SHA256:new"}
        result = classify(before, after)
        self.assertEqual(result["status"], "FAIL_KNOWN_CACHE")
        self.assertEqual(result["residual"], [KNOWN_RESIDUAL])
        self.assertEqual(result["owner_changed"], [])

    def test_unknown_file_and_any_owner_change_are_critical_failures(self):
        before = {".hermes/owner-sentinel.txt": "SHA256:old"}
        for after in (
            {},
            {**before, "unexpected/secret.txt": "SHA256:new"},
            {KNOWN_RESIDUAL: "SHA256:abc", ".hermes/owner-sentinel.txt": "SHA256:new"},
            {**before, KNOWN_RESIDUAL: "SHA256:abc",
             ".claude/foreign.txt": "SHA256:foreign"},
        ):
            with self.subTest(after=after):
                self.assertEqual(classify(before, after)["status"],
                                 "FAIL_UNEXPECTED_DELTA")

    def test_original_plan_contains_only_hermes_paths(self):
        payload = {"plan": {"operations": [
            {"destinationPath": "/test-home/.hermes/skills/verification-loop/SKILL.md"},
            {"destinationPath": "/test-home/.hermes/rules/core.md"},
        ]}}
        self.assertEqual(
            planned_paths(json.dumps(payload)),
            {".hermes/skills/verification-loop/SKILL.md", ".hermes/rules/core.md"},
        )

    def test_cross_home_plan_and_traversal_are_rejected(self):
        for destination in (
            "/test-home/.claude/evil",
            "/forbidden/evil",
            "/test-home/.hermes/../outside",
        ):
            with self.subTest(destination=destination):
                payload = json.dumps({"plan": {"operations": [
                    {"destinationPath": destination},
                ]}})
                with self.assertRaises(AssertionError):
                    planned_paths(payload)

    def test_empty_plan_rejected(self):
        with self.assertRaises(AssertionError):
            planned_paths('{"plan":{"operations":[]}}')


class TestH777TemporaryHome(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="h777-tests-")
        self.addCleanup(self.tmp.cleanup)
        self.temp = Path(self.tmp.name)

    def test_snapshot_does_not_follow_symlink_into_owner_file(self):
        home = fresh_home(self.temp, "symlink-negative")
        owner = home / ".hermes/owner-sentinel.txt"
        link = home / ".claude/ecc/state.db"
        link.parent.mkdir(parents=True)
        link.symlink_to("../../.hermes/owner-sentinel.txt")
        state = snapshot(home)
        self.assertEqual(state[KNOWN_RESIDUAL],
                         "SYMLINK:../../.hermes/owner-sentinel.txt")
        self.assertNotEqual(state[KNOWN_RESIDUAL],
                            state[".hermes/owner-sentinel.txt"])
        self.assertEqual(owner.read_text(),
                         "H777_SYNTHETIC_OWNER_STATE_UNTOUCHED\n")

    def test_only_predeclared_disposable_homes_can_bind_into_docker(self):
        ecc = self.temp / "ecc"
        ecc.mkdir()
        home = fresh_home(self.temp, "never-installed")
        cmd = original_command(ecc, home, "/usr/local/bin/node",
                               ["scripts/uninstall.js", "--target", "hermes"])
        self.assertIn("--network", cmd)
        self.assertEqual(cmd[cmd.index("--network") + 1], "none")
        self.assertIn("--read-only", cmd)
        self.assertIn("--cap-drop", cmd)
        self.assertEqual(cmd[cmd.index("--cap-drop") + 1], "ALL")
        self.assertIn("--security-opt", cmd)
        self.assertIn("no-new-privileges:true", cmd)
        self.assertIn("type=bind,src=" + str(ecc) + ",dst=/ecc,readonly", cmd)
        self.assertTrue(any("dst=/test-home" in p for p in cmd))
        self.assertNotIn("--privileged", cmd)

    def test_arbitrary_user_home_cannot_be_mounted(self):
        ecc = self.temp / "ecc"
        ecc.mkdir()
        arbitrary = self.temp / "private"
        arbitrary.mkdir()
        with self.assertRaisesRegex(ValueError, "Unsafe disposable"):
            original_command(ecc, arbitrary, "/usr/local/bin/node", [])

    def test_external_symlinked_home_cannot_be_mounted(self):
        ecc = self.temp / "ecc"
        ecc.mkdir()
        real = fresh_home(self.temp, "never-installed")
        fake = self.temp / "preexisting-state"
        fake.symlink_to(real, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, "Unsafe disposable"):
            original_command(ecc, fake, "/usr/local/bin/node", [])

    def test_readonly_sqlite_table_hash_detects_semantic_changes(self):
        database = self.temp / "legitimate.db"
        with sqlite3.connect(database) as db:
            db.execute("CREATE TABLE install_state (id TEXT, value TEXT)")
            db.execute("INSERT INTO install_state VALUES ('other-home', 'keep-me')")
        before = sqlite_semantic_snapshot(database)
        self.assertEqual(before["table_counts"]["install_state"], 1)
        self.assertEqual(before, sqlite_semantic_snapshot(database))
        with sqlite3.connect(database) as db:
            db.execute("UPDATE install_state SET value='changed'")
        after = sqlite_semantic_snapshot(database)
        self.assertEqual(after["table_counts"], before["table_counts"])
        self.assertNotEqual(after["table_hashes"], before["table_hashes"])

    def test_foreign_projection_fixture_uses_distinct_install_root(self):
        database = self.temp / "foreign.db"
        with sqlite3.connect(database) as db:
            db.execute("CREATE TABLE install_state (target_id TEXT, target_root TEXT)")
            db.execute("INSERT INTO install_state VALUES (?, ?)",
                       ("hermes", "/test-home/.hermes"))
        seed_foreign_projection(database)
        with sqlite3.connect(database) as db:
            self.assertEqual(db.execute(
                "SELECT target_id,target_root FROM install_state").fetchall(),
                [("hermes", "/unrelated-h777-owner/.hermes")])
        with self.assertRaisesRegex(AssertionError, "Unexpected original"):
            seed_foreign_projection(database)

    def test_sqlite_snapshot_refuses_symlink_and_invalid_database(self):
        owner = self.temp / "owner.db"
        owner.write_bytes(b"PRIVATE_OWNER_NO_SQLITE")
        link = self.temp / "link.db"
        link.symlink_to(owner)
        with self.assertRaises(ValueError):
            sqlite_semantic_snapshot(link)
        with self.assertRaises(sqlite3.DatabaseError):
            sqlite_semantic_snapshot(owner)

    def test_no_test_home_may_overwrite_existing_files(self):
        home = fresh_home(self.temp, "never-installed")
        with self.assertRaises(FileExistsError):
            fresh_home(self.temp, "never-installed")
        self.assertEqual((home / ".hermes/owner-sentinel.txt").read_text(),
                         "H777_SYNTHETIC_OWNER_STATE_UNTOUCHED\n")


if __name__ == "__main__":
    unittest.main()
