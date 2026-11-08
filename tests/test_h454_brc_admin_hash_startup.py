"""Hermes #454: fail-closed, source-pinned admin hash startup patch tests."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import h454_brc_admin_hash_startup as fix
from scripts.h15_remote_commander_candidate_audit import AuditError


# Synthetic file and password-verifier declaration; no real passwords, hashes,
# device IDs, production database snapshots, or owner secrets in these tests.
SOURCE = (
    "export function verifyPassword(pw: string, stored: string): boolean "
    "{ return pw === stored; }\n"
    + fix.VULNERABLE
    + "\n"
)


class AdminHashStartupPatchTests(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory(prefix="h454-admin-patch-")
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name)
        self.target = self.root / fix.STORE
        self.target.parent.mkdir(parents=True, exist_ok=True)
        self.target.write_text(SOURCE, encoding="utf-8")
        origin = patch.object(fix, "UPSTREAM_STORE_BLOB", fix.git_blob(SOURCE))
        upstream = patch.object(
            fix, "evaluate", return_value={"status": "SOURCE_PIN_VERIFIED"}
        )
        origin.start()
        upstream.start()
        self.addCleanup(origin.stop)
        self.addCleanup(upstream.stop)

    def test_only_verifiable_existing_admin_password_skips_hash_rotation(self):
        result = fix.apply(self.root)
        patched = self.target.read_text(encoding="utf-8")
        self.assertEqual(
            result["status"], "H454_ADMIN_HASH_STARTUP_IDEMPOTENT_SOURCE_PATCH"
        )
        self.assertTrue(result["admin_hash_preserved_when_password_valid"])
        self.assertTrue(result["password_rotation_preserved"])
        self.assertFalse(result["credential_guard_changed"])
        self.assertFalse(result["production_mutation"])
        self.assertEqual(patched.count(fix.PATCHED), 1)
        self.assertNotIn(fix.VULNERABLE, patched)
        self.assertIn(
            "if (existing && verifyPassword(password, existing.password_hash))",
            patched,
        )
        self.assertLess(
            patched.index(
                "if (existing && verifyPassword(password, existing.password_hash))"
            ),
            patched.index("const hash = hashPassword(password);"),
        )
        self.assertIn(
            "this.db.prepare('UPDATE users SET password_hash = ? WHERE id = ?')",
            patched,
        )
        self.assertIn(
            "return { ...existing, password_hash: hash };",
            patched,
        )

    def test_source_drift_rejected_without_rewriting_owner_file(self):
        changed = SOURCE.replace("return pw === stored;", "return false;")
        self.target.write_text(changed, encoding="utf-8")
        with self.assertRaisesRegex(AuditError, "unreviewed_admin_store_source"):
            fix.apply(self.root)
        self.assertEqual(self.target.read_text(encoding="utf-8"), changed)

    def test_original_upsert_drift_rejected_atomically(self):
        changed = SOURCE.replace("this.getUserByName(username)", "this.getUser(username)")
        self.target.write_text(changed, encoding="utf-8")
        with self.assertRaisesRegex(AuditError, "unreviewed_admin_store_source"):
            fix.apply(self.root)
        self.assertEqual(self.target.read_text(encoding="utf-8"), changed)

    def test_patch_cannot_run_twice_on_the_same_source(self):
        fix.apply(self.root)
        first = self.target.read_text(encoding="utf-8")
        with self.assertRaisesRegex(AuditError, "unreviewed_admin_store_source"):
            fix.apply(self.root)
        self.assertEqual(self.target.read_text(encoding="utf-8"), first)

    def test_broken_password_verifier_not_accepted(self):
        changed = SOURCE.replace("export function verifyPassword", "function bad")
        self.target.write_text(changed, encoding="utf-8")
        with self.assertRaisesRegex(AuditError, "unreviewed_admin_store_source"):
            fix.apply(self.root)
        self.assertEqual(self.target.read_text(encoding="utf-8"), changed)

    def test_symlinked_upstream_file_is_refused(self):
        outside = self.root / "untrusted-source.ts"
        outside.write_text(SOURCE, encoding="utf-8")
        self.target.unlink()
        self.target.symlink_to(outside)
        with self.assertRaisesRegex(AuditError, "symlink_in_candidate"):
            fix.apply(self.root)
        self.assertEqual(outside.read_text(encoding="utf-8"), SOURCE)

    def test_wrong_upstream_revision_refused_before_audit_or_write(self):
        with patch.object(fix, "evaluate") as verify:
            with self.assertRaisesRegex(AuditError, "unreviewed_upstream_sha"):
                fix.apply(self.root, sha="0" * 40)
            verify.assert_not_called()
        self.assertEqual(self.target.read_text(encoding="utf-8"), SOURCE)

    def test_missing_source_is_refused_without_creating_file(self):
        self.target.unlink()
        with self.assertRaisesRegex(AuditError, "candidate_file_missing_or_oversize"):
            fix.apply(self.root)
        self.assertFalse(self.target.exists())


if __name__ == "__main__":
    unittest.main()
