"""H454: startup hash stability with strict pinned-source refusal and no auth bypass."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import h454_brc_admin_hash_stability as subject
from scripts.h15_remote_commander_candidate_audit import AuditError


class AdminHashStabilityTests(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory(prefix="h454-admin-hash-")
        self.addCleanup(tmp.cleanup)
        self.root = Path(tmp.name)
        self.path = self.root / subject.STORE
        self.path.parent.mkdir(parents=True)
        self.original = (
            "import { verifyPassword, hashPassword } from 'fixture';\n"
            "export class SqliteStore {\n"
            + subject.ORIGINAL
            + "    return newUser;\n  }\n}\n"
        ).encode("utf-8")
        self.path.write_bytes(self.original)
        guard = patch.object(subject, "evaluate", return_value={"status": "SOURCE_PIN_VERIFIED"})
        guard.start()
        self.addCleanup(guard.stop)
        sha = patch.object(subject, "UPSTREAM_STORE_BLOB_SHA", subject.git_blob_sha(self.original))
        sha.start()
        self.addCleanup(sha.stop)

    def test_same_password_keeps_hash_but_changed_password_still_rotates(self):
        verdict = subject.apply(self.root)
        code = self.path.read_text(encoding="utf-8")
        self.assertEqual(verdict["status"], "H454_ADMIN_HASH_STABILITY_PATCHED")
        self.assertFalse(verdict["auth_guard_relaxed"])
        self.assertIn(
            "if (existing && verifyPassword(password, existing.password_hash))", code
        )
        self.assertIn("return existing;", code)
        self.assertIn("const hash = hashPassword(password);", code)
        self.assertIn(
            "UPDATE users SET password_hash = ? WHERE id = ?", code
        )
        self.assertLess(
            code.index("verifyPassword(password, existing.password_hash)"),
            code.index("const hash = hashPassword(password);"),
        )

    def test_repeat_patch_refused_without_writes(self):
        subject.apply(self.root)
        after = self.path.read_bytes()
        with self.assertRaisesRegex(AuditError, "admin_store_source_drift"):
            subject.apply(self.root)
        self.assertEqual(after, self.path.read_bytes())

    def test_unpinned_source_refused_without_mutations(self):
        for altered in (
            self.original.replace(b"hashPassword(password)", b"hashPassword('unknown')"),
            self.original.replace(b"UPDATE users SET", b"DELETE FROM users"),
        ):
            with self.subTest(altered=altered[-32:]):
                self.path.write_bytes(altered)
                with self.assertRaisesRegex(AuditError, "admin_store_source_drift"):
                    subject.apply(self.root)
                self.assertEqual(altered, self.path.read_bytes())
        self.path.write_bytes(self.original)

    def test_bad_upstream_revision_refused(self):
        with self.assertRaisesRegex(AuditError, "unreviewed_upstream_sha"):
            subject.apply(self.root, sha="f" * 40)
        self.assertEqual(self.original, self.path.read_bytes())

    def test_symlinked_source_refused_without_overwriting_target(self):
        alternate = self.root / "outside"
        alternate.write_bytes(self.original)
        self.path.unlink()
        self.path.symlink_to(alternate)
        with self.assertRaisesRegex(AuditError, "admin_store_symlink_refused"):
            subject.apply(self.root)
        self.assertEqual(self.original, alternate.read_bytes())

    def test_failed_provenance_prevents_writes(self):
        with patch.object(subject, "evaluate", side_effect=AuditError("unverified_git_checkout")):
            with self.assertRaisesRegex(AuditError, "unverified_git_checkout"):
                subject.apply(self.root)
        self.assertEqual(self.original, self.path.read_bytes())


if __name__ == "__main__":
    unittest.main()
