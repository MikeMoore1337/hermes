"""Guard the lock-owning launcher before it reads or changes runtime state."""
import hashlib
import unittest

from scripts.h15_remote_commander_candidate_audit import AuditError
from scripts.h454_windows_launcher_guard import ANCHOR, GUARD, patch_launcher, patch_launcher_bytes


class LauncherGuardTests(unittest.TestCase):
    def test_guard_runs_inside_lock_before_reading_state(self):
        patched = patch_launcher("before\n" + ANCHOR + "PERSISTENT_STATE_MISSING\nafter\n")
        self.assertEqual(patched.count(GUARD), 1)
        self.assertLess(patched.index("FileShare]::None"), patched.index("h454-wss-transition.pending"))
        self.assertLess(patched.index("H454_RECOVERY_REQUIRED"), patched.index("PERSISTENT_STATE_MISSING"))
        self.assertIn("EnumerateFileSystemEntries", GUARD)
        self.assertIn("OrdinalIgnoreCase", GUARD)
        self.assertIn("H454_STATE_DIRECTORY_OVERSIZE", GUARD)

    def test_changed_duplicated_and_repatched_launcher_are_refused(self):
        for source in (ANCHOR.replace("OpenOrCreate", "Open"), ANCHOR + ANCHOR, patch_launcher(ANCHOR)):
            with self.subTest(size=len(source)), self.assertRaisesRegex(AuditError, "unreviewed_launcher_guard_source"):
                patch_launcher(source)

    def test_pinned_bytes_preserve_bom_and_each_existing_line_ending(self):
        for newline in ("\n", "\r\n"):
            for bom in (b"", b"\xef\xbb\xbf"):
                source = bom + ("before\n" + ANCHOR + "after\n").replace("\n", newline).encode()
                result = patch_launcher_bytes(source, hashlib.sha256(source).hexdigest().upper())
                guard = GUARD.replace("\n", newline).encode()
                self.assertEqual(result.count(guard), 1)
                self.assertEqual(result.replace(guard, b"", 1), source)

    def test_bytes_reject_drift_duplicates_and_unknown_encoding(self):
        source = ANCHOR.encode()
        for candidate, digest in ((source, "0" * 64), (source + source, hashlib.sha256(source + source).hexdigest()),
                                  (source + b"H454-WSS-TRANSITION.PENDING", hashlib.sha256(source + b"H454-WSS-TRANSITION.PENDING").hexdigest()),
                                  (b"\xff", hashlib.sha256(b"\xff").hexdigest()),
                                  (source + b"\0", hashlib.sha256(source + b"\0").hexdigest())):
            with self.subTest(candidate=candidate), self.assertRaises(AuditError):
                patch_launcher_bytes(candidate, digest)


if __name__ == "__main__":
    unittest.main()
