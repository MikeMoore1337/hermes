"""Guard the lock-owning launcher before it reads or changes runtime state."""
import unittest

from scripts.h15_remote_commander_candidate_audit import AuditError
from scripts.h454_windows_launcher_guard import ANCHOR, GUARD, patch_launcher


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


if __name__ == "__main__":
    unittest.main()
