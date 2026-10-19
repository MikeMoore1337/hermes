"""Offline exact-source negative tests for BRC reconnect/pending-call security."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.h15_brc_harden_reconnect import HUB, REPLACEMENTS, apply
from scripts.h15_remote_commander_candidate_audit import AuditError, UPSTREAM_SHA


class ReconnectPolicyTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name)
        self.target = self.root / HUB
        self.target.parent.mkdir(parents=True)
        self.original = "\n".join(pair[0] for pair in REPLACEMENTS)
        self.target.write_text(self.original, encoding="utf-8")
        p = patch("scripts.h15_brc_harden_reconnect.evaluate",
                  return_value={"status": "SOURCE_PIN_VERIFIED"})
        p.start()
        self.addCleanup(p.stop)

    def test_strict_patch_rejects_stale_and_foreign_socket_replies(self):
        result = apply(self.root)
        source = self.target.read_text(encoding="utf-8")
        for old, new in REPLACEMENTS:
            self.assertIn(new, source)
            # The tick() method's original header is intentionally kept
            # after an inserted guard, so do not require its removal.
            if old not in new:
                self.assertNotIn(old, source)
        self.assertEqual(result["pending_calls"], "BOUND_TO_DEVICE_AND_SOCKET")
        self.assertEqual(result["old_socket_results"], "IGNORED")
        self.assertFalse(result["production_ready"])

    def test_unapproved_sha_denied(self):
        with self.assertRaisesRegex(AuditError, "unreviewed_upstream_sha"):
            apply(self.root, sha="f" * 40)
        self.assertEqual(self.target.read_text(encoding="utf-8"), self.original)

    def test_changed_connection_check_denied_atomically(self):
        altered = self.original.replace("if (dev) dev.lastSeen = Date.now();",
                                       "if (dev) dev.lastSeen = 0;")
        self.target.write_text(altered, encoding="utf-8")
        with self.assertRaisesRegex(AuditError, "unreviewed_hub_source_change"):
            apply(self.root)
        self.assertEqual(self.target.read_text(encoding="utf-8"), altered)

    def test_repatch_denied(self):
        apply(self.root)
        with self.assertRaisesRegex(AuditError, "unreviewed_hub_source_change"):
            apply(self.root)

    def test_symlink_to_other_file_never_modified(self):
        self.target.unlink()
        victim = self.root / "another_source.ts"
        victim.write_text(self.original, encoding="utf-8")
        self.target.symlink_to(victim)
        with self.assertRaisesRegex(AuditError, "unsafe_hub_source"):
            apply(self.root)
        self.assertEqual(victim.read_text(encoding="utf-8"), self.original)


if __name__ == "__main__":
    unittest.main()
