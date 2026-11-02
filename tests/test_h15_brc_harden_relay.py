"""Negative tests for BRC WSS header-only authorization patch, #371."""
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.h15_brc_harden_relay import (
    apply, VULNERABLE, PATCHED, RELAY, ROTATE_MARKER, ROTATE_PATCH,
    ATTACH_MARKER, ATTACH_PATCH,
)
from scripts.h15_remote_commander_candidate_audit import AuditError

SOURCE = ("import { WebSocketServer } from 'ws';\nhttp.on('upgrade', (req, socket, head) => {\n"
          + VULNERABLE + "\n" + ROTATE_MARKER + "\n" + ATTACH_MARKER + "\n});\n")


class RelayAuthTests(unittest.TestCase):
    def setUp(self):
        t = tempfile.TemporaryDirectory()
        self.addCleanup(t.cleanup)
        self.root = Path(t.name)
        self.target = self.root / RELAY
        self.target.parent.mkdir(parents=True, exist_ok=True)
        self.target.write_text(SOURCE, encoding="utf-8")
        guard = patch(
            "scripts.h15_brc_harden_relay.evaluate",
            return_value={"status": "SOURCE_PIN_VERIFIED"},
        )
        guard.start()
        self.addCleanup(guard.stop)

    def test_reject_query_tokens_without_disabling_bearer(self):
        result = apply(self.root)
        source = self.target.read_text(encoding="utf-8")
        self.assertEqual(result["ws_uri_token"], "DENIED")
        self.assertTrue(source.count(PATCHED) == 1)
        self.assertIn("url.searchParams.has('token')", source)
        self.assertNotIn("url.searchParams.get('token')", source)
        self.assertIn("h?.startsWith('Bearer ')", source)
        self.assertIn(ROTATE_PATCH, source)
        self.assertIn(ATTACH_PATCH, source)
        self.assertIn("writable: false, configurable: false, enumerable: false", source)
        self.assertNotIn("value: token", source)
        self.assertFalse(result["production_ready"])

    def test_source_changed_fail_closed_without_touching_file(self):
        changed = SOURCE.replace(
            "url.searchParams.get('token')", "url.searchParams.get('key')"
        )
        self.target.write_text(changed, encoding="utf-8")
        with self.assertRaisesRegex(AuditError, "unreviewed_ws_auth_source"):
            apply(self.root)
        self.assertEqual(self.target.read_text(encoding="utf-8"), changed)

    def test_refuse_to_reapply(self):
        apply(self.root)
        with self.assertRaisesRegex(AuditError, "unreviewed_ws_auth_source"):
            apply(self.root)

    def test_symlink_source_refused(self):
        self.target.unlink()
        tgt = self.root / "victim"
        tgt.write_text(SOURCE, encoding="utf-8")
        self.target.symlink_to(tgt)
        with self.assertRaisesRegex(AuditError, "relay_source_unsafe"):
            apply(self.root)
        self.assertEqual(tgt.read_text(encoding="utf-8"), SOURCE)

    def test_missing_credential_binding_marker_fails_atomically(self):
        altered = SOURCE.replace(ATTACH_MARKER, 'unreviewedAttach(ws)')
        self.target.write_text(altered, encoding='utf-8')
        with self.assertRaisesRegex(AuditError, 'unreviewed_ws_auth_source'):
            apply(self.root)
        self.assertEqual(self.target.read_text(encoding='utf-8'), altered)

    def test_missing_rotation_marker_fails_atomically(self):
        altered = SOURCE.replace(ROTATE_MARKER, 'unreviewedPairing()')
        self.target.write_text(altered, encoding='utf-8')
        with self.assertRaisesRegex(AuditError, 'unreviewed_ws_auth_source'):
            apply(self.root)
        self.assertEqual(self.target.read_text(encoding='utf-8'), altered)
    def test_unapproved_sha_refused(self):
        with self.assertRaisesRegex(AuditError, "unreviewed_upstream_sha"):
            apply(self.root, sha="f" * 40)


if __name__ == "__main__":
    unittest.main()
