"""The existing Windows agent must never silently re-pair or erase credentials."""
from __future__ import annotations

import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.h15_remote_commander_candidate_audit import AuditError
from scripts.h454_agent_no_auto_pair import apply, patch_cli


CLI = """import { pairDevice, loadCredentials, clearCredentials, saveCredentials, type DeviceCredentials } from './transport/pairing.js';
if (flag('logout')) clearCredentials();
async function resolveCredentials() {
  if (token) return { relayUrl, deviceToken: token, pairedAt: 'manual' };
  if (saved) return saved;
  return pairDevice({ relayUrl: relayArg, name, deviceId, openBrowser: !flag('no-browser'), log: (m) => console.log(m) });
}
const start = (c: DeviceCredentials) => {
  client = new WsClient({
    onUnauthorized: async () => {
      if (c.pairedAt === 'manual') return false;
      log('warn', 'Relay rejected our device token; re-pairing');
      clearCredentials();
      const fresh = await pairDevice({ relayUrl: c.relayUrl, name: c.name, deviceId: c.deviceId, openBrowser: !flag('no-browser'), log: (m) => console.log(m) });
      saveCredentials(fresh);
      start(fresh);
      return true;
    },
  });
};
"""


class NoAutoPairTests(unittest.TestCase):
    def test_patch_preserves_saved_and_manual_credentials_but_blocks_repair(self):
        result = patch_cli(CLI)
        self.assertIn("if (token) return", result)
        self.assertIn("if (saved) return saved", result)
        self.assertIn("if (flag('logout')) clearCredentials()", result)
        self.assertNotIn("pairDevice", result)
        self.assertNotIn("saveCredentials", result)
        self.assertEqual(result.count("clearCredentials()"), 1)
        self.assertIn("automatic pairing disabled", result)
        self.assertIn("staged credentials retained", result)
        self.assertIn("return true;", result)

    def test_drift_and_repeated_patching_are_refused(self):
        for value in (CLI.replace("re-pairing", "changed"), CLI + CLI, patch_cli(CLI)):
            with self.subTest(sha=hashlib.sha256(value.encode()).hexdigest()[:8]):
                with self.assertRaisesRegex(AuditError, "unreviewed_auto_pair_source"):
                    patch_cli(value)

    def test_source_hash_mismatch_does_not_write(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "packages/agent/src/cli.ts"
            target.parent.mkdir(parents=True)
            target.write_text(CLI, encoding="utf-8")
            with patch("scripts.h454_agent_no_auto_pair.evaluate", return_value={}):
                with self.assertRaisesRegex(AuditError, "unreviewed_auto_pair_digest"):
                    apply(root)
            self.assertEqual(target.read_text(encoding="utf-8"), CLI)

    def test_only_exact_reviewed_source_is_written(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "packages/agent/src/cli.ts"
            target.parent.mkdir(parents=True)
            target.write_bytes(CLI.encode())
            digest = hashlib.sha256(CLI.encode()).hexdigest()
            with patch("scripts.h454_agent_no_auto_pair.evaluate", return_value={}), \
                 patch("scripts.h454_agent_no_auto_pair.CLI_SHA256", digest):
                result = apply(root)
            self.assertEqual(target.read_text(encoding="utf-8"), patch_cli(CLI))
            self.assertFalse(result["production_activated"])
            self.assertEqual(result["unauthorized"], "STOP_AND_RETAIN_CREDENTIALS")

    def test_changed_anchor_is_refused_before_writing_even_with_matching_digest(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "packages/agent/src/cli.ts"
            target.parent.mkdir(parents=True)
            altered = CLI.replace("re-pairing", "unexpected")
            target.write_bytes(altered.encode())
            with patch("scripts.h454_agent_no_auto_pair.evaluate", return_value={}), \
                 patch("scripts.h454_agent_no_auto_pair.CLI_SHA256", hashlib.sha256(altered.encode()).hexdigest()):
                with self.assertRaisesRegex(AuditError, "unreviewed_auto_pair_source"):
                    apply(root)
            self.assertEqual(target.read_bytes(), altered.encode())

    def test_symlinked_cli_is_refused(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            target = root / "packages/agent/src/cli.ts"
            target.parent.mkdir(parents=True)
            original = root / "other.ts"
            original.write_bytes(CLI.encode())
            try:
                target.symlink_to(original)
            except OSError as exc:
                self.skipTest(f"symlink unavailable: {type(exc).__name__}")
            with patch("scripts.h454_agent_no_auto_pair.evaluate", return_value={}):
                with self.assertRaisesRegex(AuditError, "unsafe_auto_pair_source"):
                    apply(root)
            self.assertEqual(original.read_bytes(), CLI.encode())


if __name__ == "__main__":
    unittest.main()
