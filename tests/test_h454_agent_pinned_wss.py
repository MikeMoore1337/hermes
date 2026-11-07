"""Only the reviewed BRC agent transport can receive the pinned WSS change."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts.h15_remote_commander_candidate_audit import AuditError
from scripts import h454_agent_pinned_wss as wss

SOURCE = """import WebSocket from 'ws';
class WsClient {
  constructor(opts) {
    this.wsUrl = WsClient.toWsUrl(opts.relayUrl);
  }
  connect() {
    new WebSocket(this.wsUrl, {
      handshakeTimeout: 15_000,
    });
  }
}
"""


class AgentPinnedWssTests(unittest.TestCase):
    def test_patch_requires_wss_local_target_and_per_connection_ca(self):
        result = wss.patch_source(SOURCE)
        for value in ("target.protocol !== 'wss:'", "target.hostname !== 'host.docker.internal'",
                      "target.port !== '38184'", "target.pathname !== '/ws'", "target.username",
                      "target.password", "target.search", "target.hash", "ca: relayCA",
                      "rejectUnauthorized: true", "servername: 'brc-agent.internal'"):
            self.assertIn(value, result)
        self.assertNotIn("setDefaultCACertificates", result)

    def test_changed_duplicate_and_already_patched_sources_are_refused(self):
        for source in (SOURCE.replace("15_000", "5_000"), SOURCE + SOURCE, wss.patch_source(SOURCE)):
            with self.subTest(size=len(source)), self.assertRaisesRegex(AuditError, "unreviewed_wss_source"):
                wss.patch_source(source)

    def test_exact_source_only_and_digest_drift_never_written(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / wss.TARGET
            target.parent.mkdir(parents=True)
            target.write_bytes(SOURCE.encode())
            with patch.object(wss, "evaluate", return_value={}):
                with self.assertRaisesRegex(AuditError, "unreviewed_wss_digest"):
                    wss.apply(root)
                self.assertEqual(target.read_bytes(), SOURCE.encode())
                with patch.object(wss, "SOURCE_SHA256", hashlib.sha256(SOURCE.encode()).hexdigest()):
                    result = wss.apply(root)
            self.assertEqual(target.read_text(encoding="utf-8"), wss.patch_source(SOURCE))
            self.assertFalse(result["production_activated"])

    def test_symlink_is_refused(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            target = root / wss.TARGET
            target.parent.mkdir(parents=True)
            other = root / "other.ts"
            other.write_bytes(SOURCE.encode())
            try:
                target.symlink_to(other)
            except OSError as exc:
                self.skipTest(type(exc).__name__)
            with patch.object(wss, "evaluate", return_value={}):
                with self.assertRaisesRegex(AuditError, "unsafe_wss_source"):
                    wss.apply(root)
            self.assertEqual(other.read_bytes(), SOURCE.encode())


if __name__ == "__main__":
    unittest.main()
