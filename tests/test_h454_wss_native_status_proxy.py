"""H454 private status proxy loopback E2E; no owner host or real bearer."""
from __future__ import annotations
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]

@unittest.skipUnless(shutil.which("node") and shutil.which("openssl"), "Node.js and OpenSSL required")
class PrivateStatusProxyE2ETests(unittest.TestCase):
    def test_private_status_only_owner_bearer_and_no_http_fallback(self):
        with tempfile.TemporaryDirectory(prefix="h454-status-tls-") as folder:
            certs = subprocess.run(
                ["/bin/sh", str(ROOT / "scripts/h454_wss_fixture_certificates.sh"), folder],
                cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True,
                text=True, timeout=25, check=False,
            )
            self.assertEqual(certs.returncode, 0, certs.stderr[-800:])
            result = subprocess.run(
                ["node", str(ROOT / "scripts/h454_wss_native_status_e2e.mjs"), folder],
                cwd=ROOT, stdin=subprocess.DEVNULL, capture_output=True,
                text=True, timeout=35, check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr[-2500:])
        self.assertIn("H454_PRIVATE_TLS_STATUS_PROXY_SYNTHETIC_E2E=PASS", result.stdout)
        self.assertIn("H454_STATUS_INVALID_REQUESTS_AND_ADMIN_ROUTES=DENIED", result.stdout)
        self.assertIn("H454_ORIGINAL_HOST_OR_TOKEN_USED=NO", result.stdout)
        self.assertIn("H454_PRIVATE_TLS_REAL_SOCKET_PINNED_CA_SNI=PASS", result.stdout)

if __name__ == "__main__":
    unittest.main()
