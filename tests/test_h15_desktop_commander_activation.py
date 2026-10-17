"""Owner activation must be explicit; the isolated client must not auto-install packages."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "deploy" / "h15-desktop-commander-setup.sh"
COLLECTOR = ROOT / "control_center" / "desktop_commander.py"

class ActivationTests(unittest.TestCase):
    def test_bash_syntax(self):
        proc = subprocess.run(["bash", "-n", str(SCRIPT)], capture_output=True)
        self.assertEqual(proc.returncode, 0, proc.stderr.decode())
    def test_owner_gates(self):
        src = SCRIPT.read_text()
        for mode in ("prepare)", "local)", "auth)", "verify)", "enable)", "status)"):
            self.assertIn(mode, src)
        self.assertIn('as_identity npm --prefix "$STATE" install', src)
        self.assertIn('runuser -u "$USER_NAME"', src)
        self.assertIn("TIMER_ACTIVATED=NO", src)
        self.assertNotIn("systemctl enable --now hermes-agent", src)
        self.assertNotIn("rm -rf", src)
    def test_pinned_and_no_npx_network_at_service_start(self):
        src = COLLECTOR.read_text()
        self.assertIn("node_modules/.bin/mcp-remote", src)
        self.assertIn("node_modules/.bin/desktop-commander", src)
        self.assertNotIn('("npx", "-y",', src)

if __name__ == "__main__":
    unittest.main()
