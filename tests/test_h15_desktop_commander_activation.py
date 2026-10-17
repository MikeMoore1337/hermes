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

    def test_node_version_gate(self):
        src = SCRIPT.read_text()
        # Execute the real shell version validator, without root or system changes.
        definitions = src.split('require_root\ncase "$MODE" in')[0]
        for version, accepted in (
            ("18.19.1", False), ("20.19.0", False),
            ("22.11.9", False), ("22.12.0", True),
            ("22.16.0", True), ("24.0.0", True),
            ("garbage", False),
        ):
            with self.subTest(version=version):
                proc = subprocess.run(
                    ["bash", "-c", definitions + '\nvalidate_node_version "$1"', "bash", version],
                    capture_output=True, text=True,
                )
                self.assertEqual(proc.returncode == 0, accepted, proc.stderr)
    def test_npm_engine_strict_and_unprivileged_check(self):
        src = SCRIPT.read_text()
        self.assertIn('as_identity npm --prefix "$STATE" install --engine-strict', src)
        self.assertIn("version=$(as_identity node -p 'process.versions.node')", src)
        self.assertIn("require_supported_node", src)

    def test_systemd_and_manual_oauth_storage_match(self):
        service = (ROOT / "deploy" / "hermes-desktop-commander.service").read_text()
        setup = SCRIPT.read_text()
        expected = "/var/lib/hermes-desktop-commander/.mcp-auth"
        self.assertIn(f"Environment=MCP_REMOTE_CONFIG_DIR={expected}", service)
        self.assertIn('MCP_REMOTE_CONFIG_DIR="$STATE/.mcp-auth"', setup)
        self.assertIn("Environment=HOME=/var/lib/hermes-desktop-commander", service)
        self.assertIn("User=hermes-desktop", service)
        self.assertIn("NoNewPrivileges=true", service)
        self.assertNotIn("ExecStartPre=", service)

    def test_pinned_and_no_npx_network_at_service_start(self):
        src = COLLECTOR.read_text()
        self.assertIn("node_modules/.bin/mcp-remote", src)
        self.assertIn("node_modules/.bin/desktop-commander", src)
        self.assertNotIn('("npx", "-y",', src)

if __name__ == "__main__":
    unittest.main()
