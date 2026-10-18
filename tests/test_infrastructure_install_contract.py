"""No-network contract tests for opt-in YFC telemetry SSH bootstrap scripts."""
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]


class YfcInstallContractTests(unittest.TestCase):
    def test_both_installer_scripts_parse_under_bash(self):
        for name in (
            "install-yfc-infrastructure-emitter.sh",
            "install-hermes-yfc-pull.sh",
        ):
            with self.subTest(name=name):
                path = ROOT / "deploy" / name
                self.assertEqual(
                    subprocess.run(["bash", "-n", str(path)], check=False,
                                   capture_output=True).returncode, 0)

    def test_remote_emitter_limits_access_to_one_forced_command(self):
        script = (ROOT / "deploy/install-yfc-infrastructure-emitter.sh").read_text()
        self.assertIn('user=hermes-infra-read', script)
        self.assertIn('forced="restrict,command=', script)
        self.assertIn('die existing_authorized_keys_conflict', script)
        self.assertIn('die revision_mismatch', script)
        self.assertIn('die release_already_exists', script)
        self.assertNotIn("systemctl enable", script)
        self.assertNotIn("ssh-keyscan", script)
        self.assertNotIn("PasswordAuthentication=yes", script)

    def test_hermes_pull_requires_pinned_identity_and_real_smoke(self):
        script = (ROOT / "deploy/install-hermes-yfc-pull.sh").read_text()
        self.assertIn('ssh-keygen -F "$name" -f "$known"', script)
        self.assertIn("pinned_ssh_pull_smoke_failed", script)
        self.assertIn('assert data["yfc"]["status"] == "online"', script)
        self.assertIn("systemctl enable --now hermes-infrastructure-yfc-pull.timer", script)
        self.assertLess(script.index("pinned_ssh_pull_smoke_failed"),
                        script.index("systemctl enable --now"))
        self.assertNotIn("ssh-keyscan", script)
        self.assertNotIn("StrictHostKeyChecking=no", script)

    def test_no_password_or_agent_dependency_in_remote_ssh_unit(self):
        unit = (ROOT / "deploy/hermes-infrastructure-yfc-pull.service").read_text()
        self.assertIn("IPAddressDeny", (ROOT / "deploy/hermes-infrastructure-collector.service").read_text())
        self.assertIn("NoNewPrivileges=true", unit)
        self.assertIn("RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX", unit)
        pull = (ROOT / "control_center/infrastructure_pull.py").read_text()
        self.assertIn('"BatchMode=yes"', pull)
        self.assertIn('"PasswordAuthentication=no"', pull)
        self.assertIn('"StrictHostKeyChecking=yes"', pull)
        self.assertIn('"ClearAllForwardings=yes"', pull)


if __name__ == "__main__":
    unittest.main()
