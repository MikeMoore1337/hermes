"""Contract tests for owner-scoped SSH forwarding account bootstrap (#276/#297).

No modifications to system users, sshd or /etc; only validates source policy.
"""
import shutil
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/h15-device-fabric-ssh-forward-setup.sh"


class DeviceFabricSshForwardSetupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = SCRIPT.read_text(encoding="utf-8")

    def test_bash_syntax(self):
        if not shutil.which("bash"):
            self.skipTest("bash not available")
        subprocess.run(["bash", "-n", str(SCRIPT)], check=True, timeout=5)

    def test_dedicated_account_non_shell_password_disabled(self):
        for expected in (
            "USER_NAME=hermes-presence-tunnel",
            "HOME_DIR=/var/lib/hermes-presence-tunnel",
            "--shell /usr/sbin/nologin",
            "--password '*'",
            "account_check",
            "unexpected_tunnel_group_membership",
            "unexpected_tunnel_uid",
            "unexpected_existing_tunnel_account",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.script)

    def test_authorized_keys_are_key_specific_and_only_forward(self):
        for expected in (
            'command="/usr/sbin/nologin",restrict,port-forwarding,permitopen="127.0.0.1:38177"',
            "hermes-presence-windows",
            "hermes-presence-linux",
            "authorized_keys_unexpected_count",
            "authorized_keys_windows_policy",
            "authorized_keys_linux_policy",
            "authorized_keys_permissions",
            "authorized_keys_owner",
            "device_keys_not_distinct",
            "ssh-keygen -l -f",
            "device_key_fingerprint_mismatch",
            "host_key_fingerprint_mismatch",
            "SSH_REMOTE_SHELL=DENIED",
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected, self.script)
        self.assertNotIn("ssh-rsa", self.script)
        self.assertNotIn("no-port-forwarding", self.script)

    def test_setup_does_not_touch_any_existing_sshd_configuration(self):
        script = self.script
        self.assertIn("/usr/sbin/sshd -t", script)
        self.assertIn("SSHD_CONFIG=UNCHANGED", script)
        self.assertIn("SSHD_RESTART=NOT_REQUIRED", script)
        self.assertNotIn("systemctl restart ssh", script)
        self.assertNotIn("systemctl reload ssh", script)
        self.assertNotIn("sshd_config.d", script)
        self.assertNotIn("chmod 777", script)
        self.assertNotIn("eval ", script)

    def test_idempotence_and_narrow_rollback(self):
        script = self.script
        self.assertIn("cmp -s", script)
        self.assertIn("existing_keys_differ_manual_review_required", script)
        self.assertIn("SSH_TUNNEL_KEYS=ALREADY_PRESENT", script)
        self.assertIn("SSH_TUNNEL_KEYS=INSTALLED", script)
        self.assertIn('rm -f -- "$AUTH"', script)
        self.assertNotIn("userdel", script)
        self.assertNotIn("rm -rf", script)
        self.assertIn("TUNNEL_ACCOUNT_PRESERVED=YES", script)
        self.assertIn("SSH_TUNNEL_KEYS=REVOKED", script)

if __name__ == "__main__":
    unittest.main()
