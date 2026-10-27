"""Source-only H454 SSH guard contracts; not a native Windows E2E test.

No host secret, SSH, device token, production deployment, or process execution.
"""
from pathlib import Path
import unittest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/h454_native_ssh_tunnel_guard.ps1"


class TunnelGuardContracts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.code = SCRIPT.read_text(encoding="utf-8")

    def test_privileges_and_owner_opt_in_gated_before_file_probe(self):
        src = self.code
        self.assertIn("$env:USERNAME -ne 'Mike'", src)
        self.assertIn("$Mode -eq 'Run' -and -not $OwnerApproved", src)
        self.assertLess(src.index("$Mode -eq 'Run' -and -not $OwnerApproved"),
                        src.index("Assert-RegularFile $path"))
        self.assertIn("[ValidateRange(2, 30)]", src)
        self.assertIn("[ValidateRange(0, 3)]", src)

    def test_pinned_loopback_and_restricted_ssh_options(self):
        src = self.code
        for required in (
            "'127.0.0.1:38183:172.29.251.2:3000'",
            "'hermes-h454-forward@111.88.215.204'",
            "'StrictHostKeyChecking=yes'", "'IdentitiesOnly=yes'",
            "'PasswordAuthentication=no'", "'KbdInteractiveAuthentication=no'",
            "'ExitOnForwardFailure=yes'", "'GatewayPorts=no'",
            "'ForwardAgent=no'", "'ServerAliveCountMax=3'",
            "'.ssh\\hermes_h454_verified_host_keys'",
            "'.ssh\\hermes_h454_native_read_ed25519'",
        ):
            with self.subTest(required=required):
                self.assertIn(required, src)
        self.assertIn("$request.Proxy = $null", src)
        self.assertIn("$request.AllowAutoRedirect = $false", src)

    def test_no_persistent_credentials_or_host_privileges(self):
        src = self.code.lower()
        for forbidden in (
            "register-scheduledtask", "set-scheduledtask", "sc.exe",
            "new-service", "-atstartup", "icacls.exe", "set-acl",
            "device_token", "/device/start", "/device/poll",
            "native_file_read", "-r ", "invoke-expression", "iex ",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, src)

    def test_no_cleanup_of_unowned_pid(self):
        src = self.code
        self.assertIn("H454_LOCAL_PORT_ALREADY_BOUND", src)
        self.assertIn("H454_UNOWNED_LISTENER_AFTER_DISCONNECT", src)
        self.assertIn("Test-OwnListener -ExpectedPid $child.Id", src)
        self.assertIn("$child.Kill()", src)
        self.assertIn("$child.Dispose()", src)
        self.assertIn("H454_REASON=", src)
        self.assertNotIn("Stop-Process", src)
        self.assertNotIn("taskkill.exe", src)

    def test_health_is_real_not_literal_pass(self):
        src = self.code
        self.assertIn("Test-RelayHealth", src)
        self.assertIn("[int]$response.StatusCode -ne 200", src)
        self.assertIn("$data.ok -eq $true", src)
        self.assertIn("$data.version -eq '2.0.2'", src)
        self.assertIn("$data.devices -ge 3", src)
        self.assertIn("$data = (-join $body", src)
        self.assertIn("throw 'H454_TUNNEL_NOT_HEALTHY'", src)
        self.assertIn("'H454_NATIVE_SSH_TUNNEL=REFUSED'", src)


if __name__ == "__main__":
    unittest.main()
