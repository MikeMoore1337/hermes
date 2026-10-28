"""Fail-closed source contracts for read-only Windows Docker host inventory (#445).

No live host invocation, no credentials or Docker mutation. The Windows CI
workflow additionally parses PowerShell and verifies invalid IDs fail before
the executable can be invoked.
"""
from pathlib import Path
import unittest

TARGET = Path(__file__).resolve().parents[1] / "scripts/h445_windows_docker_inventory.ps1"


class H445ReadOnlyHostInventoryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.script = TARGET.read_text(encoding="utf-8")

    def test_exact_container_id_required_for_inspect(self):
        p = self.script
        self.assertIn("^[a-f0-9]{64}$", p)
        self.assertIn("H445_FULL_CONTAINER_ID_REQUIRED", p)
        self.assertLess(p.index("H445_FULL_CONTAINER_ID_REQUIRED"),
                        p.index("'container', 'inspect'"))
        self.assertIn("$id -cne $ContainerId", p)

    def test_only_readonly_docker_calls_and_pinned_executable(self):
        p = self.script
        self.assertIn("Docker\\Docker\\resources\\bin\\docker.exe", p)
        self.assertIn("PSIsContainer", p)
        self.assertIn("ReparsePoint", p)
        self.assertIn("'ps', '-a', '--no-trunc', '--format'", p)
        self.assertIn("'container', 'inspect', '--format'", p)
        for illegal in (
            "'exec'", "'run'", "'restart'", "'stop'", "'kill'",
            "'rm'", "'cp'", "'start'", "'update'", "'commit'", "'pull'",
            "Start-Process", "Invoke-Expression", "iex ", "Remove-Item",
            "Set-Acl", "docker inspect --", "docker.exe -H",
        ):
            with self.subTest(illegal=illegal):
                self.assertNotIn(illegal, p)

    def test_inspect_minimizes_secrets(self):
        p = self.script
        # The mandatory metadata template must not dereference optional Init.
        self.assertIn("{{.HostConfig.Init}}", p)
        self.assertIn("$fmt = '{{.Id}}|", p)
        mandatory = p.split("$fmt = '", 1)[1].split("'", 1)[0]
        self.assertNotIn("HostConfig.Init", mandatory)
        self.assertIn("{{.HostConfig.PidsLimit}}", mandatory)
        self.assertIn("'container', 'inspect', '--format', '{{.HostConfig.Init}}', $ContainerId", p)
        self.assertIn("try {\n        $optional = @(", p)
        self.assertIn("Normalize-InitValue -Raw $optional", p)
        self.assertIn("$init = 'UNAVAILABLE'", p)
        self.assertIn("init_probe_status = $initProbeStatus", p)
        self.assertIn("suspected_process_reaping_risk = $initRisk", p)
        self.assertIn("else { $null }", p)
        self.assertIn("{{.HostConfig.PidsLimit}}", p)
        self.assertIn("{{.HostConfig.Memory}}", p)
        self.assertIn("{{len .Mounts}}", p)
        self.assertIn("{{.Config.User}}", p)
        for forbidden in (
            "docker inspect --format '{{json .}}'",
            "Get-Content", "Secret", "Password", ".Config.Env",
            "HostConfig.Binds", "{{json .Mounts}}", "inspect --format '{{json",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, p)

    def test_no_authorization_is_implied(self):
        p = self.script
        for marker in (
            "HOST_INSPECTED_IDENTITY_NOT_ATTESTED",
            "CANDIDATES_NOT_VERIFIED",
            "suspected_process_reaping_risk",
            "target_device_verified = $false",
            "rollback_verified = $false",
            "host_change_authorized = $false",
            "changes_applied = $false",
            "H445_DOCKER_INSPECTION_UNAVAILABLE",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, p)

    def test_sanitized_nonverbose_failure(self):
        p = self.script
        self.assertIn("Write-Output ('H445_REASON=' + $Code)", p)
        self.assertIn("Deny 'H445_DOCKER_INSPECTION_UNAVAILABLE'", p)
        self.assertIn("$LASTEXITCODE -ne 0", p)
        self.assertNotIn("Write-Error $_", p)
        self.assertNotIn("Get-ChildItem Env:", p)


if __name__ == "__main__":
    unittest.main()
