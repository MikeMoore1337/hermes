"""Offline source security contracts for H445 read-only init cutover gate."""
from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]
SOURCE = (ROOT / "scripts/h445_windows_init_cutover_preflight.ps1").read_text(encoding="utf-8")

class H445InitCutoverPreflightTests(unittest.TestCase):
    def test_pinned_identity_and_protected_evidence(self):
        for marker in (
            "HermesH445Rollback-20261028",
            "HermesH15BRCWindows",
            "571a1e2bede31a07638b896e3ef2de677dafa1c000e4a7975e7996257f8ea162",
            "sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3",
            "55EA1245671C8B656A3BBA944945198350668B2920CD46E36ED7CBA56637317E",
            "AreAccessRulesProtected", "Get-FileHash",
            "Match-Section $saved $live 'Config'",
            "Match-Section $saved $live 'HostConfig'",
            "Match-Section $saved $live 'Mounts'",
            "Export-ScheduledTask", "Inspect-RunStructure",
            "LAUNCHER_AST_REQUIRES_MANUAL_REVIEW",
            "SECURITY_OR_IDENTITY_MATERIAL_DRIFT",
        ):
            with self.subTest(marker=marker):
                self.assertIn(marker, SOURCE)

    def test_is_read_only_and_no_private_output(self):
        for forbidden in (
            "Start-ScheduledTask", "Stop-ScheduledTask",
            "Register-ScheduledTask", "Set-ScheduledTask",
            "Set-Content", "Add-Content", "New-Item",
            "docker run --init", "docker stop ", "docker rm ",
            "docker restart ", "docker exec ", "docker create ",
            "docker rename ", "Start-Process", "Stop-Process",
            "Write-Output $raw", "Write-Output $live",
            "Write-Output $saved", "Write-Output $_",
            "H445_ROLLBACK_EXECUTION=PASS",
            "H445_DEVICE_IDENTITY_REATTACH=PASS",
            "H445_CUTOVER_AUTHORIZED=TRUE",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, SOURCE)
        self.assertIn("H445_CUTOVER_AUTHORIZED=FALSE", SOURCE)
        self.assertIn("H445_ROLLBACK_EXECUTION=NOT_TESTED", SOURCE)
        self.assertIn("H445_ORIGINAL_CONTAINER_CHANGED=FALSE", SOURCE)
        self.assertIn("MANUAL_REVIEW_REQUIRED", SOURCE)

    def test_no_remote_or_secret_exfiltration(self):
        for item in ("Invoke-WebRequest", "Invoke-RestMethod",
                     "Start-BitsTransfer", "Send-MailMessage",
                     "Set-Clipboard", "ConvertTo-SecureString",
                     "Get-Credential"):
            self.assertNotIn(item, SOURCE)
        self.assertIn("SNAPSHOT_HASH_DRIFT", SOURCE)
        self.assertIn("TASK_LAUNCHER_CHANGED", SOURCE)
        self.assertIn("SOURCE_AST_INVALID", SOURCE)
        self.assertRegex(SOURCE, r"if \(\$structure\.DockerRunSites -ne 1")

if __name__ == "__main__":
    unittest.main()
