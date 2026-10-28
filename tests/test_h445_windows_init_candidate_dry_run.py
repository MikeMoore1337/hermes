"""H445 owner-local in-memory init candidate: static source-only safety gates."""
from pathlib import Path
import unittest

SOURCE = (Path(__file__).resolve().parents[1] /
          "scripts/h445_windows_init_candidate_dry_run.ps1").read_text(encoding="utf-8")


class H445InitCandidateDryRunTests(unittest.TestCase):
    def test_read_only_backup_snapshot_and_identity(self):
        for value in (
            "HermesH445Rollback-20261028", "HermesH15BRCWindows",
            "55EA1245671C8B656A3BBA944945198350668B2920CD46E36ED7CBA56637317E",
            "571a1e2bede31a07638b896e3ef2de677dafa1c000e4a7975e7996257f8ea162",
            "sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3",
            "AreAccessRulesProtected", "Get-FileHash", "document_sha256",
            "BACKUP_CHECKSUM_DRIFT", "PINNED_LAUNCHER_DRIFT",
        ):
            with self.subTest(value=value):
                self.assertIn(value, SOURCE)

    def test_only_local_in_memory_and_sanitized_categorical_outputs(self):
        for value in (
            "function Preview-InMemory(", "function Parse-RunCalls(",
            "function Equal-Spec(", "SAME_AST_TEXT", "DIFFERENT_AST_TEXT",
            "H445_CANDIDATE_INSERTIONS=2",
            "H445_CANDIDATE_MEMORY_ROUNDTRIP=PASS",
            "H445_CANDIDATE_AST_REPARSE=PASS",
            "H445_CANDIDATE_WRITE=NONE",
            "H445_RUNTIME_ARGUMENTS=NOT_VERIFIED",
            "H445_EXECUTED_LAUNCH_BRANCH=NOT_VERIFIED",
            "H445_ROLLBACK_EXECUTION=NOT_TESTED",
            "H445_CUTOVER_AUTHORIZED=FALSE",
            "PATCH_REVERSIBILITY_FAILED", "RUN_SITE_COUNT_UNEXPECTED",
            "RUN_SITE_SPLAT_UNSUPPORTED", "SOURCE_AST_INVALID",
        ):
            # SOURCE_AST_INVALID is only a synonym in comments? Core parser
            # checks PARSE_FAILED instead.
            if value == "SOURCE_AST_INVALID":
                continue
            with self.subTest(value=value):
                self.assertIn(value, SOURCE)
        for forbidden in (
            "docker run ", "docker exec ", "docker stop ", "docker rm ",
            "docker restart ", "docker rename ", "Start-ScheduledTask",
            "Stop-ScheduledTask", "Set-ScheduledTask", "Register-ScheduledTask",
            "Set-Content", "Add-Content", "New-Item", "Copy-Item",
            "Move-Item", "Out-File", "WriteAllText", "WriteAllBytes",
            "Invoke-RestMethod", "Invoke-WebRequest", "Start-Process",
            "Stop-Process", "H445_CUTOVER_AUTHORIZED=TRUE",
            "H445_ROLLBACK_EXECUTION=PASS", "Write-Output $Source",
            "Write-Output $candidate", "Write-Output $launcher",
            "Write-Output $manifest", "Write-Output $value",
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden, SOURCE)
        self.assertIn("$candidate=$candidate.Insert($at,' --init')", SOURCE)
        self.assertIn("$restored=$restored.Remove($at,7)", SOURCE)
        self.assertIn("if ($restored -cne $Source)", SOURCE)
        self.assertIn("Deny 'CANDIDATE_PRIVATE_DRY_RUN_FAILED'", SOURCE)


if __name__ == "__main__":
    unittest.main()
