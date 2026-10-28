"""H445 private launcher AST inventory: static no-mutation source contracts."""
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = (ROOT / "scripts/h445_windows_launcher_sites_inventory.ps1").read_text(encoding="utf-8")

class H445LauncherSitesInventoryTests(unittest.TestCase):
    def test_exact_snapshot_identity_and_hashes(self):
        for fragment in (
            "HermesH445Rollback-20261028",
            "HermesH15BRCWindows",
            "55EA1245671C8B656A3BBA944945198350668B2920CD46E36ED7CBA56637317E",
            "571a1e2bede31a07638b896e3ef2de677dafa1c000e4a7975e7996257f8ea162",
            "sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3",
            "AreAccessRulesProtected", "Get-FileHash", "BACKUP_CHECKSUM_MISMATCH",
            "PINNED_LAUNCHER_MISMATCH", "NO_DIRECT_DOCKER_RUN_SITE",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, SCRIPT)

    def test_categorical_output_only_and_no_execution(self):
        for fragment in (
            "H445_RUN_SITE_", "_CONTEXT=", "_CONDITIONAL=",
            "H445_RUN_SITE_RELATION=", "_NEAREST_IF=",
            "H445_RUN_SITE_PAIR_TRY_RELATION=", "_NEAREST_CONTROL=",
            "_ENCLOSING_TRY=", "_TRY_REGION=",
            "_NAME_FLAG=", "_MOUNT_FLAG=", "_ENV_FLAG=",
            "_INIT_FLAG=", "_RM_FLAG=", "_NETWORK_FLAG=",
            "_VARIABLE_ARGUMENT=", "_SPLAT=",
            "H445_EXECUTED_LAUNCH_BRANCH=NOT_VERIFIED",
            "H445_CUTOVER_AUTHORIZED=FALSE",
            "H445_ROLLBACK_EXECUTION=NOT_TESTED",
            "H445_SITES_STATIC_ONLY=TRUE",
            "RUN_SITE_LIMIT_EXCEEDED", "GetType().Name", "Find-RunSites",
            "Nearest-If", "If-Arm", "If-Relation",
            "Nearest-Control", "Nearest-Try", "Try-Region", "Try-Relation",
            "'TRY_BODY'", "'CATCH'", "'FINALLY'", "'SWITCH'",
            "'SAME_TRY'", "'ONE_ONLY'", "'DIFFERENT_TRY'",
            "'UNKNOWN'",
            "'EXCLUSIVE_IF_ARMS'", "'SAME_IF_ARM'", "'DIFFERENT_NEAREST_IF'",
            "return 'UNKNOWN'",
            "return 'YES'", "return 'NO'", "'FUNCTION'", "'TOP_LEVEL'",
        ):
            with self.subTest(fragment=fragment):
                self.assertIn(fragment, SCRIPT)
        for fragment in (
            "& $docker", "docker run ", "docker exec ", "docker stop ",
            "docker rm ", "docker restart ", "docker rename ",
            "Invoke-WebRequest", "Invoke-RestMethod", "Start-Process",
            "Stop-Process", "Start-ScheduledTask", "Set-ScheduledTask",
            "Register-ScheduledTask", "New-Item", "Set-Content",
            "Write-Output $launcherPath", "Write-Output $manifest",
            "Write-Output $arg", "Write-Output $Source",
            "H445_CUTOVER_AUTHORIZED=TRUE", "H445_ROLLBACK_EXECUTION=PASS",
        ):
            with self.subTest(forbidden=fragment):
                self.assertNotIn(fragment, SCRIPT)

    def test_avoid_revealing_ast_source_in_output(self):
        self.assertIn("function Find-RunSites([string]$Source)", SCRIPT)
        self.assertIn("if ($sites.Count -ge 12)", SCRIPT)
        self.assertIn("ReadAllText($launcherPath)", SCRIPT)
        self.assertIn("if ($literal -ceq '--init')", SCRIPT)
        self.assertIn("Write-Output ($prefix+'_INIT_FLAG='+$site.Init)", SCRIPT)
        self.assertNotIn("Write-Output $literal", SCRIPT)
        self.assertNotIn("Write-Output $exe", SCRIPT)
        self.assertNotIn("Write-Output $verb", SCRIPT)
        self.assertIn("Deny 'PRIVATE_AST_DIAGNOSTIC_FAILED'", SCRIPT)

if __name__ == "__main__":
    unittest.main()
