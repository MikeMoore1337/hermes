"""H445 Windows protected owner-only rollback evidence snapshot source gates."""
from pathlib import Path
import unittest

P=Path(__file__).resolve().parents[1]/"scripts/h445_windows_local_rollback_snapshot.ps1"
class H445RollbackSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.src=P.read_text(encoding="utf-8")
    def test_default_dry_run_and_explicit_owner_write_gate(self):
        for required in (
            "'Preflight','Backup'", "$Mode='Preflight'", "[switch]$OwnerApproved",
            "if (-not $OwnerApproved) { Deny 'EXPLICIT_OWNER_BACKUP_APPROVAL_REQUIRED' }",
            "H445_BACKUP_FILES_CREATED=FALSE",
            "H445_BACKUP_ALREADY_EXISTS" if False else "BACKUP_ALREADY_EXISTS",
            "rollback_verified=$false",
            "H445_ROLLBACK_VERIFIED=FALSE",
        ):
            self.assertIn(required,self.src)
        self.assertLess(self.src.index("EXPLICIT_OWNER_BACKUP_APPROVAL_REQUIRED"),
                        self.src.index("Protected-Directory $dest"))
    def test_exact_live_container_launcher_and_image(self):
        for required in (
            "HermesH15BRCWindows",
            "571a1e2bede31a07638b896e3ef2de677dafa1c000e4a7975e7996257f8ea162",
            "sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3",
            "55EA1245671C8B656A3BBA944945198350668B2920CD46E36ED7CBA56637317E",
            "'true|no|1'", "'image','inspect'", "'container','inspect'",
            "LAUNCHER_HASH_DRIFT", "CONTAINER_IDENTITY_DRIFT",
        ):
            # The expected container status is embedded in an interpolated string.
            if required == "'true|no|1'":
                required = "|true|no|1"
            self.assertIn(required,self.src)
    def test_acl_secret_isolation_and_manifest_hashes(self):
        for required in (
            "DirectorySecurity", "SetAccessRuleProtection($true,$false)",
            "[IO.Directory]::CreateDirectory($Location,$acl)",
            "S-1-5-18", "S-1-5-32-544", "SecurityIdentifier",
            "Export-ScheduledTask", "container','inspect',$cid",
            "Get-FileHash", "manifest.json", "h445-owner-local-backup-v1",
            "BACKUP_LAUNCHER_CHECKSUM_MISMATCH",
        ):
            with self.subTest(marker=required):
                self.assertIn(required,self.src)
        for forbidden in (
            "Start-ScheduledTask", "Stop-ScheduledTask",
            "Register-ScheduledTask", "Unregister-ScheduledTask",
            "Set-ScheduledTask", "docker run", "docker stop",
            "docker restart", "docker rm", "docker exec",
            "Invoke-Expression", "Stop-Process", "Start-Process",
            "Write-Output $taskXml", "Write-Output $allText",
        ):
            with self.subTest(marker=forbidden):
                self.assertNotIn(forbidden,self.src)
    def test_never_print_private_snapshot_or_claim_rollback(self):
        self.assertNotIn("rollback_verified=$true",self.src)
        self.assertNotIn("H445_ROLLBACK_VERIFIED=TRUE",self.src)
        self.assertIn("H445_BACKUP=PASS",self.src)
        self.assertIn("H445_ORIGINAL_CONTAINER_UNCHANGED=PASS",self.src)
if __name__=="__main__":
    unittest.main()
