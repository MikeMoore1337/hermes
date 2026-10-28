"""Source-only fail-closed contracts: read-only private Windows restore evidence."""
from pathlib import Path
import unittest

ROOT=Path(__file__).resolve().parents[1]
SOURCE=(ROOT/"scripts/h445_windows_restore_readiness.ps1").read_text(encoding="utf-8")

class H445RestoreReadinessTests(unittest.TestCase):
    def test_fixed_private_evidence_and_exact_target(self):
        for expected in (
            'HermesH445Rollback-20261028',
            'HermesH15BRCWindows',
            '571a1e2bede31a07638b896e3ef2de677dafa1c000e4a7975e7996257f8ea162',
            'sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3',
            '55EA1245671C8B656A3BBA944945198350668B2920CD46E36ED7CBA56637317E',
            'Get-FileHash', 'container-inspect.json', 'scheduled-task.xml',
            'manifest.json', "'container','inspect'" if False else 'container inspect $cid',
            'Compare-Section', "Compare-Section $saved $live 'Config'",
            "Compare-Section $saved $live 'HostConfig'",
            "Compare-Section $saved $live 'Mounts'",
            'Export-ScheduledTask', 'Get-Acl',
        ):
            with self.subTest(expected=expected):
                self.assertIn(expected,SOURCE)

    def test_never_mutates_or_prints_private_data(self):
        for forbidden in (
            'docker run', 'docker stop', 'docker restart', 'docker rm', 'docker exec',
            'Stop-Process', 'Start-Process', 'Start-ScheduledTask',
            'Register-ScheduledTask', 'Set-ScheduledTask',
            'New-Item', 'Copy-Item', 'Set-Content',
            'Write-Output $raw', 'Write-Output $saved',
            'Write-Output $savedTask', 'Write-Output $_',
            'H445_ROLLBACK_EXECUTION=PASS',
            'H445_MOUNT_REATTACH=PASS',
            'H445_DEVICE_IDENTITY_REATTACH=PASS',
        ):
            with self.subTest(forbidden=forbidden):
                self.assertNotIn(forbidden,SOURCE)
        for status in (
            'H445_RESTORE_READINESS=SNAPSHOT_CONSISTENT',
            'H445_ROLLBACK_EXECUTION=NOT_TESTED',
            'H445_MOUNT_REATTACH=NOT_VERIFIED',
            'H445_DEVICE_IDENTITY_REATTACH=NOT_VERIFIED',
            'H445_ORIGINAL_CONTAINER_CHANGED=FALSE',
        ):
            self.assertIn(status,SOURCE)

    def test_private_paths_not_in_receipt_and_bounded_input(self):
        self.assertIn('Private-File',SOURCE)
        self.assertIn('2097152',SOURCE)
        self.assertIn("H445_REASON='+$Code",SOURCE)
        self.assertIn('EVIDENCE_READ_OR_COMPARE_FAILED',SOURCE)
        self.assertIn('BACKUP_HASH_MISMATCH',SOURCE)
        self.assertIn('SECTION_CHANGED',SOURCE)
        self.assertIn('if (-not $acl.AreAccessRulesProtected)',SOURCE)
        self.assertIn('S-1-5-18',SOURCE)
        self.assertIn('S-1-5-32-544',SOURCE)

if __name__=='__main__':
    unittest.main()
