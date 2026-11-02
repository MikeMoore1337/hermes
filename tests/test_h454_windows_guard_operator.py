"""The guard operator must reject unsafe entry before touching the host."""
import os
from pathlib import Path
import subprocess
import unittest


if os.name == 'nt':
    class GuardOperatorBoundaryTests(unittest.TestCase):
        def test_apply_requires_approval_and_pinned_sources(self):
            powershell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
            source = Path(__file__).resolve().parents[1] / 'scripts/h454_windows_guard_operator.ps1'
            arguments = [str(powershell), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', str(source),
                         '-OriginalLauncherSha256', 'A' * 64, '-GuardedLauncherSha256', 'B' * 64,
                         '-BackupName', 'h454-original-launcher-' + 'a' * 32 + '.txt',
                         '-TaskBackupName', 'h454-legacy-task-' + 'b' * 32 + '.xml',
                         '-TaskBackupSha256', 'C' * 64, '-TaskSourceSha256', 'D' * 64,
                         '-RecoverySourceSha256', 'E' * 64, '-Apply']
            for extra, reason in (([], 'H454_GUARD_OPERATOR_APPROVAL'),
                                  (['-OwnerApproved'], 'H454_GUARD_OPERATOR_SOURCE'),
                                  (['-OwnerApproved', '-StartWss'], 'H454_GUARD_OPERATOR_WSS_MODE'),
                                  (['-OwnerApproved', '-RestageOnly'], 'H454_GUARD_OPERATOR_MONITOR_MODE'),
                                  (['-OwnerApproved', '-InstallBrokerMonitor'], 'H454_GUARD_OPERATOR_MONITOR_MODE'),
                                  (['-OwnerApproved', '-PrepareBrokerCandidate'], 'H454_GUARD_OPERATOR_CANDIDATE_MODE'),
                                  (['-OwnerApproved', '-BeginBrokerTrial'], 'H454_GUARD_OPERATOR_TRIAL_MODE'),
                                  (['-OwnerApproved', '-OriginalMcpObserved'], 'H454_GUARD_OPERATOR_TRIAL_MODE'),
                                  (['-OwnerApproved', '-RestoreOriginal', '-CompleteBrokerTrial'], 'H454_TRIAL_MCP_ACKNOWLEDGMENT'),
                                  (['-OwnerApproved', '-RestoreOriginal', '-BeginBrokerTrial', '-RecoverBrokerTrial'], 'H454_GUARD_OPERATOR_TRIAL_MODE'),
                                  (['-OwnerApproved', '-RestoreOriginal', '-RecoverBrokerTrial', '-RestageOnly'], 'H454_GUARD_OPERATOR_TRIAL_MODE'),
                                  (['-OwnerApproved', '-RestoreOriginal', '-BeginBrokerTrial'], 'H454_GUARD_OPERATOR_CANDIDATE_PINS'),
                                  (['-OwnerApproved', '-RestoreOriginal', '-BeginBrokerTrial', '-CandidateSourceSha256', 'F' * 64,
                                    '-CandidateImageId', 'sha256:' + 'a' * 64], 'H454_GUARD_OPERATOR_TRIAL_PINS'),
                                  (['-OwnerApproved', '-RestoreOriginal', '-RecoverBrokerTrial', '-CandidateSourceSha256', 'F' * 64,
                                    '-CandidateImageId', 'sha256:' + 'a' * 64, '-TrialSourceSha256', 'F' * 64,
                                    '-CandidateId', 'b' * 64], 'H454_GUARD_OPERATOR_MONITOR_PINS'),
                                  (['-OwnerApproved', '-RestoreOriginal', '-PrepareBrokerCandidate'], 'H454_GUARD_OPERATOR_CANDIDATE_PINS'),
                                  (['-OwnerApproved', '-RestoreOriginal', '-PrepareBrokerCandidate', '-RestageOnly'], 'H454_GUARD_OPERATOR_CANDIDATE_MODE'),
                                  (['-OwnerApproved', '-RestoreOriginal', '-PrepareBrokerCandidate', '-CandidateSourceSha256', 'F' * 64,
                                    '-CandidateImageId', 'sha256:' + 'a' * 64], 'H454_GUARD_OPERATOR_MONITOR_PINS'),
                                  (['-OwnerApproved', '-RestoreOriginal', '-RestageOnly'], 'H454_GUARD_OPERATOR_MONITOR_PINS'),
                                  (['-OwnerApproved', '-RestoreOriginal', '-InstallBrokerMonitor'], 'H454_GUARD_OPERATOR_MONITOR_PINS'),
                                  (['-OwnerApproved', '-CheckOriginal'], 'H454_GUARD_OPERATOR_ORIGINAL_MODE'),
                                  (['-OwnerApproved', '-PrepareRecoveryRoute'], 'H454_GUARD_OPERATOR_ORIGINAL_MODE'),
                                  (['-OwnerApproved', '-PrepareRecoveryBroker'], 'H454_GUARD_OPERATOR_ORIGINAL_MODE'),
                                  (['-OwnerApproved', '-RestoreOriginal'], 'H454_GUARD_OPERATOR_ORIGINAL_MODE'),
                                  (['-OwnerApproved', '-PrepareRecoveryRoute', '-OriginalProfileSourceSha256', 'F' * 64,
                                    '-RecoveryDockerSourceSha256', 'F' * 64, '-DockerSha256', 'F' * 64], 'H454_GUARD_OPERATOR_ROUTE_PINS'),
                                  (['-OwnerApproved', '-PrepareRecoveryRoute', '-PrepareRecoveryBroker',
                                    '-OriginalProfileSourceSha256', 'F' * 64, '-RecoveryDockerSourceSha256', 'F' * 64,
                                    '-DockerSha256', 'F' * 64], 'H454_GUARD_OPERATOR_ORIGINAL_MODE'),
                                  (['-OwnerApproved', '-PrepareRecoveryBroker', '-OriginalProfileSourceSha256', 'F' * 64,
                                    '-RecoveryDockerSourceSha256', 'F' * 64, '-DockerSha256', 'F' * 64,
                                    '-RecoveryRouteSourceSha256', 'F' * 64, '-NetworkGuardSourceSha256', 'F' * 64,
                                    '-WssConfigSha256', 'F' * 64, '-SupervisorSha256', 'F' * 64, '-CaSha256', 'F' * 64,
                                    '-CurlSha256', 'F' * 64, '-ProxyImageId', 'sha256:' + 'a' * 64],
                                   'H454_GUARD_OPERATOR_BROKER_PINS'),
                                  (['-OwnerApproved', '-RestoreOriginal', '-OriginalProfileSourceSha256', 'F' * 64,
                                    '-RecoveryDockerSourceSha256', 'F' * 64, '-DockerSha256', 'F' * 64,
                                    '-RecoveryRouteSourceSha256', 'F' * 64, '-NetworkGuardSourceSha256', 'F' * 64,
                                    '-WssConfigSha256', 'F' * 64, '-SupervisorSha256', 'F' * 64, '-CaSha256', 'F' * 64,
                                    '-CurlSha256', 'F' * 64, '-ProxyImageId', 'sha256:' + 'a' * 64,
                                    '-BrokerImageId', 'sha256:' + 'b' * 64], 'H454_GUARD_OPERATOR_RESTORE_PINS'),
                                  (['-OwnerApproved', '-PrepareWss'], 'H454_GUARD_OPERATOR_WSS_PINS')):
                with self.subTest(reason=reason):
                    result = subprocess.run(arguments + extra, capture_output=True, text=True, timeout=10,
                                            creationflags=subprocess.CREATE_NO_WINDOW)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertIn('H454_GUARD_OPERATOR_REASON=' + reason, result.stdout)


if __name__ == '__main__':
    unittest.main()
