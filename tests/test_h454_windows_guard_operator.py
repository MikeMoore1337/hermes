"""The guard operator must reject unsafe entry before touching the host."""
import os
import base64
from pathlib import Path
import subprocess
import unittest


if os.name == 'nt':
    class GuardOperatorBoundaryTests(unittest.TestCase):
        def test_wss_health_child_is_hidden_and_bounded(self):
            powershell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
            source = Path(__file__).resolve().parents[1] / 'scripts/h454_windows_guard_operator.ps1'
            script = r'''
$ErrorActionPreference = 'Stop'
$tokens=$null; $errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($env:H454_TEST_SOURCE,[ref]$tokens,[ref]$errors)
$matches=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Test-H454HiddenWssHealth'},$true))
if(@($errors).Count -ne 0 -or $matches.Count -ne 1){throw 'HEALTH_FUNCTION_MISSING'}
function Require-H454([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
. ([scriptblock]::Create($matches[0].Extent.Text))
$dir=Join-Path $env:TEMP ('h454-hidden-test-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $dir
$exe=Join-Path $dir 'fixture.exe'
try {
    $src=@'
using System;
using System.Runtime.InteropServices;
public class TestCurl {
  [DllImport("kernel32.dll")] static extern IntPtr GetConsoleWindow();
  [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
  public static int Main(string[] args) {
    var window = GetConsoleWindow();
    if (window != IntPtr.Zero && IsWindowVisible(window)) return 8;
    int index = Array.IndexOf(args, "--cacert");
    if (index < 0 || index + 1 >= args.Length ||
        Array.IndexOf(args, "brc-agent.internal:38184:127.0.0.1") < 0 ||
        Array.IndexOf(args, "https://brc-agent.internal:38184/") < 0) return 9;
    if (args[index + 1].EndsWith("slow.pem")) System.Threading.Thread.Sleep(12000);
    Console.Write(args[index + 1].EndsWith("good.pem") ? "404" : "200");
    return 0;
  }
}
'@
    Add-Type -TypeDefinition $src -OutputAssembly $exe -OutputType ConsoleApplication
    if(-not (Test-H454HiddenWssHealth $exe 'C:\fixture folder\good.pem')){throw 'HIDDEN_HEALTH_FAILED'}
    if(Test-H454HiddenWssHealth $exe 'C:\fixture folder\bad.pem'){throw 'WRONG_STATUS_ACCEPTED'}
    if(Test-H454HiddenWssHealth $exe 'C:\fixture folder\slow.pem'){throw 'TIMEOUT_ACCEPTED'}
    try { $null=Test-H454HiddenWssHealth $exe 'C:\fixture"bad.pem'; throw 'BAD_PATH_ACCEPTED' }
    catch { if($_.Exception.Message -eq 'BAD_PATH_ACCEPTED'){throw} }
    'H454_HIDDEN_HEALTH=PASS'
} finally {
    if(Test-Path -LiteralPath $exe){Remove-Item -LiteralPath $exe -Force}
    [IO.Directory]::Delete($dir)
}
'''
            encoded = base64.b64encode(script.encode('utf-16le')).decode('ascii')
            result = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
                                    env={**os.environ, 'H454_TEST_SOURCE': str(source)},
                                    capture_output=True, text=True, timeout=25,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('H454_HIDDEN_HEALTH=PASS', result.stdout)

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
                                  (['-OwnerApproved', '-RestoreOriginal', '-BeginBrokerTrial', '-CandidateSourceSha256', 'F' * 64,
                                    '-CandidateImageId', 'sha256:' + 'a' * 64, '-TrialSourceSha256', 'F' * 64,
                                    '-CandidateId', 'b' * 64, '-WindowStartUtc', '2030-01-02T01:02:03+03:00',
                                    '-WindowEndUtc', '2030-01-02T02:02:03Z'], 'H454_TRIAL_WINDOW'),
                                  (['-OwnerApproved', '-RestoreOriginal', '-BeginBrokerTrial', '-CandidateSourceSha256', 'F' * 64,
                                    '-CandidateImageId', 'sha256:' + 'a' * 64, '-TrialSourceSha256', 'F' * 64,
                                    '-CandidateId', 'b' * 64, '-WindowStartUtc', '2030-02-30T01:02:03Z',
                                    '-WindowEndUtc', '2030-03-01T02:02:03Z'], 'H454_TRIAL_WINDOW'),
                                  (['-OwnerApproved', '-RestoreOriginal', '-BeginBrokerTrial', '-CandidateSourceSha256', 'F' * 64,
                                    '-CandidateImageId', 'sha256:' + 'a' * 64, '-TrialSourceSha256', 'F' * 64,
                                    '-CandidateId', 'b' * 64, '-WindowStartUtc', '2030-01-02T01:02:03Z',
                                    '-WindowEndUtc', '2030-01-02T02:02:03Z'], 'H454_GUARD_OPERATOR_MONITOR_PINS'),
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
