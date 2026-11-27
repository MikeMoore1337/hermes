"""Exercise task-controller decisions with in-memory PowerShell task doubles."""
import base64
import os
from pathlib import Path
import subprocess
import unittest


class RegistrationTaskTests(unittest.TestCase):
    def _check_stop_start_and_wrong_action(self):
        script = Path(__file__).resolve().parents[1] / 'scripts' / 'h454_windows_personal_registration_task.ps1'
        source = r'''
$ErrorActionPreference = 'Stop'
$global:testState = 'Running'
function global:Get-ScheduledTask {
  [CmdletBinding()] param($TaskName,$TaskPath)
  [pscustomobject]@{ State=$global:testState; Settings=[pscustomobject]@{Enabled=$true};
    Actions=@([pscustomobject]@{Execute='C:\safe\pythonw.exe';Arguments='safe-args'});
    Triggers=@([pscustomobject]@{UserId='S-1-5-21-123'});
    Principal=[pscustomobject]@{UserId='S-1-5-21-123';LogonType='Interactive';RunLevel='Limited'} }
}
function global:Stop-ScheduledTask { [CmdletBinding()] param($TaskName,$TaskPath) $global:testState='Ready' }
function global:Start-ScheduledTask { [CmdletBinding()] param($TaskName,$TaskPath) $global:testState='Running' }
function global:Get-CimInstance { [CmdletBinding()] param([Parameter(Position=0)]$ClassName,$Filter) return @() }
function global:Start-Sleep { [CmdletBinding()] param($Milliseconds) }
try {
  $argsCommon = @{ExpectedExecutable='C:\safe\pythonw.exe';ExpectedArguments='safe-args';
    ExpectedSid='S-1-5-21-123';BootstrapDigest=('a'*64)}
  & $env:H454_TASK_TEST_FILE -Mode Check @argsCommon
  & $env:H454_TASK_TEST_FILE -Mode Stop @argsCommon
  if ($global:testState -ne 'Ready') { throw 'not stopped' }
  & $env:H454_TASK_TEST_FILE -Mode Start @argsCommon
  if ($global:testState -ne 'Running') { throw 'not started' }
  $argsCommon.ExpectedArguments='wrong'
  try { & $env:H454_TASK_TEST_FILE -Mode Stop @argsCommon; throw 'wrong task accepted' }
  catch { if ($_.Exception.Message -eq 'wrong task accepted') { throw } }
  if ($global:testState -ne 'Running') { throw 'wrong task changed' }
  Write-Output 'REGISTRATION_TASK_SYNTHETIC=PASS'
  exit 0
} catch { Write-Error $_; exit 1 }
'''
        env = os.environ.copy()
        env['H454_TASK_TEST_FILE'] = str(script)
        encoded = base64.b64encode(source.encode('utf-16-le')).decode('ascii')
        result = subprocess.run(['pwsh', '-NoProfile', '-NonInteractive', '-EncodedCommand', encoded],
            text=True, capture_output=True, env=env, timeout=30,
            creationflags=subprocess.CREATE_NO_WINDOW)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn('REGISTRATION_TASK_SYNTHETIC=PASS', result.stdout)


if os.name == 'nt':
    RegistrationTaskTests.test_check_stop_start_and_wrong_action = (
        RegistrationTaskTests._check_stop_start_and_wrong_action)


if __name__ == '__main__':
    unittest.main()
