# Owner-triggered Windows boot-time presence agent with least-privilege LocalService.
# Requires elevated PowerShell and a MACHINE-WIDE Python installation.
# No Windows login, stored password, public WSS port or command execution.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Prepare','Enable','Status','Rollback')]
    [string] $Mode,
    [string] $MachinePython = ''
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$taskName = 'HermesDevicePresence'
$source = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.hermes-device'
$state = Join-Path $env:ProgramData 'HermesDevicePresence'
$venvPython = Join-Path $state '.venv\Scripts\python.exe'

$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principalCheck = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principalCheck.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw 'OWNER_ADMIN_REQUIRED'
}

function Require-File([string] $path) {
    $item = Get-Item -LiteralPath $path -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'INVALID_SOURCE_FILE'
    }
}

switch ($Mode) {
    Prepare {
        if (Test-Path -LiteralPath $state) {
            throw 'STATE_EXISTS_MANUAL_REVIEW_REQUIRED'
        }
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            throw 'TASK_EXISTS_MANUAL_REVIEW_REQUIRED'
        }
        if (-not [IO.Path]::IsPathRooted($MachinePython) -or
            [IO.Path]::GetFileName($MachinePython) -ne 'python.exe') {
            throw 'MACHINE_PYTHON_PATH_REQUIRED'
        }
        Require-File $MachinePython
        Require-File (Join-Path $source 'windows-pc.json')
        Require-File (Join-Path $source 'device_fabric\device_agent.py')
        $key = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\hermes_presence_ed25519'
        $known = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\hermes_presence_known_hosts'
        Require-File $key
        Require-File $known

        New-Item -ItemType Directory -Path $state -ErrorAction Stop | Out-Null
        Copy-Item -LiteralPath (Join-Path $source 'device_fabric') -Destination (Join-Path $state 'device_fabric') -Recurse
        Copy-Item -LiteralPath (Join-Path $source 'windows-pc.json') -Destination $state
        Copy-Item -LiteralPath $key -Destination (Join-Path $state 'hermes_presence_ed25519')
        Copy-Item -LiteralPath $known -Destination (Join-Path $state 'hermes_presence_known_hosts')

        & $MachinePython -m venv (Join-Path $state '.venv')
        if ($LASTEXITCODE -ne 0) { throw 'VENV_CREATION_FAILED' }
        & $venvPython -m pip install --isolated --no-input --only-binary=:all: --no-deps 'websockets==16.0'
        if ($LASTEXITCODE -ne 0) { throw 'WEBSOCKETS_SETUP_FAILED' }
        & $venvPython -c 'import websockets; assert websockets.__version__ == "16.0"'
        if ($LASTEXITCODE -ne 0) { throw 'WEBSOCKETS_VERSION_INVALID' }

        # SIDs are language-neutral. No Users or Everyone permissions; the
        # running LocalService principal has read/execute but not write access.
        & icacls.exe $state /inheritance:r /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)RX' /T | Out-Null
        if ($LASTEXITCODE -ne 0) { throw 'PRIVATE_ACL_FAILED' }

        $arguments = '-m device_fabric.device_agent --config "' + $state + '\windows-pc.json" --watch ' +
          '--ssh-host 111.88.215.204 --ssh-user hermes-presence-tunnel ' +
          '--ssh-key "' + $state + '\hermes_presence_ed25519" ' +
          '--known-hosts "' + $state + '\hermes_presence_known_hosts" --ssh-bin ssh.exe'

        $taskAction = New-ScheduledTaskAction -Execute $venvPython -Argument $arguments -WorkingDirectory $state
        $trigger = New-ScheduledTaskTrigger -AtStartup
        $taskPrincipal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\LOCAL SERVICE' -LogonType ServiceAccount -RunLevel Limited
        $settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew -StartWhenAvailable `
            -RestartInterval (New-TimeSpan -Minutes 2) -RestartCount 999 `
            -ExecutionTimeLimit (New-TimeSpan -Seconds 0) `
            -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
        Register-ScheduledTask -TaskName $taskName -Action $taskAction -Principal $taskPrincipal `
            -Trigger $trigger -Settings $settings `
            -Description 'Hermes read-only SSH/WSS presence; owner-gated, no remote tools' | Out-Null
        Disable-ScheduledTask -TaskName $taskName | Out-Null
        Write-Output 'WINDOWS_PERSISTENCE=PREPARED'
        Write-Output 'AUTOSTART=NOT_ENABLED'
    }
    Enable {
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
        if ($task.Principal.UserId -notin @('NT AUTHORITY\LOCAL SERVICE','S-1-5-19')) {
            throw 'TASK_IDENTITY_MISMATCH'
        }
        Enable-ScheduledTask -TaskName $taskName | Out-Null
        Start-ScheduledTask -TaskName $taskName
        Write-Output 'WINDOWS_PERSISTENCE=ENABLED'
    }
    Status {
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
        $info = Get-ScheduledTaskInfo -TaskName $taskName
        Write-Output "WINDOWS_TASK_STATE=$($task.State)"
        Write-Output "WINDOWS_LAST_RESULT=$($info.LastTaskResult)"
        Write-Output "WINDOWS_PRINCIPAL=$($task.Principal.UserId)"
    }
    Rollback {
        $task = Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        if ($task) {
            Disable-ScheduledTask -TaskName $taskName | Out-Null
            Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
        }
        # Secrets and enrolment are intentionally retained for controlled re-use.
        Write-Output 'WINDOWS_PERSISTENCE=DISABLED'
        Write-Output 'STATE_AND_ENROLLMENT=PRESERVED'
    }
}
