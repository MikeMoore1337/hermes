# Owner-triggered Windows boot-time presence agent with least-privilege LocalService.
# Requires elevated PowerShell and a trusted owner Python 3.14, copied to
# a private machine-local runtime so LocalService needs NO user profile access.
# No Windows login, stored password, public WSS port or command execution.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Prepare','Repair','Enable','Status','Rollback')]
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

function Protect-PrivateState([string] $directory) {
    # Windows icacls processes /inheritance:r and /grant:r differently when
    # passed in one recursive invocation: parent grants can survive while
    # descendants become empty-DACL and unreadable (observed in owner pilot).
    # Always do these as TWO operations across the same subtree.
    & icacls.exe $directory /inheritance:r /T | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'PRIVATE_ACL_INHERITANCE_FAILED' }
    & icacls.exe $directory /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' '*S-1-5-19:(OI)(CI)RX' /T | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'PRIVATE_ACL_GRANT_FAILED' }
}

# A prior failed Prepare can contain secrets before task registration.
# Only an explicit Repair can re-use this pinned private staging directory.
switch ($Mode) {
    { $_ -eq 'Prepare' -or $_ -eq 'Repair' } {
        $repair = $Mode -eq 'Repair'
        if ($repair) {
            if (-not (Test-Path -LiteralPath $state)) {
                throw 'REPAIR_STATE_MISSING'
            }
            $existing = Get-Item -LiteralPath $state -Force
            if (-not $existing.PSIsContainer -or
                ($existing.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'REPAIR_UNTRUSTED_STATE'
            }
            Protect-PrivateState $state
        } elseif (Test-Path -LiteralPath $state) {
            throw 'STATE_EXISTS_USE_REPAIR_AFTER_ACL_REVIEW'
        }
        if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
            throw 'TASK_EXISTS_MANUAL_REVIEW_REQUIRED'
        }
        if (-not [IO.Path]::IsPathRooted($MachinePython) -or
            [IO.Path]::GetFileName($MachinePython) -ne 'python.exe') {
            throw 'MACHINE_PYTHON_PATH_REQUIRED'
        }
        # Only trust the owner's installed CPython or Program Files Python,
        # never an arbitrary binary from Downloads, TEMP or untrusted share.
        $pythonPath = [IO.Path]::GetFullPath($MachinePython)
        $userPython = [IO.Path]::GetFullPath(
            (Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'Programs\Python')
        ).TrimEnd('\') + '\'
        $systemPython = [IO.Path]::GetFullPath($env:ProgramFiles).TrimEnd('\') + '\'
        if (-not ($pythonPath.StartsWith($userPython, [StringComparison]::OrdinalIgnoreCase) -or
                  $pythonPath.StartsWith($systemPython, [StringComparison]::OrdinalIgnoreCase))) {
            throw 'UNTRUSTED_PYTHON_LOCATION'
        }
        Require-File $MachinePython
        & $MachinePython -I -c 'import sys; assert sys.version_info[:2] == (3,14)'
        if ($LASTEXITCODE -ne 0) { throw 'PYTHON_VERSION_NOT_SUPPORTED' }
        $pythonRoot = Split-Path -Parent $pythonPath
        foreach ($directory in @($pythonRoot, (Join-Path $pythonRoot 'Lib'),
                                  (Join-Path $pythonRoot 'DLLs'))) {
            $entry = Get-Item -LiteralPath $directory -Force -ErrorAction Stop
            if (-not $entry.PSIsContainer -or
                ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'UNTRUSTED_PYTHON_DIRECTORY'
            }
        }
        foreach ($name in @('python314.dll', 'python.exe')) {
            Require-File (Join-Path $pythonRoot $name)
        }
        Require-File (Join-Path $source 'windows-pc.json')
        Require-File (Join-Path $source 'device_fabric\device_agent.py')
        $key = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\hermes_presence_ed25519'
        $known = Join-Path ([Environment]::GetFolderPath('UserProfile')) '.ssh\hermes_presence_known_hosts'
        Require-File $key
        Require-File $known
        $ssh = Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'
        Require-File $ssh

        if (-not $repair) {
            New-Item -ItemType Directory -Path $state -ErrorAction Stop | Out-Null
        }

        # CRITICAL: protect ProgramData BEFORE copying tokens and private SSH
        # keys or installing wheels, including all existing files on Repair.
        # Applying ACLs only after pip is unsafe if preparation fails mid-way.
        Protect-PrivateState $state

        # Copy only the CPython runtime, NEVER the user's site-packages or
        # Scripts. The service's venv points at this ProgramData copy and
        # therefore remains usable before the owner signs in after reboot.
        $runtime = Join-Path $state 'python-runtime'
        $runtimePython = Join-Path $runtime 'python.exe'
        if (Test-Path -LiteralPath $runtime) {
            $runtimeInfo = Get-Item -LiteralPath $runtime -Force
            if (-not $runtimeInfo.PSIsContainer -or
                ($runtimeInfo.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'UNTRUSTED_STAGED_RUNTIME'
            }
        } else {
            New-Item -ItemType Directory -Path $runtime -ErrorAction Stop | Out-Null
        }
        foreach ($name in @('python.exe', 'python314.dll', 'python3.dll',
                             'vcruntime140.dll', 'vcruntime140_1.dll',
                             'python314.zip')) {
            $src = Join-Path $pythonRoot $name
            if (Test-Path -LiteralPath $src) {
                Require-File $src
                Copy-Item -LiteralPath $src -Destination (Join-Path $runtime $name) -Force
            }
        }
        foreach ($folder in @('Lib', 'DLLs')) {
            $src = Join-Path $pythonRoot $folder
            $dst = Join-Path $runtime $folder
            New-Item -ItemType Directory -Path $dst -Force | Out-Null
            $exclude = @()
            if ($folder -eq 'Lib') {
                $exclude = @('/XD', (Join-Path $src 'site-packages'))
            }
            # Robocopy skips junctions and symlinks (/XJ) and never uses MIR.
            # Exit 0..7 is success/extra files; 8+ indicates an actual failure.
            & robocopy.exe $src $dst /E /XJ /R:0 /W:0 /NFL /NDL /NJH /NJS /NP @exclude | Out-Null
            if ($LASTEXITCODE -ge 8) { throw 'PYTHON_RUNTIME_COPY_FAILED' }
        }
        # This validation exercises SSL/socket/venv imports from a copy
        # that does NOT have access to per-user third-party site-packages.
        & $runtimePython -I -c 'import ssl, socket, venv, ensurepip'
        if ($LASTEXITCODE -ne 0) { throw 'ISOLATED_PYTHON_RUNTIME_INVALID' }
        Protect-PrivateState $state

        if ($repair) {
            # No overwrites or imports from an unknown staging directory.
            # Exact content comparison prevents accidental reuse of modified
            # tokens, host keys, or unsigned copied source after a partial run.
            foreach ($pair in @(
                @((Join-Path $source 'windows-pc.json'), (Join-Path $state 'windows-pc.json')),
                @($key, (Join-Path $state 'hermes_presence_ed25519')),
                @($known, (Join-Path $state 'hermes_presence_known_hosts')),
                @((Join-Path $source 'device_fabric\device_agent.py'), (Join-Path $state 'device_fabric\device_agent.py'))
            )) {
                Require-File $pair[1]
                # Fail on the FIRST unreadable source/staged file. Native
                # Get-FileHash without ErrorAction Stop writes a nonterminating
                # access-denied error, then StrictMode reports a misleading
                # missing Hash property. Do not skip this identity check.
                try {
                    $expected = (Get-FileHash -LiteralPath $pair[0] -Algorithm SHA256 -ErrorAction Stop).Hash
                    $actual = (Get-FileHash -LiteralPath $pair[1] -Algorithm SHA256 -ErrorAction Stop).Hash
                } catch {
                    throw 'REPAIR_HASH_ACCESS_OR_IO_FAILED'
                }
                if ($actual -ne $expected) { throw 'REPAIR_SOURCE_MISMATCH' }
            }
            $venv = Join-Path $state '.venv'
            $venvInfo = Get-Item -LiteralPath $venv -Force -ErrorAction Stop
            if (-not $venvInfo.PSIsContainer -or
                ($venvInfo.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
                throw 'REPAIR_UNTRUSTED_VENV'
            }
            # Incomplete venv is rebuilt against the isolated staged runtime.
            & $runtimePython -I -m venv --clear $venv
        } else {
            Copy-Item -LiteralPath (Join-Path $source 'device_fabric') -Destination (Join-Path $state 'device_fabric') -Recurse
            Copy-Item -LiteralPath (Join-Path $source 'windows-pc.json') -Destination $state
            Copy-Item -LiteralPath $key -Destination (Join-Path $state 'hermes_presence_ed25519')
            Copy-Item -LiteralPath $known -Destination (Join-Path $state 'hermes_presence_known_hosts')
            & $runtimePython -I -m venv (Join-Path $state '.venv')
        }
        if ($LASTEXITCODE -ne 0) { throw 'VENV_CREATION_FAILED' }
        # Verify the venv's sys.base_prefix resolves under private ProgramData
        # rather than relying on the user-profile Python at boot.
        $cfg = Get-Content -LiteralPath (Join-Path $state '.venv\pyvenv.cfg') -Raw
        if (-not $cfg.Contains($runtime)) { throw 'VENV_HOME_OUTSIDE_STATE' }
        & $venvPython -m pip install --isolated --no-input --only-binary=:all: --no-deps 'websockets==16.0'
        if ($LASTEXITCODE -ne 0) { throw 'WEBSOCKETS_SETUP_FAILED' }
        # PowerShell 5.1 strips inner double-quotes when passing -c to a
        # native Windows executable; compare against str(16.0) instead.
        & $venvPython -c 'import websockets; assert websockets.__version__ == str(16.0)'
        if ($LASTEXITCODE -ne 0) { throw 'WEBSOCKETS_VERSION_INVALID' }

        # Re-apply restricted ACLs to files created by venv/pip.
        Protect-PrivateState $state

        $arguments = '-m device_fabric.device_agent --config "' + $state + '\windows-pc.json" --watch ' +
          '--ssh-host 111.88.215.204 --ssh-user hermes-presence-tunnel ' +
          '--ssh-key "' + $state + '\hermes_presence_ed25519" ' +
          '--known-hosts "' + $state + '\hermes_presence_known_hosts" --ssh-bin "' + $ssh + '"'

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
