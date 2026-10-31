#requires -Version 5.1
# Dot-source only from the owner-approved operator which owns runtime.lock.
$script:h454RecoveryOwnedLock=$null
function Open-H454RecoveryLock([string]$StateDir) {
    Require-H454 ($null -eq $script:h454RecoveryOwnedLock) 'RECOVERY_LOCK_ALREADY_OPEN'
    Assert-H454PrivateAcl $StateDir
    $lockPath=Join-Path $StateDir 'runtime.lock'
    $count=0
    foreach($entry in [IO.Directory]::EnumerateFileSystemEntries($StateDir)){
        $count++;Require-H454 ($count -le 512) 'RECOVERY_STATE_DIRECTORY_OVERSIZE'
        if([IO.Path]::GetFileName($entry).Equals('runtime.lock',[StringComparison]::OrdinalIgnoreCase)){
            Assert-H454PrivateAcl $entry
        }
    }
    $stream=[IO.File]::Open($lockPath,[IO.FileMode]::OpenOrCreate,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try { Assert-H454PrivateAcl $lockPath } catch { $stream.Dispose();throw }
    $script:h454RecoveryOwnedLock=$stream
    return $stream
}

function Close-H454RecoveryLock([IO.FileStream]$Lock) {
    Require-H454 ($null -ne $Lock -and [Object]::ReferenceEquals($Lock,$script:h454RecoveryOwnedLock)) 'RECOVERY_LOCK'
    $Lock.Dispose();$script:h454RecoveryOwnedLock=$null
}

function Assert-H454RecoveryLock([string]$StateDir,[IO.FileStream]$Lock) {
    Assert-H454PrivateAcl $StateDir
    $lockPath=Join-Path $StateDir 'runtime.lock'
    Assert-H454PrivateAcl $lockPath
    Require-H454 ($null -ne $Lock -and [Object]::ReferenceEquals($Lock,$script:h454RecoveryOwnedLock) -and $Lock.CanWrite -and
        [IO.Path]::GetFullPath($Lock.Name) -ieq [IO.Path]::GetFullPath($lockPath)) 'RECOVERY_LOCK'
    $other=$null;$exclusive=$false
    try { $other=[IO.File]::Open($lockPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite) }
    catch {
        $errorValue=$_.Exception
        if($errorValue -is [Management.Automation.MethodInvocationException]){$errorValue=$errorValue.InnerException}
        if($errorValue -is [IO.IOException] -and ($errorValue.HResult -band 0xffff) -eq 32){$exclusive=$true}
        else{throw 'RECOVERY_LOCK_CHECK'}
    } finally { if($null -ne $other){$other.Dispose()} }
    Require-H454 $exclusive 'RECOVERY_LOCK_NOT_EXCLUSIVE'
}

function New-H454TransitionMarker([string]$StateDir,[byte[]]$Bytes,[IO.FileStream]$Lock) {
    Assert-H454RecoveryLock $StateDir $Lock
    Require-H454 ($null -ne $Bytes -and $Bytes.Length -gt 0 -and $Bytes.Length -le 4096) 'RECOVERY_MARKER_SIZE'
    $marker=Join-Path $StateDir 'h454-wss-transition.pending'
    $count=0
    foreach($entry in [IO.Directory]::EnumerateFileSystemEntries($StateDir)){
        $count++;Require-H454 ($count -le 512) 'RECOVERY_STATE_DIRECTORY_OVERSIZE'
        Require-H454 (-not [IO.Path]::GetFileName($entry).Equals('h454-wss-transition.pending',[StringComparison]::OrdinalIgnoreCase)) 'RECOVERY_MARKER_OCCUPIED'
    }
    $pending=Join-Path $StateDir ('h454-journal-'+[Guid]::NewGuid().ToString('N')+'.new')
    $stream=[IO.File]::Open($pending,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
    Assert-H454PrivateAcl $pending
    Require-H454 ((Get-FileHash -LiteralPath $pending -Algorithm SHA256).Hash -ceq (Hash-H454Bytes $Bytes)) 'RECOVERY_MARKER_DRIFT'
    [IO.File]::Move($pending,$marker)
    Assert-H454PrivateAcl $marker
    $digest=(Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash
    Require-H454 ($digest -ceq (Hash-H454Bytes $Bytes)) 'RECOVERY_MARKER_DRIFT'
    return $digest
}

function Set-H454RecoveredFile([string]$Target,[byte[]]$Bytes,[string]$ExpectedHash,
                               [string]$StateDir,[string]$RunDir) {
    Assert-H454PrivateAcl $Target
    Require-H454 ((Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash -ceq $ExpectedHash) 'RECOVERY_FILE_DRIFT'
    $suffix=[Guid]::NewGuid().ToString('N')
    $pending=Join-Path $StateDir ('h454-recover-'+$suffix+'.new')
    $backup=Join-Path $RunDir ('h454-recover-'+$suffix+'.backup')
    Require-H454 (-not (Test-Path -LiteralPath $backup)) 'RECOVERY_BACKUP_OCCUPIED'
    $stream=[IO.File]::Open($pending,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try { $stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true) } finally { $stream.Dispose() }
    Assert-H454PrivateAcl $pending
    Require-H454 ((Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash -ceq $ExpectedHash) 'RECOVERY_FILE_DRIFT'
    [IO.File]::Replace($pending,$Target,$backup)
    Assert-H454PrivateAcl $Target
    Require-H454 ((Get-FileHash -LiteralPath $Target -Algorithm SHA256).Hash -ceq (Hash-H454Bytes $Bytes)) 'RECOVERY_FILE_REPLACE'
}

function Repair-H454OfflineControl([string]$StateDir,[string]$RunDir,[IO.FileStream]$Lock,[hashtable]$Pins) {
    $required=@('OriginalId','CandidateId','OriginalImage','CandidateImage','LiveName','CandidateName','BackupName',
        'OldStateHash','NewStateHash','GuardOldHash','GuardNewHash','MarkerHash')
    Require-H454 ($Pins.Count -eq $required.Count) 'RECOVERY_PINS'
    foreach($key in $required){Require-H454 ($Pins.ContainsKey($key) -and $Pins[$key] -is [string]) 'RECOVERY_PINS'}
    foreach($key in @('OldStateHash','NewStateHash','GuardOldHash','GuardNewHash','MarkerHash')){
        Require-H454 ($Pins[$key] -cmatch '^[A-F0-9]{64}$') 'RECOVERY_PINS'
    }
    foreach($key in @('OriginalId','CandidateId')){Require-H454 ($Pins[$key] -cmatch '^[a-f0-9]{64}$') 'RECOVERY_PINS'}
    foreach($key in @('OriginalImage','CandidateImage')){Require-H454 ($Pins[$key] -cmatch '^sha256:[a-f0-9]{64}$') 'RECOVERY_PINS'}
    foreach($key in @('LiveName','CandidateName','BackupName')){Require-H454 ($Pins[$key] -cmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,127}$') 'RECOVERY_PINS'}
    Require-H454 ($Pins.OriginalId -cne $Pins.CandidateId -and $Pins.OriginalImage -cne $Pins.CandidateImage -and
        $Pins.OldStateHash -cne $Pins.NewStateHash -and $Pins.GuardOldHash -cne $Pins.GuardNewHash -and
        @( @($Pins.LiveName,$Pins.CandidateName,$Pins.BackupName) | Select-Object -Unique).Count -eq 3) 'RECOVERY_PINS'
    Assert-H454PrivateAcl $RunDir
    Assert-H454RecoveryLock $StateDir $Lock
    $marker=Join-Path $StateDir 'h454-wss-transition.pending'
    $state=Join-Path $StateDir 'agent-state.json'
    $launcher=Join-Path $StateDir 'Hermes-H15-Windows-Permanent.ps1'
    $stateBackup=Join-Path $RunDir 'agent-state.json'
    $launcherBackup=Join-Path $RunDir 'launcher-guarded-old.ps1'
    foreach($path in @($marker,$state,$launcher,$stateBackup,$launcherBackup)){Assert-H454PrivateAcl $path}
    foreach($path in @($state,$stateBackup)){
        Require-H454 ((Get-Item -LiteralPath $path).Length -le 65536) 'RECOVERY_FILE_SIZE'
    }
    foreach($path in @($launcher,$launcherBackup)){
        Require-H454 ((Get-Item -LiteralPath $path).Length -le 1048576) 'RECOVERY_FILE_SIZE'
    }
    Require-H454 ((Get-Item -LiteralPath $marker).Length -le 4096) 'RECOVERY_FILE_SIZE'
    Require-H454 ((Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash -ceq $Pins.MarkerHash) 'RECOVERY_MARKER_DRIFT'
    $oldState=[IO.File]::ReadAllBytes($stateBackup);$oldLauncher=[IO.File]::ReadAllBytes($launcherBackup)
    Require-H454 ((Hash-H454Bytes $oldState) -ceq $Pins.OldStateHash -and
        (Hash-H454Bytes $oldLauncher) -ceq $Pins.GuardOldHash) 'RECOVERY_BACKUP_DRIFT'
    $stateHash=(Get-FileHash -LiteralPath $state -Algorithm SHA256).Hash
    $launcherHash=(Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash
    Require-H454 ($stateHash -cin @($Pins.OldStateHash,$Pins.NewStateHash) -and
        $launcherHash -cin @($Pins.GuardOldHash,$Pins.GuardNewHash)) 'RECOVERY_CONTROL_DRIFT'
    $original=Get-H454Container $Pins.OriginalId;$candidate=Get-H454Container $Pins.CandidateId
    foreach($item in @($original,$candidate)){
        Require-H454 ($item.State.Running -is [bool] -and -not $item.State.Running -and
            $item.State.Paused -is [bool] -and -not $item.State.Paused -and
            $item.State.Restarting -is [bool] -and -not $item.State.Restarting -and
            $item.State.Dead -is [bool] -and -not $item.State.Dead -and
            $item.State.Status -cin @('exited','created')) 'RECOVERY_CONTAINER_NOT_STOPPED'
    }
    Require-H454 ($original.Id -ceq $Pins.OriginalId -and $candidate.Id -ceq $Pins.CandidateId -and
        $original.Image -ceq $Pins.OriginalImage -and $candidate.Image -ceq $Pins.CandidateImage -and
        $original.Name -cin @(('/'+$Pins.LiveName),('/'+$Pins.BackupName)) -and
        $candidate.Name -cin @(('/'+$Pins.LiveName),('/'+$Pins.CandidateName)) -and
        $original.Name -cne $candidate.Name) 'RECOVERY_CONTAINER_DRIFT'
    if($stateHash -cne $Pins.OldStateHash){Set-H454RecoveredFile $state $oldState $stateHash $StateDir $RunDir}
    if($launcherHash -cne $Pins.GuardOldHash){Set-H454RecoveredFile $launcher $oldLauncher $launcherHash $StateDir $RunDir}
    Require-H454 ((Get-FileHash -LiteralPath $marker -Algorithm SHA256).Hash -ceq $Pins.MarkerHash -and
        (Get-FileHash -LiteralPath $state -Algorithm SHA256).Hash -ceq $Pins.OldStateHash -and
        (Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash -ceq $Pins.GuardOldHash) 'RECOVERY_FINAL_DRIFT'
    return 'RECOVERED_OFFLINE_START_BLOCKED'
}
