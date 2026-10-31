#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$Source,[Parameter(Mandatory=$true)][string]$GuardPath,
      [Parameter(Mandatory=$true)][string]$FixtureParent,[string]$Fixture='',[switch]$CrashChild)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
. $Source
function Require-H454([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
function Require([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
function Hash-H454Bytes([byte[]]$Bytes){
    $hash=[Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($hash.ComputeHash($Bytes))).Replace('-','')}finally{$hash.Dispose()}
}
$parent=[IO.Path]::GetFullPath($FixtureParent)
if(-not $CrashChild){
    Require-H454 ($Fixture -ceq '') 'FIXTURE_MUST_BE_NEW'
    $Fixture=Join-Path $parent ('recovery-fixture-'+[Guid]::NewGuid().ToString('N'))
}
$Fixture=[IO.Path]::GetFullPath($Fixture)
Require-H454 ($Fixture.StartsWith($parent+'\',[StringComparison]::OrdinalIgnoreCase) -and
    [IO.Path]::GetFileName($Fixture) -cmatch '^recovery-fixture-[a-f0-9]{32}$') 'FIXTURE_SCOPE'
if(-not $CrashChild){
    Require-H454 (-not [IO.Directory]::Exists($Fixture) -and -not [IO.File]::Exists($Fixture)) 'FIXTURE_OCCUPIED'
    [IO.Directory]::CreateDirectory($Fixture)|Out-Null
}else{Require-H454 ([IO.Directory]::Exists($Fixture)) 'FIXTURE_MISSING'}
$stateDir=Join-Path $Fixture 'state';$runDir=Join-Path $Fixture 'snapshot'
if(-not $CrashChild){[IO.Directory]::CreateDirectory($stateDir)|Out-Null;[IO.Directory]::CreateDirectory($runDir)|Out-Null}
function Assert-H454PrivateAcl([string]$Path){
    $absolute=[IO.Path]::GetFullPath($Path)
    Require-H454 ($absolute.StartsWith($Fixture+'\',[StringComparison]::OrdinalIgnoreCase)) 'FIXTURE_PATH'
    $item=Get-Item -LiteralPath $absolute -Force
    Require-H454 (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'FIXTURE_REPARSE'
}
$oldState=[Text.Encoding]::UTF8.GetBytes('old-state');$newState=[Text.Encoding]::UTF8.GetBytes('new-state')
$guardOld=[Text.Encoding]::UTF8.GetBytes('guard-old');$guardNew=[Text.Encoding]::UTF8.GetBytes('guard-new')
$markerBytes=[Text.Encoding]::UTF8.GetBytes('synthetic-journal-v1')
$pins=@{OriginalId=('a'*64);CandidateId=('b'*64);OriginalImage=('sha256:'+('c'*64));CandidateImage=('sha256:'+('d'*64));
    LiveName='fixture-live';CandidateName='fixture-candidate';BackupName='fixture-backup';
    OldStateHash=(Hash-H454Bytes $oldState);NewStateHash=(Hash-H454Bytes $newState);
    GuardOldHash=(Hash-H454Bytes $guardOld);GuardNewHash=(Hash-H454Bytes $guardNew);MarkerHash=(Hash-H454Bytes $markerBytes)}
$script:containers=@{}
function Set-FixtureContainers {
    $script:containers=@{}
    $script:containers[$pins.OriginalId]=[pscustomobject]@{Id=$pins.OriginalId;Image=$pins.OriginalImage;Name='/fixture-backup';
        State=[pscustomobject]@{Running=$false;Paused=$false;Restarting=$false;Dead=$false;Status='exited'}}
    $script:containers[$pins.CandidateId]=[pscustomobject]@{Id=$pins.CandidateId;Image=$pins.CandidateImage;Name='/fixture-live';
        State=[pscustomobject]@{Running=$false;Paused=$false;Restarting=$false;Dead=$false;Status='exited'}}
}
function Get-H454Container([string]$Id){Require-H454 ($script:containers.ContainsKey($Id)) 'FIXTURE_CONTAINER';return $script:containers[$Id]}
$lockPath=Join-Path $stateDir 'runtime.lock';$marker=Join-Path $stateDir 'h454-wss-transition.pending'
$STATE_PATH=Join-Path $stateDir 'agent-state.json';$launcher=Join-Path $stateDir 'Hermes-H15-Windows-Permanent.ps1'
function Reset-Fixture {
    [IO.File]::WriteAllBytes($STATE_PATH,$newState);[IO.File]::WriteAllBytes($launcher,$guardNew)
    [IO.File]::WriteAllBytes($marker,$markerBytes);[IO.File]::WriteAllBytes((Join-Path $runDir 'agent-state.json'),$oldState)
    [IO.File]::WriteAllBytes((Join-Path $runDir 'launcher-guarded-old.ps1'),$guardOld)
    Set-FixtureContainers
}

if($CrashChild){
    Set-FixtureContainers
    $lock=Open-H454RecoveryLock $stateDir
    $setter=(Get-Item Function:\Set-H454RecoveredFile).ScriptBlock
    function Set-H454RecoveredFile([string]$Target,[byte[]]$Bytes,[string]$ExpectedHash,[string]$StateDir,[string]$RunDir){
        & $setter $Target $Bytes $ExpectedHash $StateDir $RunDir
        [Environment]::Exit(73)
    }
    $null=Repair-H454OfflineControl $stateDir $runDir $lock $pins
    throw 'CRASH_FIXTURE_DID_NOT_EXIT'
}

$lock=$null
try {
    Reset-Fixture
    $lock=Open-H454RecoveryLock $stateDir
    [IO.File]::Delete($marker)
    Require-H454 ((New-H454TransitionMarker $stateDir $markerBytes $lock) -ceq $pins.MarkerHash) 'MARKER_CREATE'
    $refused=$false;try { $null=New-H454TransitionMarker $stateDir $markerBytes $lock } catch { $refused=$true }
    Require-H454 ($refused -and (Get-FileHash $marker).Hash -ceq $pins.MarkerHash) 'MARKER_OVERWRITE'
    . (Join-Path $PSScriptRoot 'h454_windows_cutover_engine.ps1')
    $integration=[pscustomobject]@{Events=[Collections.Generic.List[string]]::new();Staged=$false;Smoke=$false}
    $actions=@{
        VerifyRollbackState={Require-H454 ([IO.File]::Exists($marker)) 'INTEGRATION_MARKER';$true}
        StopCandidate={Require-H454 (-not $script:containers[$pins.CandidateId].State.Running) 'INTEGRATION_CANDIDATE';$true}
        RestoreControls={
            $integration.Events.Add('restore')
            if(-not $script:containers[$pins.OriginalId].State.Running){
                Require-H454 ((Repair-H454OfflineControl $stateDir $runDir $lock $pins) -ceq 'RECOVERED_OFFLINE_START_BLOCKED') 'INTEGRATION_RESTORE'
            }else{
                Require-H454 ((Get-FileHash $STATE_PATH).Hash -ceq $pins.OldStateHash -and
                    (Get-FileHash $launcher).Hash -ceq $pins.GuardOldHash) 'INTEGRATION_RUNNING_CONTROL_DRIFT'
            }
            $true
        }
        ReactivateOriginal={
            $integration.Events.Add('start')
            Require-H454 ((Get-FileHash $STATE_PATH).Hash -ceq $pins.OldStateHash -and
                (Get-FileHash $launcher).Hash -ceq $pins.GuardOldHash -and [IO.File]::Exists($marker)) 'INTEGRATION_START_ORDER'
            if($script:containers[$pins.OriginalId].State.Running){'ALREADY_STAGED_VERIFIED'}else{
                $script:containers[$pins.OriginalId].State.Running=$true
                $script:containers[$pins.OriginalId].State.Status='running'
                'RESTAGE_REQUIRED'
            }
        }
        StageOriginal={$integration.Events.Add('stage');$integration.Staged=$true;$true}
        ConfirmOriginalMcp={Require-H454 ($integration.Staged -and [IO.File]::Exists($marker)) 'INTEGRATION_SMOKE';$integration.Smoke=$true;$true}
        VerifyRecovery={Require-H454 ($integration.Smoke -and [IO.File]::Exists($marker)) 'INTEGRATION_FINAL';$true}
    }
    $result=Invoke-H454RecoveryEngine $stateDir $lock $actions -OwnerApproved
    Require-H454 ($result.Status -ceq 'ROLLBACK_VERIFIED_PENDING' -and
        ($integration.Events -join ',') -ceq 'restore,start,stage' -and [IO.File]::Exists($marker)) 'INTEGRATION_ROLLBACK'
    $integration.Events.Clear()
    $result=Invoke-H454RecoveryEngine $stateDir $lock $actions -OwnerApproved
    Require-H454 ($result.Status -ceq 'ROLLBACK_VERIFIED_PENDING' -and
        ($integration.Events -join ',') -ceq 'restore,start') 'INTEGRATION_REPEAT'
    [IO.File]::WriteAllBytes($launcher,$guardNew)
    $integration.Events.Clear()
    $result=Invoke-H454RecoveryEngine $stateDir $lock $actions -OwnerApproved
    Require-H454 ($result.Status -ceq 'ROLLBACK_HOLD' -and $result.Phase -ceq 'RestoreControls' -and
        ($integration.Events -join ',') -ceq 'restore' -and (Get-FileHash $launcher).Hash -ceq $pins.GuardNewHash -and
        [IO.File]::Exists($marker)) 'INTEGRATION_RUNNING_DRIFT'
    Reset-Fixture
    foreach($stateBytes in @($oldState,$newState)){
        foreach($launcherBytes in @($guardOld,$guardNew)){
            [IO.File]::WriteAllBytes($STATE_PATH,$stateBytes);[IO.File]::WriteAllBytes($launcher,$launcherBytes)
            Require-H454 ((Repair-H454OfflineControl $stateDir $runDir $lock $pins) -ceq 'RECOVERED_OFFLINE_START_BLOCKED') 'RECOVERY_RESULT'
            Require-H454 ((Get-FileHash $STATE_PATH).Hash -ceq $pins.OldStateHash -and
                (Get-FileHash $launcher).Hash -ceq $pins.GuardOldHash -and [IO.File]::Exists($marker)) 'RECOVERY_CONTENT'
            $null=Repair-H454OfflineControl $stateDir $runDir $lock $pins
        }
    }
    $guard=[scriptblock]::Create([IO.File]::ReadAllText($GuardPath))
    $blocked=$false;try { & $guard } catch { $blocked=$_.Exception.Message -match 'H454_RECOVERY_REQUIRED' }
    Require-H454 $blocked 'LAUNCH_NOT_BLOCKED'
    foreach($case in @('marker','missing-marker','state','oversize','launcher','backup','original-running','candidate-running','restarting','image','name')){
        Reset-Fixture
        switch($case){
            'marker'{[IO.File]::WriteAllText($marker,'foreign')}
            'missing-marker'{[IO.File]::Delete($marker)}
            'state'{[IO.File]::WriteAllText($STATE_PATH,'foreign')}
            'oversize'{[IO.File]::WriteAllBytes($STATE_PATH,[byte[]]::new(65537))}
            'launcher'{[IO.File]::WriteAllText($launcher,'foreign')}
            'backup'{[IO.File]::WriteAllText((Join-Path $runDir 'agent-state.json'),'foreign')}
            'original-running'{$script:containers[$pins.OriginalId].State.Running=$true}
            'candidate-running'{$script:containers[$pins.CandidateId].State.Running=$true}
            'restarting'{$script:containers[$pins.CandidateId].State.Restarting=$true}
            'image'{$script:containers[$pins.CandidateId].Image='sha256:'+('e'*64)}
            'name'{$script:containers[$pins.CandidateId].Name='/foreign'}
        }
        $beforeState=(Get-FileHash $STATE_PATH).Hash;$beforeLauncher=(Get-FileHash $launcher).Hash
        $refused=$false;try { $null=Repair-H454OfflineControl $stateDir $runDir $lock $pins } catch { $refused=$true }
        Require-H454 ($refused -and (Get-FileHash $STATE_PATH).Hash -ceq $beforeState -and
            (Get-FileHash $launcher).Hash -ceq $beforeLauncher) 'DRIFT_NOT_REFUSED'
    }
    Reset-Fixture
    $wrongPath=Join-Path $stateDir 'wrong-fixture.lock'
    $wrongLock=[IO.File]::Open($wrongPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        $refused=$false;try { $null=Repair-H454OfflineControl $stateDir $runDir $wrongLock $pins } catch { $refused=$true }
        Require-H454 ($refused -and (Get-FileHash $STATE_PATH).Hash -ceq $pins.NewStateHash) 'WRONG_LOCK_NOT_REFUSED'
    } finally { $wrongLock.Dispose();[IO.File]::Delete($wrongPath) }
    Close-H454RecoveryLock $lock
    $lock=[IO.File]::Open($lockPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)
    $refused=$false;try { $null=Repair-H454OfflineControl $stateDir $runDir $lock $pins } catch { $refused=$_.Exception.Message -match 'RECOVERY_LOCK' }
    Require-H454 ($refused -and (Get-FileHash $STATE_PATH).Hash -ceq $pins.NewStateHash) 'SHARED_LOCK_NOT_REFUSED'
    $lock.Dispose();$lock=Open-H454RecoveryLock $stateDir
    Reset-Fixture
    Close-H454RecoveryLock $lock;$lock=$null
    $exe=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $arguments=@('-NoProfile','-NonInteractive','-File',('"'+$PSCommandPath+'"'),'-Source',('"'+$Source+'"'),
        '-GuardPath',('"'+$GuardPath+'"'),'-FixtureParent',('"'+$parent+'"'),'-Fixture',('"'+$Fixture+'"'),'-CrashChild')
    $child=Start-Process -FilePath $exe -ArgumentList $arguments -PassThru -WindowStyle Hidden
    if(-not $child.WaitForExit(15000)){$child.Kill();throw 'CRASH_CHILD_TIMEOUT'}
    Require-H454 ($child.ExitCode -eq 73) 'CRASH_CHILD_FAILED'
    Require-H454 ((Get-FileHash $STATE_PATH).Hash -ceq $pins.OldStateHash -and
        (Get-FileHash $launcher).Hash -ceq $pins.GuardNewHash -and [IO.File]::Exists($marker)) 'CRASH_INTERMEDIATE'
    $lock=Open-H454RecoveryLock $stateDir
    $null=Repair-H454OfflineControl $stateDir $runDir $lock $pins
    Require-H454 ((Get-FileHash $launcher).Hash -ceq $pins.GuardOldHash -and [IO.File]::Exists($marker)) 'CRASH_RECOVERY'
    'PS51_RECOVERY_INTERMEDIATE_AND_PROCESS_TERMINATION=PASS'
} finally {
    if($null -ne $lock){
        if([Object]::ReferenceEquals($lock,$script:h454RecoveryOwnedLock)){Close-H454RecoveryLock $lock}else{$lock.Dispose()}
    }
    foreach($dir in @($stateDir,$runDir)){
        if([IO.Directory]::Exists($dir)){
            foreach($item in Get-ChildItem -LiteralPath $dir -File -Force){
                Require-H454 (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
                    ($item.Name -cin @('runtime.lock','h454-wss-transition.pending','agent-state.json',
                        'Hermes-H15-Windows-Permanent.ps1','launcher-guarded-old.ps1') -or
                     $item.Name -cmatch '^h454-(recover|journal)-[a-f0-9]{32}\.(new|backup)$')) 'FIXTURE_UNKNOWN'
                [IO.File]::Delete($item.FullName)
            }
            [IO.Directory]::Delete($dir)
        }
    }
    if([IO.Directory]::Exists($Fixture)){[IO.Directory]::Delete($Fixture)}
}
