#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$Source,[Parameter(Mandatory=$true)][string]$FixtureParent)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. $Source
function Require-H454([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
function Assert-H454RecoveryLock([string]$StateDir,[IO.FileStream]$Lock){
    Require-H454 ([Object]::ReferenceEquals($Lock,$script:ownedLock) -and $Lock.CanWrite -and
        [IO.Path]::GetDirectoryName($Lock.Name) -ceq $StateDir) 'FIXTURE_LOCK'
    $other=$null;$denied=$false
    try{$other=[IO.File]::Open($Lock.Name,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::ReadWrite)}
    catch{$denied=$true}finally{if($null -ne $other){$other.Dispose()}}
    Require-H454 $denied 'FIXTURE_LOCK_NOT_EXCLUSIVE'
}
$names=@('Preflight','Snapshot','InstallGuard','WriteMarker','RecheckBeforeStop',
    'StopOriginal','ActivateCandidate','StageCandidate','ConfirmCandidateMcp',
    'CommitLauncher','CommitState','VerifyCommit','ClearMarker',
    'VerifyRollbackState','StopCandidate','RestoreControls','ReactivateOriginal','StageOriginal',
    'ConfirmOriginalMcp','VerifyRecovery')
function MakeAction([string]$Name,[object]$Context){
    return {
        $Context.Events.Add($Name)
        if($Context.Case -ceq $Name){
            if($Name -cin @('Preflight','Snapshot','InstallGuard','WriteMarker','RecheckBeforeStop')){throw 'FIXTURE_FAILURE'}
            return 'FAILED_SETTLED'
        }
        if($Context.Case -ceq 'candidate-result-false' -and $Name -ceq 'StageCandidate'){return $false}
        if($Context.Case -ceq 'candidate-result-empty' -and $Name -ceq 'StageCandidate'){return}
        switch($Name){
            'InstallGuard' {$Context.Guard=$true;if($Context.Case -ceq 'guard-after'){throw 'FIXTURE_GUARD_INTERRUPTED'}}
            'WriteMarker' {Require-H454 $Context.Guard 'FIXTURE_GUARD_ORDER';$Context.Marker=$true;if($Context.Case -ceq 'marker-after'){throw 'FIXTURE_MARKER_INTERRUPTED'}}
            'RecheckBeforeStop' {Require-H454 ($Context.Guard -and $Context.Marker -and $Context.Original) 'FIXTURE_STOP_GATE'}
            'StopOriginal' {
                if($Context.Case -ceq 'stop-before'){return 'FAILED_SETTLED'}
                if($Context.Case -ceq 'stop-ambiguous-before'){throw 'FIXTURE_STOP_UNKNOWN'}
                $Context.Original=$false
                if($Context.Case -ceq 'stop-after'){return 'FAILED_SETTLED'}
                if($Context.Case -ceq 'stop-ambiguous-after'){throw 'FIXTURE_STOP_UNKNOWN'}
                if($Context.Case -ceq 'lock-lost'){$Context.Lock.Dispose()}
            }
            'ActivateCandidate' {Require-H454 (-not $Context.Original) 'FIXTURE_TWO_AGENTS';$Context.Candidate=$true}
            'StageCandidate' {Require-H454 $Context.Candidate 'FIXTURE_CANDIDATE_NOT_RUNNING';$Context.CandidateStaged=$true}
            'ConfirmCandidateMcp' {
                Require-H454 ($Context.CandidateStaged -and $Context.Marker) 'FIXTURE_CANDIDATE_SMOKE'
                if($Context.Case -cin @('rollback-stop','rollback-reactivate-invalid','rollback-stage','rollback-smoke','rollback-controls','rollback-verify')){return 'FAILED_SETTLED'}
                $Context.CandidateSmoke=$true
            }
            'CommitLauncher' {Require-H454 $Context.CandidateSmoke 'FIXTURE_SMOKE_ORDER';$Context.Launcher=$true}
            'CommitState' {Require-H454 $Context.Launcher 'FIXTURE_LAUNCHER_ORDER';$Context.State=$true}
            'VerifyCommit' {Require-H454 ($Context.State -and $Context.Marker) 'FIXTURE_COMMIT_ORDER'}
            'ClearMarker' {
                Require-H454 $Context.State 'FIXTURE_CLEAR_ORDER'
                if($Context.Case -ceq 'clear-before'){throw 'FIXTURE_CLEAR_UNKNOWN'}
                $Context.Marker=$false
                if($Context.Case -ceq 'clear-after'){throw 'FIXTURE_CLEAR_UNKNOWN'}
            }
            'VerifyRollbackState' {Require-H454 $Context.Marker 'FIXTURE_ROLLBACK_WITHOUT_MARKER'}
            'StopCandidate' {if($Context.Case -ceq 'rollback-stop'){throw 'FIXTURE_STOP_CANDIDATE'};$Context.Candidate=$false}
            'ReactivateOriginal' {
                Require-H454 (-not $Context.Candidate) 'FIXTURE_TWO_AGENTS'
                if($Context.Case -ceq 'rollback-reactivate-invalid'){return $false}
                $needsStage=-not $Context.Original;$Context.Original=$true
                if($needsStage){return 'RESTAGE_REQUIRED'}
                return 'ALREADY_STAGED_VERIFIED'
            }
            'StageOriginal' {if($Context.Case -ceq 'rollback-stage'){throw 'FIXTURE_STAGE_ORIGINAL'};$Context.OriginalStaged=$true}
            'ConfirmOriginalMcp' {
                if($Context.Case -ceq 'rollback-smoke'){throw 'FIXTURE_SMOKE_ORIGINAL'}
                Require-H454 ($Context.Original -and -not $Context.Launcher -and -not $Context.State -and
                    ($Context.OriginalStaged -or $Context.Case -ceq 'stop-before')) 'FIXTURE_ORIGINAL_NOT_STAGED'
                $Context.OriginalSmoke=$true
            }
            'RestoreControls' {
                if($Context.Case -ceq 'rollback-controls'){throw 'FIXTURE_RESTORE_CONTROLS'}
                Require-H454 ($Context.Marker -and -not $Context.Candidate -and
                    (-not $Context.Original -or (-not $Context.Launcher -and -not $Context.State))) 'FIXTURE_RESTORE_ORDER'
                $Context.Launcher=$false;$Context.State=$false
            }
            'VerifyRecovery' {
                if($Context.Case -ceq 'rollback-verify'){throw 'FIXTURE_VERIFY_RECOVERY'}
                Require-H454 ($Context.Original -and -not $Context.Candidate -and $Context.Marker -and $Context.OriginalSmoke -and
                    -not $Context.Launcher -and -not $Context.State) 'FIXTURE_RECOVERY_STATE'
            }
        }
        return $true
    }.GetNewClosure()
}
$parent=[IO.Path]::GetFullPath($FixtureParent)
$fixture=Join-Path $parent ('h454-engine-fixture-'+[Guid]::NewGuid().ToString('N'))
Require-H454 ([IO.Path]::GetDirectoryName($fixture) -ceq $parent -and -not (Test-Path -LiteralPath $fixture)) 'FIXTURE_SCOPE'
[IO.Directory]::CreateDirectory($fixture)|Out-Null
$lockPath=Join-Path $fixture 'runtime.lock';$script:ownedLock=$null
try {
    $script:ownedLock=[IO.File]::Open($lockPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $cases=@('success','Preflight','Snapshot','InstallGuard','WriteMarker','guard-after','marker-after','RecheckBeforeStop',
        'stop-before','stop-after','stop-ambiguous-before','stop-ambiguous-after','lock-lost',
        'ActivateCandidate','StageCandidate','candidate-result-false','candidate-result-empty','ConfirmCandidateMcp',
        'CommitLauncher','CommitState','VerifyCommit','rollback-stop','rollback-reactivate-invalid','rollback-stage','rollback-smoke',
        'rollback-controls','rollback-verify','clear-before','clear-after')
    foreach($case in $cases){
        $context=[pscustomobject]@{Case=$case;Events=[Collections.Generic.List[string]]::new();
            Lock=$script:ownedLock;Guard=$false;Marker=$false;Original=$true;Candidate=$false;CandidateStaged=$false;
            CandidateSmoke=$false;OriginalStaged=$false;OriginalSmoke=$false;Launcher=$false;State=$false}
        $actions=@{};foreach($name in $names){$actions[$name]=MakeAction $name $context}
        $result=Invoke-H454CutoverEngine $fixture $script:ownedLock $actions -OwnerApproved
        if($case -ceq 'success'){
            Require-H454 ($result.Status -ceq 'COMMITTED' -and $context.Candidate -and -not $context.Original -and
                $context.State -and -not $context.Marker -and $context.Events[-1] -ceq 'ClearMarker') 'FIXTURE_SUCCESS'
        }elseif($case -cin @('Preflight','Snapshot','InstallGuard','WriteMarker','guard-after','marker-after','RecheckBeforeStop')){
            Require-H454 ($result.Status -ceq 'PREFLIGHT_HOLD' -and $context.Original -and
                -not $context.Events.Contains('StopOriginal')) 'FIXTURE_PREFLIGHT_MUTATED'
            if($case -ceq 'marker-after'){Require-H454 ($context.Guard -and $context.Marker) 'FIXTURE_MARKER_GUARD'}
        }elseif($case -ceq 'lock-lost'){
            Require-H454 ($result.Status -ceq 'TRANSITION_HOLD' -and $context.Marker -and -not $context.Original -and
                -not $context.Events.Contains('ActivateCandidate') -and -not $context.Events.Contains('StopCandidate')) 'FIXTURE_LOCK_LOST'
            $script:ownedLock=[IO.File]::Open($lockPath,[IO.FileMode]::Open,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
        }elseif($case -cin @('stop-ambiguous-before','stop-ambiguous-after','candidate-result-false','candidate-result-empty')){
            Require-H454 ($result.Status -ceq 'TRANSITION_HOLD' -and $context.Marker -and
                -not $context.Events.Contains('VerifyRollbackState') -and -not $context.Events.Contains('ReactivateOriginal')) 'FIXTURE_AMBIGUOUS_MUTATION'
        }elseif($case -cin @('rollback-stop','rollback-reactivate-invalid','rollback-stage','rollback-smoke','rollback-controls','rollback-verify')){
            Require-H454 ($result.Status -ceq 'ROLLBACK_HOLD' -and $context.Marker -and
                -not $context.Events.Contains('ClearMarker')) 'FIXTURE_ROLLBACK_FALSE_PASS'
            if($case -ceq 'rollback-stop'){Require-H454 (-not $context.Events.Contains('ReactivateOriginal')) 'FIXTURE_UNSAFE_RESTART'}
            if($case -ceq 'rollback-controls'){Require-H454 (-not $context.Events.Contains('ReactivateOriginal')) 'FIXTURE_CONTROL_FAILURE_RESTART'}
        }elseif($case -cin @('clear-before','clear-after')){
            Require-H454 ($result.Status -ceq 'FINALIZATION_HOLD' -and $context.Candidate -and -not $context.Original -and
                -not $context.Events.Contains('VerifyRollbackState')) 'FIXTURE_AMBIGUOUS_FINALIZATION'
        }else{
            Require-H454 ($result.Status -ceq 'ROLLBACK_VERIFIED_PENDING' -and $context.Original -and
                -not $context.Candidate -and $context.Marker -and -not $context.Events.Contains('ClearMarker')) 'FIXTURE_ROLLBACK'
            Require-H454 (($case -ceq 'stop-before') -eq (-not $context.Events.Contains('StageOriginal'))) 'FIXTURE_RESTAGE'
            Require-H454 ($context.Events.IndexOf('RestoreControls') -lt $context.Events.IndexOf('ReactivateOriginal') -and
                $context.Events.IndexOf('ReactivateOriginal') -lt $context.Events.IndexOf('ConfirmOriginalMcp')) 'FIXTURE_RECOVERY_ORDER'
        }
    }
    foreach($case in @('stop-before','interrupted','VerifyRollbackState')){
        $context=[pscustomobject]@{Case=$case;Events=[Collections.Generic.List[string]]::new();
            Guard=$true;Marker=$true;Original=($case -ceq 'stop-before');Candidate=($case -cne 'stop-before');
            CandidateStaged=$true;CandidateSmoke=$true;OriginalStaged=$false;OriginalSmoke=$false;
            Launcher=($case -cne 'stop-before');State=$false}
        $actions=@{};foreach($name in $names){$actions[$name]=MakeAction $name $context}
        $result=Invoke-H454RecoveryEngine $fixture $script:ownedLock $actions -OwnerApproved
        if($case -ceq 'VerifyRollbackState'){
            Require-H454 ($result.Status -ceq 'ROLLBACK_HOLD' -and -not $context.Events.Contains('StopCandidate')) 'FIXTURE_DRIFT_MUTATED'
        }else{
            Require-H454 ($result.Status -ceq 'ROLLBACK_VERIFIED_PENDING' -and $context.Original -and -not $context.Candidate -and
                $context.Marker -and (($case -ceq 'stop-before') -eq (-not $context.Events.Contains('StageOriginal')))) 'FIXTURE_RESUME'
            $context.Events.Clear()
            $result=Invoke-H454RecoveryEngine $fixture $script:ownedLock $actions -OwnerApproved
            Require-H454 ($result.Status -ceq 'ROLLBACK_VERIFIED_PENDING' -and -not $context.Events.Contains('StageOriginal')) 'FIXTURE_REPEAT_RECOVERY'
        }
    }
    $none=@{};$result=Invoke-H454CutoverEngine $fixture $script:ownedLock $none
    Require-H454 ($result.Status -ceq 'OWNER_APPROVAL_REQUIRED') 'FIXTURE_OWNER_GATE'
    $refused=$false;try {$null=Invoke-H454CutoverEngine $fixture $script:ownedLock $none -OwnerApproved}catch{$refused=$true}
    Require-H454 $refused 'FIXTURE_MISSING_ACTIONS'
    $context=[pscustomobject]@{Case='success';Events=[Collections.Generic.List[string]]::new()}
    $actions=@{};foreach($name in $names){$actions[$name]=MakeAction $name $context}
    $wrongPath=Join-Path $fixture 'wrong.lock'
    $wrong=[IO.File]::Open($wrongPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    try {
        $result=Invoke-H454CutoverEngine $fixture $wrong $actions -OwnerApproved
        Require-H454 ($result.Status -ceq 'PREFLIGHT_HOLD' -and $context.Events.Count -eq 0) 'FIXTURE_WRONG_LOCK'
    } finally {$wrong.Dispose();[IO.File]::Delete($wrongPath)}
    'PS51_CUTOVER_ORDER_AND_ROLLBACK=PASS'
} finally {
    if($null -ne $script:ownedLock){$script:ownedLock.Dispose()}
    if([IO.File]::Exists($lockPath)){[IO.File]::Delete($lockPath)}
    [IO.Directory]::Delete($fixture)
}
