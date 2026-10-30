#requires -Version 5.1
# Trusted local adapter only; FAILED_SETTLED means no operation can mutate later.
function Invoke-H454RecoveryEngine(
    [string]$StateDir, [IO.FileStream]$Lock, [hashtable]$Actions, [switch]$OwnerApproved
) {
    if(-not $OwnerApproved){return [pscustomobject]@{Status='OWNER_APPROVAL_REQUIRED';Phase='NONE'}}
    $names=@('VerifyRollbackState','StopCandidate','ReactivateOriginal','StageOriginal',
        'ConfirmOriginalMcp','RestoreControls','VerifyRecovery')
    foreach($name in $names){
        Require-H454 ($null -ne $Actions -and @($Actions.Keys | Where-Object {$_ -is [string] -and $_ -ceq $name}).Count -eq 1 -and
            $Actions[$name] -is [scriptblock]) 'CUTOVER_ACTIONS'
    }
    $phase='VerifyRollbackState'
    try {
        foreach($name in $names){
            $phase=$name
            Assert-H454RecoveryLock $StateDir $Lock
            if($name -ceq 'ReactivateOriginal'){
                $stageDecision=@(& $Actions[$name])
                Require-H454 ($stageDecision.Count -eq 1 -and $stageDecision[0] -is [string] -and
                    $stageDecision[0] -cin @('RESTAGE_REQUIRED','ALREADY_STAGED_VERIFIED')) 'CUTOVER_STAGE_DECISION'
            } elseif($name -cne 'StageOriginal' -or $stageDecision[0] -ceq 'RESTAGE_REQUIRED') {
                $confirmed=@(& $Actions[$name])
                Require-H454 ($confirmed.Count -eq 1 -and $confirmed[0] -is [bool] -and $confirmed[0]) 'CUTOVER_ACTION_NOT_CONFIRMED'
            }
        }
        return [pscustomobject]@{Status='ROLLBACK_VERIFIED_PENDING';Phase='VerifyRecovery'}
    } catch {return [pscustomobject]@{Status='ROLLBACK_HOLD';Phase=$phase}}
}

function Invoke-H454CutoverEngine(
    [string]$StateDir, [IO.FileStream]$Lock, [hashtable]$Actions, [switch]$OwnerApproved
) {
    if(-not $OwnerApproved){return [pscustomobject]@{Status='OWNER_APPROVAL_REQUIRED';Phase='NONE'}}
    $names=@('Preflight','Snapshot','InstallGuard','WriteMarker','RecheckBeforeStop',
        'StopOriginal','ActivateCandidate','StageCandidate','ConfirmCandidateMcp',
        'CommitLauncher','CommitState','VerifyCommit','ClearMarker',
        'VerifyRollbackState','StopCandidate','ReactivateOriginal','StageOriginal',
        'ConfirmOriginalMcp','RestoreControls','VerifyRecovery')
    Require-H454 ($null -ne $Actions -and $Actions.Count -eq $names.Count) 'CUTOVER_ACTIONS'
    foreach($name in $names){
        Require-H454 (@($Actions.Keys | Where-Object {$_ -is [string] -and $_ -ceq $name}).Count -eq 1 -and
            $Actions[$name] -is [scriptblock]) 'CUTOVER_ACTIONS'
    }
    $phase='Preflight';$stopAttempted=$false
    try {
        foreach($name in @('Preflight','Snapshot','InstallGuard','WriteMarker','RecheckBeforeStop',
            'StopOriginal','ActivateCandidate','StageCandidate','ConfirmCandidateMcp',
            'CommitLauncher','CommitState','VerifyCommit')){
            $phase=$name
            Assert-H454RecoveryLock $StateDir $Lock
            if($name -ceq 'StopOriginal'){$stopAttempted=$true}
            $confirmed=@(& $Actions[$name])
            if($confirmed.Count -eq 1 -and $confirmed[0] -is [string] -and $confirmed[0] -ceq 'FAILED_SETTLED'){
                if(-not $stopAttempted){return [pscustomobject]@{Status='PREFLIGHT_HOLD';Phase=$phase}}
                return Invoke-H454RecoveryEngine $StateDir $Lock $Actions -OwnerApproved
            }
            Require-H454 ($confirmed.Count -eq 1 -and $confirmed[0] -is [bool] -and $confirmed[0]) 'CUTOVER_ACTION_NOT_CONFIRMED'
        }
    } catch {
        if(-not $stopAttempted){return [pscustomobject]@{Status='PREFLIGHT_HOLD';Phase=$phase}}
        return [pscustomobject]@{Status='TRANSITION_HOLD';Phase=$phase}
    }
    # A failed marker removal may have succeeded; never start a rollback from that ambiguous state.
    try {
        $phase='ClearMarker'
        Assert-H454RecoveryLock $StateDir $Lock
        $confirmed=@(& $Actions.ClearMarker)
        Require-H454 ($confirmed.Count -eq 1 -and $confirmed[0] -is [bool] -and $confirmed[0]) 'CUTOVER_ACTION_NOT_CONFIRMED'
        return [pscustomobject]@{Status='COMMITTED';Phase=$phase}
    } catch {return [pscustomobject]@{Status='FINALIZATION_HOLD';Phase=$phase}}
}
