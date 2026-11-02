param([Parameter(Mandatory=$true)][string]$FixtureParent,[Parameter(Mandatory=$true)][string]$Verifier)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\scripts\h454_windows_secure_credential.ps1')
. (Join-Path $PSScriptRoot '..\scripts\h454_windows_broker_credential.ps1')
. (Join-Path $PSScriptRoot '..\scripts\h454_windows_broker_trial.ps1')
function Require-H454([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
function Hash-H454Bytes([byte[]]$Bytes){
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return ([BitConverter]::ToString($sha.ComputeHash($Bytes))).Replace('-','')}finally{$sha.Dispose()}
}
function Assert-H454RecoveryLock([string]$StateDir,[IO.FileStream]$Lock){Require-H454 ($Lock.CanWrite -and $Lock.Name -ceq (Join-Path $StateDir 'runtime.lock')) 'FIXTURE_LOCK'}
function Assert-H454WssTaskFile([string]$Path,[string]$Hash,[int]$Max){
    Require-H454 ((Test-Path -LiteralPath $Path -PathType Leaf) -and (Get-Item -LiteralPath $Path).Length -le $Max -and
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ceq $Hash) 'FIXTURE_MARKER'
}
function Read-H454PinnedBytes([string]$Path,[string]$Hash){
    Require-H454 ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ceq $Hash) 'FIXTURE_VERIFIER'
    return ,[IO.File]::ReadAllBytes($Path)
}
$script:originalId='a'*64;$script:candidateId='b'*64;$script:candidateImage='sha256:'+('c'*64)
$script:bridgeId='d'*64;$script:privateId='e'*64;$script:brokerId='f'*64
$script:events=@();$script:failure='';$script:failed=$false
function Reset-Fixture {
    $script:originalRunning=$true;$script:originalBridge=$false;$script:originalPrivate=$true
    $script:candidateRunning=$false;$script:candidateStatus='created';$script:candidateBridge=$true;$script:candidatePrivate=$false
    $script:events=@();$script:failure='';$script:failed=$false
}
function Get-H454BrokerTrialState([hashtable]$RestoreArgs,[string]$CandidateId,[string]$CandidateImage,[switch]$Pending){
    if($Pending){Assert-H454BrokerTrialMarker $RestoreArgs $CandidateId $CandidateImage}
    Require-H454 ($CandidateId -ceq $script:candidateId -and $CandidateImage -ceq $script:candidateImage -and
        (-not $script:originalRunning -or ($script:originalPrivate -and -not $script:originalBridge)) -and
        (-not $script:candidateRunning -or ($script:candidatePrivate -and -not $script:candidateBridge)) -and
        (-not $script:candidatePrivate -or (-not $script:originalRunning -and $script:originalBridge -and -not $script:originalPrivate))) 'FIXTURE_ROUTE'
    return [pscustomobject]@{Original=[pscustomobject]@{Agent=[pscustomobject]@{State=[pscustomobject]@{Running=$script:originalRunning}};
        OnBridge=$script:originalBridge;OnPrivate=$script:originalPrivate;Bridge=[pscustomobject]@{Id=$script:bridgeId};
        Plan=[pscustomobject]@{Id=$script:privateId};Broker=[pscustomobject]@{Id=$script:brokerId}};
        Candidate=[pscustomobject]@{State=[pscustomobject]@{Running=$script:candidateRunning;Status=$script:candidateStatus}};
        OnBridge=$script:candidateBridge;OnPrivate=$script:candidatePrivate}
}
function Invoke-H454RecoveryDocker([string[]]$Arguments,[string]$DockerSha256,[byte[]]$InputBytes=$null){
    $event='';$output=''
    if($Arguments[0] -ceq 'stop' -and $Arguments[-1] -ceq $script:originalId){$event='stop-original';$script:originalRunning=$false}
    elseif($Arguments[0] -ceq 'stop' -and $Arguments[-1] -ceq $script:candidateId){$event='stop-candidate';$script:candidateRunning=$false;$script:candidateStatus='exited'}
    elseif($Arguments[0] -ceq 'network'){
        $op=$Arguments[1];$network=$Arguments[2];$id=$Arguments[3]
        if($id -ceq $script:originalId -and $network -ceq $script:bridgeId -and $op -ceq 'connect'){$event='original-connect-bridge';$script:originalBridge=$true}
        elseif($id -ceq $script:originalId -and $network -ceq $script:privateId -and $op -ceq 'disconnect'){$event='original-disconnect-private';$script:originalPrivate=$false}
        elseif($id -ceq $script:candidateId -and $network -ceq $script:privateId -and $op -ceq 'connect'){$event='candidate-connect-private';$script:candidatePrivate=$true}
        elseif($id -ceq $script:candidateId -and $network -ceq $script:bridgeId -and $op -ceq 'disconnect'){$event='candidate-disconnect-bridge';$script:candidateBridge=$false}
        elseif($id -ceq $script:candidateId -and $network -ceq $script:bridgeId -and $op -ceq 'connect'){$event='candidate-connect-bridge';$script:candidateBridge=$true}
        elseif($id -ceq $script:candidateId -and $network -ceq $script:privateId -and $op -ceq 'disconnect'){$event='candidate-disconnect-private';$script:candidatePrivate=$false}
        else{throw 'FIXTURE_NETWORK_OPERATION'}
    }elseif($Arguments[0] -ceq 'start' -and $Arguments[1] -ceq $script:candidateId){$event='start-candidate';$script:candidateRunning=$true;$script:candidateStatus='running'}
    elseif($Arguments[0] -ceq 'exec' -and $Arguments -ccontains '/usr/local/bin/h15-stage.sh'){
        $event='stage-candidate';Require-H454 ([Text.Encoding]::UTF8.GetString($InputBytes) -cnotmatch ('brc_dev_'+('a'*43))) 'FIXTURE_AGENT_SECRET'
    }elseif($Arguments[0] -ceq 'exec' -and $Arguments -ccontains '/opt/hermes-rollback/stage.cjs'){
        $event='stage-broker';Require-H454 ([Text.Encoding]::UTF8.GetString($InputBytes) -ceq ('brc_dev_'+('a'*43))) 'FIXTURE_BROKER_SECRET';$output='H454_BROKER_TOKEN_STAGED'
    }elseif($Arguments[0] -ceq 'exec' -and $Arguments -ccontains '--interactive'){$event='verify-candidate';$output='H454_STAGED_CREDENTIAL_MATCH'}
    elseif($Arguments[0] -ceq 'exec'){$event='verify-empty';$output='H454_STAGE_EMPTY'}
    else{throw 'FIXTURE_DOCKER_OPERATION'}
    $script:events+=@($event)
    if($event -ceq $script:failure -and -not $script:failed){$script:failed=$true;throw 'H454_DOCKER_AMBIGUOUS'}
    return [pscustomobject]@{Code=0;Output=$output}
}
function Restore-H454Original {
    param($StateDir,$Lock,$MarkerSha256,$SafetyCheck,$Launcher,$LauncherSha256,$AgentId,$AgentImage,$AgentName,$DeviceId,
        $OldImage,$BrokerImage,$CaSha256,$DockerSha256,$VerifierPath,$VerifierSha256,$TokenBytes,$AgentBytes,[switch]$Apply,[switch]$OwnerApproved,[switch]$RestageOnly)
    Require-H454 ($Apply -and $OwnerApproved -and $AgentId -ceq $script:originalId -and -not $script:candidateRunning -and
        $script:candidateBridge -and -not $script:candidatePrivate -and $null -ne $TokenBytes -and $null -ne $AgentBytes) 'FIXTURE_RESTORE'
    $script:events+=@('restore-original');$script:originalRunning=$true;$script:originalBridge=$false;$script:originalPrivate=$true
    if($script:failure -ceq 'restore-original' -and -not $script:failed){$script:failed=$true;throw 'H454_DOCKER_AMBIGUOUS'}
    return [pscustomobject]@{Status='ORIGINAL_STAGED';AgentId=$AgentId}
}
$parent=[IO.Path]::GetFullPath($FixtureParent)
$dir=Join-Path $parent ('h454-trial-fixture-'+[Guid]::NewGuid().ToString('N'))
Require-H454 ([IO.Path]::GetDirectoryName($dir) -ceq $parent -and -not (Test-Path -LiteralPath $dir)) 'FIXTURE_SCOPE'
[IO.Directory]::CreateDirectory($dir)|Out-Null
$lock=$null;$credential=$null
try{
    $lock=[IO.File]::Open((Join-Path $dir 'runtime.lock'),[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    $raw=ConvertTo-Json -Compress -InputObject ([ordered]@{relayUrl='http://host.docker.internal:38180';deviceId='synthetic-device';
        deviceToken=('brc_dev_'+('a'*43));name='fixture';pairedAt='before'})
    $credential=Convert-H454BrokerCredential $raw 'synthetic-device'
    $args=@{StateDir=$dir;Lock=$lock;MarkerSha256=('A'*64);SafetyCheck={return $true};Launcher='fixture';LauncherSha256=('B'*64);
        AgentId=$script:originalId;AgentImage=('sha256:'+('9'*64));AgentName='fixture';DeviceId='synthetic-device';
        OldImage=('sha256:'+('8'*64));BrokerImage=('sha256:'+('7'*64));CaSha256=('C'*64);DockerSha256=('D'*64);
        VerifierPath=$Verifier;VerifierSha256=(Get-FileHash -LiteralPath $Verifier -Algorithm SHA256).Hash}
    $start=@{RestoreArgs=$args;CandidateId=$script:candidateId;CandidateImage=$script:candidateImage;
        TokenBytes=$credential.TokenBytes;AgentBytes=$credential.AgentBytes;WindowStartUtc=[DateTime]::UtcNow.AddMinutes(-1);WindowEndUtc=[DateTime]::UtcNow.AddMinutes(10)}
    Reset-Fixture
    $preview=Start-H454BrokerTrial @start
    Require-H454 ($preview.Status -ceq 'PREFLIGHT' -and $script:events.Count -eq 0) 'FIXTURE_PREVIEW'
    $refused=$false;try{$null=Start-H454BrokerTrial @start -Apply}catch{$refused=$true}
    Require-H454 ($refused -and $script:events.Count -eq 0) 'FIXTURE_APPROVAL'
    $expired=$start.Clone();$expired.WindowEndUtc=[DateTime]::UtcNow.AddSeconds(-1);$refused=$false
    try{$null=Start-H454BrokerTrial @expired -Apply -OwnerApproved}catch{$refused=$true}
    Require-H454 ($refused -and $script:events.Count -eq 0 -and -not (Test-Path -LiteralPath (Join-Path $dir 'h454-broker-trial.pending'))) 'FIXTURE_WINDOW'
    $refused=$false
    try{$null=Invoke-H454BrokerTrialDocker $args @('stop','--time','10',$script:originalId) -WindowStartUtc ([DateTime]::UtcNow.AddMinutes(-2)) -WindowEndUtc ([DateTime]::UtcNow.AddMinutes(-1))}
    catch{$refused=$_.Exception.Message -ceq 'H454_TRIAL_WINDOW'}
    Require-H454 ($refused -and $script:events.Count -eq 0 -and -not (Test-Path -LiteralPath (Join-Path $dir 'h454-broker-trial.inflight'))) 'FIXTURE_WINDOW_AT_DISPATCH'
    $cases=@('success','stop-original','original-connect-bridge','original-disconnect-private','candidate-connect-private',
        'candidate-disconnect-bridge','start-candidate','verify-empty','stage-candidate','verify-candidate','stage-broker')
    foreach($case in $cases){
        Reset-Fixture;if($case -cne 'success'){$script:failure=$case}
        $interrupted=$false
        try{$result=Start-H454BrokerTrial @start -Apply -OwnerApproved}catch{$interrupted=$_.Exception.Message -ceq 'H454_DOCKER_AMBIGUOUS'}
        Require-H454 (($case -ceq 'success' -and $result.Status -ceq 'CANDIDATE_STAGED_MCP_REQUIRED') -or
            ($case -cne 'success' -and $interrupted)) 'FIXTURE_TRIAL_RESULT'
        Require-H454 (Test-Path -LiteralPath (Join-Path $dir 'h454-broker-trial.pending')) 'FIXTURE_MARKER_MISSING'
        if($interrupted){
            Require-H454 (Test-Path -LiteralPath (Join-Path $dir 'h454-broker-trial.inflight')) 'FIXTURE_OPERATION_MARKER'
            $before=$script:events.Count;$refused=$false
            try{$null=Restore-H454BrokerTrial $args $script:candidateId $script:candidateImage $credential.TokenBytes $credential.AgentBytes -Apply -OwnerApproved}
            catch{$refused=$_.Exception.Message -ceq 'H454_TRIAL_OPERATION_UNKNOWN'}
            Require-H454 ($refused -and $script:events.Count -eq $before) 'FIXTURE_UNKNOWN_OPERATION_RETRIED'
            # The mock has already settled; a real Docker timeout has no such proof.
            [IO.File]::Delete((Join-Path $dir 'h454-broker-trial.inflight'))
        }
        if($case -ceq 'success'){
            Require-H454 ($script:candidateRunning -and -not $script:originalRunning) 'FIXTURE_CANDIDATE_RUNNING'
            $before=$script:events.Count;$refused=$false
            try{$null=Restore-H454BrokerTrial $args $script:candidateId $script:candidateImage ([byte[]](1,2)) $credential.AgentBytes -Apply -OwnerApproved}catch{$refused=$true}
            Require-H454 ($refused -and $script:events.Count -eq $before -and $script:candidateRunning) 'FIXTURE_BAD_RECOVERY_CREDENTIAL'
        }
        $script:failure=''
        $restored=Restore-H454BrokerTrial $args $script:candidateId $script:candidateImage $credential.TokenBytes $credential.AgentBytes -Apply -OwnerApproved
        Require-H454 ($restored.Status -ceq 'ORIGINAL_STAGED_MCP_REQUIRED' -and $script:originalRunning -and
            $script:originalPrivate -and -not $script:originalBridge -and -not $script:candidateRunning -and
            $script:candidateBridge -and -not $script:candidatePrivate -and $script:events[-1] -ceq 'restore-original') 'FIXTURE_RECOVERY'
        if($case -ceq 'success'){
            $refused=$false
            try{$null=Complete-H454BrokerTrial $args $script:candidateId $script:candidateImage $credential.TokenBytes $credential.AgentBytes -Apply -OwnerApproved}catch{$refused=$true}
            Require-H454 ($refused -and (Test-Path -LiteralPath (Join-Path $dir 'h454-broker-trial.pending'))) 'FIXTURE_MCP_ACK_REQUIRED'
            $done=Complete-H454BrokerTrial $args $script:candidateId $script:candidateImage $credential.TokenBytes $credential.AgentBytes -Apply -OwnerApproved -OriginalMcpObserved
            Require-H454 ($done.Status -ceq 'RECOVERY_ACKNOWLEDGED' -and -not (Test-Path -LiteralPath (Join-Path $dir 'h454-broker-trial.pending'))) 'FIXTURE_ACKNOWLEDGMENT'
        }else{[IO.File]::Delete((Join-Path $dir 'h454-broker-trial.pending'))}
    }
    foreach($case in @('stop-candidate','candidate-connect-bridge','candidate-disconnect-private','restore-original')){
        Reset-Fixture
        $null=Start-H454BrokerTrial @start -Apply -OwnerApproved
        $script:failure=$case;$refused=$false
        try{$null=Restore-H454BrokerTrial $args $script:candidateId $script:candidateImage $credential.TokenBytes $credential.AgentBytes -Apply -OwnerApproved}
        catch{$refused=$_.Exception.Message -ceq 'H454_DOCKER_AMBIGUOUS'}
        Require-H454 ($refused -and (Test-Path -LiteralPath (Join-Path $dir 'h454-broker-trial.inflight'))) 'FIXTURE_RECOVERY_INTERRUPTED'
        $before=$script:events.Count;$refused=$false
        try{$null=Restore-H454BrokerTrial $args $script:candidateId $script:candidateImage $credential.TokenBytes $credential.AgentBytes -Apply -OwnerApproved}
        catch{$refused=$_.Exception.Message -ceq 'H454_TRIAL_OPERATION_UNKNOWN'}
        Require-H454 ($refused -and $before -eq $script:events.Count) 'FIXTURE_RECOVERY_UNKNOWN_RETRIED'
        [IO.File]::Delete((Join-Path $dir 'h454-broker-trial.inflight'))
        $script:failure=''
        $restored=Restore-H454BrokerTrial $args $script:candidateId $script:candidateImage $credential.TokenBytes $credential.AgentBytes -Apply -OwnerApproved
        Require-H454 ($restored.Status -ceq 'ORIGINAL_STAGED_MCP_REQUIRED' -and $script:originalRunning -and
            -not $script:candidateRunning -and $script:candidateBridge -and -not $script:candidatePrivate) 'FIXTURE_RECOVERY_RESUME'
        [IO.File]::Delete((Join-Path $dir 'h454-broker-trial.pending'))
    }
    'PS51_SYNTHETIC_BROKER_TRIAL_RECOVERY=PASS'
}finally{
    if($null -ne $credential){[Array]::Clear($credential.TokenBytes,0,$credential.TokenBytes.Length);[Array]::Clear($credential.AgentBytes,0,$credential.AgentBytes.Length)}
    if($null -ne $lock){$lock.Dispose()}
    foreach($name in @('runtime.lock','h454-broker-trial.pending','h454-broker-trial.inflight')){[IO.File]::Delete((Join-Path $dir $name))}
    [IO.Directory]::Delete($dir)
}
