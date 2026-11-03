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
function Assert-H454PrivateAcl([string]$Path){Require-H454 ([IO.Path]::GetDirectoryName($Path) -ceq $dir -and -not ((Get-Item -LiteralPath $Path).Attributes -band [IO.FileAttributes]::ReparsePoint)) 'FIXTURE_PATH'}
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
    $script:originalStaged=$true
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
    if($Arguments[0] -ceq 'stop' -and $Arguments[-1] -ceq $script:originalId){$event='stop-original';$script:originalRunning=$false;$script:originalStaged=$false}
    elseif($Arguments[0] -ceq 'stop' -and $Arguments[-1] -ceq $script:candidateId){$event='stop-candidate';$script:candidateRunning=$false;$script:candidateStatus='exited'}
    elseif($Arguments[0] -ceq 'network'){
        $op=$Arguments[1];$network=$Arguments[2];$id=$Arguments[3]
        if($id -ceq $script:originalId -and $network -ceq $script:bridgeId -and $op -ceq 'connect'){$event='original-connect-bridge';$script:originalBridge=$true}
        elseif($id -ceq $script:originalId -and $network -ceq $script:privateId -and $op -ceq 'disconnect'){$event='original-disconnect-private';$script:originalPrivate=$false}
        elseif($id -ceq $script:originalId -and $network -ceq $script:privateId -and $op -ceq 'connect'){$event='original-connect-private';$script:originalPrivate=$true}
        elseif($id -ceq $script:originalId -and $network -ceq $script:bridgeId -and $op -ceq 'disconnect'){$event='original-disconnect-bridge';$script:originalBridge=$false}
        elseif($id -ceq $script:candidateId -and $network -ceq $script:privateId -and $op -ceq 'connect'){$event='candidate-connect-private';$script:candidatePrivate=$true}
        elseif($id -ceq $script:candidateId -and $network -ceq $script:bridgeId -and $op -ceq 'disconnect'){$event='candidate-disconnect-bridge';$script:candidateBridge=$false}
        elseif($id -ceq $script:candidateId -and $network -ceq $script:bridgeId -and $op -ceq 'connect'){$event='candidate-connect-bridge';$script:candidateBridge=$true}
        elseif($id -ceq $script:candidateId -and $network -ceq $script:privateId -and $op -ceq 'disconnect'){$event='candidate-disconnect-private';$script:candidatePrivate=$false}
        else{throw 'FIXTURE_NETWORK_OPERATION'}
    }elseif($Arguments[0] -ceq 'start' -and $Arguments[1] -ceq $script:originalId){$event='start-original';$script:originalRunning=$true}
    elseif($Arguments[0] -ceq 'start' -and $Arguments[1] -ceq $script:candidateId){$event='start-candidate';$script:candidateRunning=$true;$script:candidateStatus='running'}
    elseif($Arguments[0] -ceq 'exec' -and $Arguments -ccontains '/usr/local/bin/h15-stage.sh'){
        $event=if($Arguments -ccontains $script:originalId){$script:originalStaged=$true;'stage-original'}else{'stage-candidate'}
        Require-H454 ([Text.Encoding]::UTF8.GetString($InputBytes) -cnotmatch ('brc_dev_'+('a'*43))) 'FIXTURE_AGENT_SECRET'
    }elseif($Arguments[0] -ceq 'exec' -and $Arguments -ccontains '/opt/hermes-rollback/stage.cjs'){
        $event='stage-broker';Require-H454 ([Text.Encoding]::UTF8.GetString($InputBytes) -ceq ('brc_dev_'+('a'*43))) 'FIXTURE_BROKER_SECRET';$output='H454_BROKER_TOKEN_STAGED'
    }elseif($Arguments[0] -ceq 'exec' -and $Arguments -ccontains '--interactive'){$event='verify-candidate';$output='H454_STAGED_CREDENTIAL_MATCH'}
    elseif($Arguments[0] -ceq 'exec'){$event='verify-empty';$output='H454_STAGE_EMPTY'}
    else{throw 'FIXTURE_DOCKER_OPERATION'}
    $script:events+=@($event)
    if($event -ceq $script:failure -and -not $script:failed){$script:failed=$true;throw 'H454_DOCKER_AMBIGUOUS'}
    return [pscustomobject]@{Code=0;Output=$output}
}
function Start-H454TrialReceiptWorker([hashtable]$RestoreArgs,[object]$Operation,[byte[]]$InputBytes=$null){
    $arguments=switch -CaseSensitive ($Operation.Phase){
        {$_ -cin @('STOP_ORIGINAL','STOP_CANDIDATE')} {@('stop','--time','10',$Operation.Target)}
        {$_ -cin @('START_ORIGINAL','START_CANDIDATE')} {@('start',$Operation.Target)}
        {$_ -cin @('CONNECT_ORIGINAL','CONNECT_CANDIDATE')} {@('network','connect',$Operation.Network,$Operation.Target)}
        {$_ -cin @('DISCONNECT_ORIGINAL','DISCONNECT_CANDIDATE')} {@('network','disconnect',$Operation.Network,$Operation.Target)}
        {$_ -cin @('STAGE_ORIGINAL','STAGE_CANDIDATE')} {@('exec','--interactive','--user','65534:65534',$Operation.Target,'/bin/sh','/usr/local/bin/h15-stage.sh')}
        'STAGE_BROKER' {@('exec','--interactive','--user','65534:65534',$Operation.Target,'node','/opt/hermes-rollback/stage.cjs')}
        default {throw 'FIXTURE_PHASE'}
    }
    $null=Invoke-H454RecoveryDocker -Arguments $arguments -DockerSha256 $RestoreArgs.DockerSha256 -InputBytes $InputBytes
    $receipt=Join-Path $RestoreArgs.StateDir ('h454-broker-op-'+$Operation.Nonce+'.receipt')
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes("H454-BROKER-TRIAL-RECEIPT-1`n$($Operation.Hash)`nHTTP_OK`n")
    $stream=[IO.File]::Open($receipt,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
}
function Restore-H454Original {
    param($StateDir,$Lock,$MarkerSha256,$SafetyCheck,$Launcher,$LauncherSha256,$AgentId,$AgentImage,$AgentName,$DeviceId,
        $OldImage,$BrokerImage,$CaSha256,$DockerSha256,$VerifierPath,$VerifierSha256,$TokenBytes,$AgentBytes,[switch]$Apply,[switch]$OwnerApproved,[switch]$RestageOnly,[scriptblock]$TrialMutation)
    Require-H454 ($Apply -and $OwnerApproved -and $AgentId -ceq $script:originalId -and -not $script:candidateRunning -and
        $script:candidateBridge -and -not $script:candidatePrivate -and $null -ne $TokenBytes -and $null -ne $AgentBytes -and $null -ne $TrialMutation) 'FIXTURE_RESTORE'
    if($script:originalBridge -and -not $script:originalPrivate){$null=& $TrialMutation @('network','connect',$script:privateId,$AgentId) $null}
    if($script:originalBridge -and $script:originalPrivate){$null=& $TrialMutation @('network','disconnect',$script:bridgeId,$AgentId) $null}
    if(-not $script:originalRunning){$null=& $TrialMutation @('start',$AgentId) $null}
    if(-not $script:originalStaged){$null=& $TrialMutation @('exec','--interactive','--user','65534:65534',$AgentId,'/bin/sh','/usr/local/bin/h15-stage.sh') $AgentBytes}
    $null=& $TrialMutation @('exec','--interactive','--user','65534:65534',$script:brokerId,'node','/opt/hermes-rollback/stage.cjs') $TokenBytes
    $script:events+=@('restore-original')
    return [pscustomobject]@{Status='ORIGINAL_STAGED';AgentId=$AgentId}
}
$parent=[IO.Path]::GetFullPath($FixtureParent)
$dir=Join-Path $parent ('h454-trial-fixture-'+[Guid]::NewGuid().ToString('N'))
Require-H454 ([IO.Path]::GetDirectoryName($dir) -ceq $parent -and -not (Test-Path -LiteralPath $dir)) 'FIXTURE_SCOPE'
[IO.Directory]::CreateDirectory($dir)|Out-Null
$lock=$null;$credential=$null
try{
    $lock=[IO.File]::Open((Join-Path $dir 'runtime.lock'),[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
    # Exercise the actual operator gate and state-entry enumeration, including the monitor path.
    $guardPath=Join-Path $PSScriptRoot '..\scripts\h454_windows_guard_operator.ps1'
    $taskPath=Join-Path $PSScriptRoot '..\scripts\h454_windows_wss_task.ps1'
    $tokens=$null;$errors=$null
    $guardAst=[Management.Automation.Language.Parser]::ParseFile($guardPath,[ref]$tokens,[ref]$errors)
    Require-H454 (@($errors).Count -eq 0) 'FIXTURE_OPERATOR_PARSE'
    $gate=@($guardAst.FindAll({param($x)$x -is [Management.Automation.Language.IfStatementAst] -and
        $x.Extent.Text.StartsWith('if(-not $trial){')},$true))
    $guardText=[IO.File]::ReadAllText($guardPath)
    $gateStart=$guardText.IndexOf($gate[0].Extent.Text,[StringComparison]::Ordinal)
    Require-H454 ($gate.Count -eq 1 -and $gateStart -gt $guardText.IndexOf('$lock=Open-H454RecoveryLock $state',[StringComparison]::Ordinal) -and
        $gateStart -lt $guardText.IndexOf('if($CheckOriginal -or $PrepareRecoveryRoute',$gateStart,[StringComparison]::Ordinal)) 'FIXTURE_OPERATOR_GATE'
    $taskAst=[Management.Automation.Language.Parser]::ParseFile($taskPath,[ref]$tokens,[ref]$errors)
    $enumerator=@($taskAst.FindAll({param($x)$x -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $x.Name -ceq 'Test-H454WssStateEntry'},$true))
    Require-H454 (@($errors).Count -eq 0 -and $enumerator.Count -eq 1) 'FIXTURE_STATE_ENUMERATOR'
    . ([scriptblock]::Create($enumerator[0].Extent.Text))
    $gateBlock=[scriptblock]::Create($gate[0].Extent.Text);$state=$dir;$trial=$false
    & $gateBlock
    foreach($name in @('H454-BROKER-TRIAL.PENDING','h454-broker-trial.inflight')){
        $entry=Join-Path $dir $name
        [IO.File]::WriteAllText($entry,'interrupted')
        try{
            $refused=$false
            try{& $gateBlock}catch{$refused=$_.Exception.Message -ceq 'H454_BROKER_TRIAL_PENDING'}
            Require-H454 $refused 'FIXTURE_MONITOR_BYPASS'
            $trial=$true;& $gateBlock;$trial=$false
        }finally{[IO.File]::Delete($entry)}
    }
    $entry=Join-Path $dir 'h454-broker-trial.pending'
    [IO.Directory]::CreateDirectory($entry)|Out-Null
    try{
        $refused=$false
        try{& $gateBlock}catch{$refused=$_.Exception.Message -ceq 'H454_BROKER_TRIAL_PENDING'}
        Require-H454 $refused 'FIXTURE_TRIAL_MARKER_DIRECTORY'
    }finally{[IO.Directory]::Delete($entry)}
    $raw=ConvertTo-Json -Compress -InputObject ([ordered]@{relayUrl='http://host.docker.internal:38180';deviceId='synthetic-device';
        deviceToken=('brc_dev_'+('a'*43));name='fixture';pairedAt='before'})
    $credential=Convert-H454BrokerCredential $raw 'synthetic-device'
    $args=@{StateDir=$dir;Lock=$lock;MarkerSha256=('A'*64);SafetyCheck={return $true};Launcher='fixture';LauncherSha256=('B'*64);
        AgentId=$script:originalId;AgentImage=('sha256:'+('9'*64));AgentName='fixture';DeviceId='synthetic-device';
        OldImage=('sha256:'+('8'*64));BrokerImage=('sha256:'+('7'*64));CaSha256=('C'*64);DockerSha256=('D'*64);
        VerifierPath=$Verifier;VerifierSha256=(Get-FileHash -LiteralPath $Verifier -Algorithm SHA256).Hash}
    $start=@{RestoreArgs=$args;CandidateId=$script:candidateId;CandidateImage=$script:candidateImage;
        TokenBytes=$credential.TokenBytes;AgentBytes=$credential.AgentBytes;WindowStartUtc=[DateTime]::UtcNow.AddMinutes(-1);WindowEndUtc=[DateTime]::UtcNow.AddMinutes(10)}
    $recorded=Get-H454TrialRecordedOperation $args $script:candidateId 'STOP_CANDIDATE' ([Guid]::NewGuid().ToString('N')) $script:candidateId '-' 0 0
    Start-H454TrialRecordedOperation $args $recorded
    Require-H454 ($null -eq (Resolve-H454TrialRecordedOperation $args $script:candidateId)) 'FIXTURE_RECEIPT_MISSING'
    $refused=$false
    try{Assert-H454BrokerTrialSettled $args}catch{$refused=$_.Exception.Message -ceq 'H454_TRIAL_UNKNOWN_STOP_CANDIDATE'}
    Require-H454 $refused 'FIXTURE_RECEIPT_PENDING'
    $receipt=Join-Path $dir ('h454-broker-op-'+$recorded.Nonce+'.receipt')
    [IO.File]::WriteAllText($receipt,"H454-BROKER-TRIAL-RECEIPT-1`n$('F'*64)`nHTTP_OK`n")
    $refused=$false
    try{$null=Resolve-H454TrialRecordedOperation $args $script:candidateId}catch{$refused=$_.Exception.Message -ceq 'H454_TRIAL_RECEIPT_INVALID'}
    Require-H454 ($refused -and (Test-Path -LiteralPath (Join-Path $dir 'h454-broker-trial.inflight'))) 'FIXTURE_RECEIPT_MISMATCH'
    [IO.File]::WriteAllText($receipt,"H454-BROKER-TRIAL-RECEIPT-1`n$($recorded.Hash)`nHTTP_OK`n")
    Require-H454 ((Resolve-H454TrialRecordedOperation $args $script:candidateId) -ceq 'HTTP_OK' -and
        -not (Test-Path -LiteralPath $receipt) -and -not (Test-Path -LiteralPath (Join-Path $dir 'h454-broker-trial.inflight'))) 'FIXTURE_RECEIPT_RESOLVED'
    $recorded=Get-H454TrialRecordedOperation $args $script:candidateId 'STAGE_CANDIDATE' ([Guid]::NewGuid().ToString('N')) $script:candidateId '-' 0 0
    Start-H454TrialRecordedOperation $args $recorded
    $receipt=Join-Path $dir ('h454-broker-op-'+$recorded.Nonce+'.receipt')
    $trialPath=Join-Path $PSScriptRoot '..\scripts\h454_windows_broker_trial.ps1'
    $trialAst=[Management.Automation.Language.Parser]::ParseFile($trialPath,[ref]$tokens,[ref]$errors)
    $workers=@($trialAst.FindAll({param($x)$x -is [Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -ceq 'Start-H454TrialReceiptWorker'},$true))
    Require-H454 (@($errors).Count -eq 0 -and $workers.Count -eq 1) 'FIXTURE_WORKER_SOURCE'
    $sources=@($workers[0].FindAll({param($x)$x -is [Management.Automation.Language.StringConstantExpressionAst] -and
        $x.StringConstantType -eq 'SingleQuotedHereString' -and $x.Value.Contains('__PAYLOAD__')},$true))
    Require-H454 ($sources.Count -eq 1) 'FIXTURE_WORKER_SOURCE'
    $powershell=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $workerHash=(Get-FileHash -LiteralPath $powershell -Algorithm SHA256).Hash
    $payload=@($dir,$recorded.Phase,$recorded.Nonce,$recorded.Target,$recorded.Network,'0','0',$recorded.Hash,$workerHash,'100',('D'*64)) -join "`n"
    $encodedPayload=[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($payload))
    $workerSource=$sources[0].Value.Replace('__PAYLOAD__',$encodedPayload)
    $encodedSource=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($workerSource))
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$powershell
    $info.Arguments='-NoProfile -NonInteractive -EncodedCommand '+$encodedSource
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.RedirectStandardInput=$true
    $info.EnvironmentVariables['PSModulePath']=Join-Path $PSHOME 'Modules'
    $worker=[Diagnostics.Process]::new();$worker.StartInfo=$info
    try{
        Require-H454 $worker.Start() 'FIXTURE_WORKER_START'
        $partial=[Text.Encoding]::UTF8.GetBytes('H454_SYNTHETIC_PARTIAL_INPUT')
        $worker.StandardInput.BaseStream.Write($partial,0,$partial.Length);$worker.StandardInput.Close()
        Require-H454 ($worker.WaitForExit(15000) -and $worker.ExitCode -eq 0) 'FIXTURE_WORKER_EXIT'
    }finally{$worker.Dispose()}
    Require-H454 ((Test-Path -LiteralPath $receipt) -and
        [IO.File]::ReadAllText($receipt) -ceq "H454-BROKER-TRIAL-RECEIPT-1`n$($recorded.Hash)`nINPUT_INCOMPLETE`n" -and
        -not $workerSource.Contains('H454_SYNTHETIC_PARTIAL_INPUT')) 'FIXTURE_STAGE_INPUT_NOT_DISPATCHED'
    Require-H454 ((Resolve-H454TrialRecordedOperation $args $script:candidateId) -ceq 'INPUT_INCOMPLETE' -and
        -not (Test-Path -LiteralPath (Join-Path $dir 'h454-broker-trial.inflight'))) 'FIXTURE_STAGE_INPUT_NOT_DISPATCHED'
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
    $refused=$false
    try{$null=Invoke-H454BrokerTrialDocker $args @('stop','--time','10',$script:originalId) -WindowStartUtc ([DateTime]::UtcNow.AddMinutes(-1)) -WindowEndUtc ([DateTime]::UtcNow.AddSeconds(5))}
    catch{$refused=$_.Exception.Message -ceq 'H454_TRIAL_WINDOW'}
    Require-H454 ($refused -and $script:events.Count -eq 0 -and -not (Test-Path -LiteralPath (Join-Path $dir 'h454-broker-trial.inflight'))) 'FIXTURE_WINDOW_TOO_SHORT'
    $cases=@('success','stop-original','original-connect-bridge','original-disconnect-private','candidate-connect-private',
        'candidate-disconnect-bridge','start-candidate','verify-empty','stage-candidate','verify-candidate','stage-broker')
    foreach($case in $cases){
        Reset-Fixture;if($case -cne 'success'){$script:failure=$case}
        $interrupted=$false
        try{$result=Start-H454BrokerTrial @start -Apply -OwnerApproved}catch{
            if($_.Exception.Message -cne 'H454_DOCKER_AMBIGUOUS'){throw}
            $interrupted=$true
        }
        Require-H454 (($case -ceq 'success' -and $result.Status -ceq 'CANDIDATE_STAGED_MCP_REQUIRED') -or
            ($case -cne 'success' -and $interrupted)) 'FIXTURE_TRIAL_RESULT'
        Require-H454 (Test-Path -LiteralPath (Join-Path $dir 'h454-broker-trial.pending')) 'FIXTURE_MARKER_MISSING'
        if($interrupted){
            Require-H454 (Test-Path -LiteralPath (Join-Path $dir 'h454-broker-trial.inflight')) 'FIXTURE_OPERATION_MARKER'
            $phase=switch($case){
                'stop-original'{'STOP_ORIGINAL'} 'original-connect-bridge'{'CONNECT_ORIGINAL'}
                'original-disconnect-private'{'DISCONNECT_ORIGINAL'} 'candidate-connect-private'{'CONNECT_CANDIDATE'}
                'candidate-disconnect-bridge'{'DISCONNECT_CANDIDATE'} 'start-candidate'{'START_CANDIDATE'}
                'verify-empty'{'CHECK_CANDIDATE'} 'stage-candidate'{'STAGE_CANDIDATE'}
                'verify-candidate'{'VERIFY_CANDIDATE'} 'stage-broker'{'STAGE_BROKER'}
            }
            $before=$script:events.Count;$refused=$false
            try{$null=Restore-H454BrokerTrial $args $script:candidateId $script:candidateImage $credential.TokenBytes $credential.AgentBytes -Apply -OwnerApproved}
            catch{$refused=$_.Exception.Message -ceq ('H454_TRIAL_UNKNOWN_'+$phase)}
            Require-H454 ($refused -and $script:events.Count -eq $before) 'FIXTURE_UNKNOWN_OPERATION_RETRIED'
            # The mock has already settled; a real Docker timeout has no such proof.
            [IO.File]::Delete((Join-Path $dir 'h454-broker-trial.inflight'))
        }
        if($case -ceq 'success'){
            Require-H454 ($script:candidateRunning -and -not $script:originalRunning) 'FIXTURE_CANDIDATE_RUNNING'
            $forged=Get-H454TrialRecordedOperation $args $script:candidateId 'STAGE_BROKER' ([Guid]::NewGuid().ToString('N')) ('0'*64) '-' 0 0
            Start-H454TrialRecordedOperation $args $forged
            $forgedReceipt=Join-Path $dir ('h454-broker-op-'+$forged.Nonce+'.receipt')
            [IO.File]::WriteAllText($forgedReceipt,"H454-BROKER-TRIAL-RECEIPT-1`n$($forged.Hash)`nHTTP_OK`n")
            $refused=$false
            try{$null=Resolve-H454TrialRecordedOperation $args $script:candidateId $script:candidateImage}catch{$refused=$_.Exception.Message -ceq 'H454_TRIAL_RECEIPT_BROKER'}
            Require-H454 ($refused -and (Test-Path -LiteralPath (Join-Path $dir 'h454-broker-trial.inflight'))) 'FIXTURE_RECEIPT_BROKER_IDENTITY'
            [IO.File]::Delete($forgedReceipt);[IO.File]::Delete((Join-Path $dir 'h454-broker-trial.inflight'))
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
    foreach($case in @('stop-candidate','candidate-connect-bridge','candidate-disconnect-private','original-connect-private',
        'original-disconnect-bridge','start-original','stage-original','stage-broker')){
        Reset-Fixture
        $null=Start-H454BrokerTrial @start -Apply -OwnerApproved
        $script:failure=$case;$refused=$false
        try{$null=Restore-H454BrokerTrial $args $script:candidateId $script:candidateImage $credential.TokenBytes $credential.AgentBytes -Apply -OwnerApproved}
        catch{$refused=$_.Exception.Message -ceq 'H454_DOCKER_AMBIGUOUS'}
        Require-H454 ($refused -and (Test-Path -LiteralPath (Join-Path $dir 'h454-broker-trial.inflight'))) 'FIXTURE_RECOVERY_INTERRUPTED'
        $before=$script:events.Count;$refused=$false
        $phase=switch($case){'stop-candidate'{'STOP_CANDIDATE'} 'candidate-connect-bridge'{'CONNECT_CANDIDATE'}
            'candidate-disconnect-private'{'DISCONNECT_CANDIDATE'} 'original-connect-private'{'CONNECT_ORIGINAL'}
            'original-disconnect-bridge'{'DISCONNECT_ORIGINAL'} 'start-original'{'START_ORIGINAL'}
            'stage-original'{'STAGE_ORIGINAL'} 'stage-broker'{'STAGE_BROKER'}}
        try{$null=Restore-H454BrokerTrial $args $script:candidateId $script:candidateImage $credential.TokenBytes $credential.AgentBytes -Apply -OwnerApproved}
        catch{$refused=$_.Exception.Message -ceq ('H454_TRIAL_UNKNOWN_'+$phase)}
        Require-H454 ($refused -and $before -eq $script:events.Count) 'FIXTURE_RECOVERY_UNKNOWN_RETRIED'
        $inflight=Join-Path $dir 'h454-broker-trial.inflight'
        $fields=[IO.File]::ReadAllText($inflight).Split([char]10)
        Require-H454 ($fields.Count -eq 8 -and $fields[0] -ceq 'H454-BROKER-TRIAL-INFLIGHT-2') 'FIXTURE_RECORDED_INTERRUPTION'
        $settled=Get-H454TrialRecordedOperation $args $script:candidateId $fields[1] $fields[2] $fields[3] $fields[4] ([long]$fields[5]) ([long]$fields[6])
        $receipt=Join-Path $dir ('h454-broker-op-'+$settled.Nonce+'.receipt')
        [IO.File]::WriteAllText($receipt,"H454-BROKER-TRIAL-RECEIPT-1`n$($settled.Hash)`nHTTP_OK`n")
        $attempts=@($script:events|Where-Object {$_ -ceq $case}).Count
        $script:failure=''
        $restored=Restore-H454BrokerTrial $args $script:candidateId $script:candidateImage $credential.TokenBytes $credential.AgentBytes -Apply -OwnerApproved
        Require-H454 ($restored.Status -ceq 'ORIGINAL_STAGED_MCP_REQUIRED' -and $script:originalRunning -and
            -not $script:candidateRunning -and $script:candidateBridge -and -not $script:candidatePrivate) 'FIXTURE_RECOVERY_RESUME'
        $after=@($script:events|Where-Object {$_ -ceq $case}).Count
        Require-H454 (($case -ceq 'stage-broker' -and $after -eq $attempts+1) -or
            ($case -cne 'stage-broker' -and $after -eq $attempts)) 'FIXTURE_RECOVERY_DUPLICATE'
        [IO.File]::Delete((Join-Path $dir 'h454-broker-trial.pending'))
    }
    Reset-Fixture
    $null=Start-H454BrokerTrial @start -Apply -OwnerApproved
    $null=Restore-H454BrokerTrial $args $script:candidateId $script:candidateImage $credential.TokenBytes $credential.AgentBytes -Apply -OwnerApproved
    $script:failure='stage-broker';$script:failed=$false;$refused=$false
    try{$null=Complete-H454BrokerTrial $args $script:candidateId $script:candidateImage $credential.TokenBytes $credential.AgentBytes -Apply -OwnerApproved -OriginalMcpObserved}
    catch{$refused=$_.Exception.Message -ceq 'H454_DOCKER_AMBIGUOUS'}
    Require-H454 ($refused -and (Test-Path -LiteralPath (Join-Path $dir 'h454-broker-trial.inflight'))) 'FIXTURE_ACK_INTERRUPTED'
    $fields=[IO.File]::ReadAllText((Join-Path $dir 'h454-broker-trial.inflight')).Split([char]10)
    $settled=Get-H454TrialRecordedOperation $args $script:candidateId $fields[1] $fields[2] $fields[3] $fields[4] ([long]$fields[5]) ([long]$fields[6])
    $receipt=Join-Path $dir ('h454-broker-op-'+$settled.Nonce+'.receipt')
    [IO.File]::WriteAllText($receipt,"H454-BROKER-TRIAL-RECEIPT-1`n$($settled.Hash)`nHTTP_OK`n")
    $script:failure=''
    $done=Complete-H454BrokerTrial $args $script:candidateId $script:candidateImage $credential.TokenBytes $credential.AgentBytes -Apply -OwnerApproved -OriginalMcpObserved
    Require-H454 ($done.Status -ceq 'RECOVERY_ACKNOWLEDGED' -and -not (Test-Path -LiteralPath (Join-Path $dir 'h454-broker-trial.pending'))) 'FIXTURE_ACK_RESUME'
    'PS51_SYNTHETIC_BROKER_TRIAL_RECOVERY=PASS'
}finally{
    if($null -ne $credential){[Array]::Clear($credential.TokenBytes,0,$credential.TokenBytes.Length);[Array]::Clear($credential.AgentBytes,0,$credential.AgentBytes.Length)}
    if($null -ne $lock){$lock.Dispose()}
    foreach($name in @('runtime.lock','h454-broker-trial.pending','h454-broker-trial.inflight')){[IO.File]::Delete((Join-Path $dir $name))}
    [IO.Directory]::Delete($dir)
}
