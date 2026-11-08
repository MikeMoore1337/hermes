#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$Verifier)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\scripts\h454_windows_secure_credential.ps1')
. (Join-Path $PSScriptRoot '..\scripts\h454_windows_broker_credential.ps1')
. (Join-Path $PSScriptRoot '..\scripts\h454_windows_original_restore.ps1')
function Require-H454([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
$tokens=$null;$errors=$null
$guardAst=[Management.Automation.Language.Parser]::ParseFile((Join-Path $PSScriptRoot '..\scripts\h454_windows_guard_operator.ps1'),[ref]$tokens,[ref]$errors)
$leafFunctions=@($guardAst.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and $node.Name -ceq 'Get-H454LauncherLeaf'},$true))
Require-H454 (@($errors).Count -eq 0 -and $leafFunctions.Count -eq 1) 'FIXTURE_PATH_PARSER'
. ([scriptblock]::Create($leafFunctions[0].Extent.Text))
$safe='$CRED_PATH = Join-Path $STATE_DIR ''credential.bin'''
Require-H454 ((Get-H454LauncherLeaf $safe 'CRED_PATH') -ceq 'credential.bin') 'FIXTURE_PATH_VALID'
foreach($badPath in @('$CRED_PATH = Join-Path $STATE_DIR ''../secret''',
    '$CRED_PATH = Join-Path $OTHER ''credential.bin''',
    '$CRED_PATH = Join-Path $STATE_DIR ''..''',
    ($safe+"`n"+$safe))){
    $refused=$false;try{$null=Get-H454LauncherLeaf $badPath 'CRED_PATH'}catch{$refused=$true}
    Require-H454 $refused 'FIXTURE_PATH_NOT_REFUSED'
}
function Read-H454PinnedBytes([string]$Path,[string]$Sha256){
    Require-H454 ($Path -ceq $Verifier -and (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ceq $Sha256) 'FIXTURE_VERIFIER'
    return ,[IO.File]::ReadAllBytes($Path)
}
$agentId='a'*64;$brokerId='b'*64;$device='synthetic-device';$token='brc_dev_'+('a'*43)
$raw=ConvertTo-Json -Compress -InputObject ([ordered]@{relayUrl='http://host.docker.internal:38180';deviceId=$device;
    deviceToken=$token;name='fixture';pairedAt='before'})
$credential=Convert-H454BrokerCredential $raw $device
$script:bridge=$true;$script:private=$false;$script:running=$false;$script:agentStaged=$false;$script:wrongStage=$false
$script:events=@();$script:failEvent='';$script:failed=$false
$script:mutationFenceActive=$false;$script:delayedStart=$false;$script:delayedStartPending=$false
function Open-H454MutationFence([string]$StateDir,[IO.FileStream]$Lock,[string]$Scope,[string]$MarkerSha256) {
    Require-H454 (-not $script:mutationFenceActive) 'H454_MUTATION_UNSETTLED'
    $script:mutationFenceActive=$true
    return [pscustomobject]@{Scope=$Scope}
}
function Close-H454MutationFence([string]$StateDir,[IO.FileStream]$Lock,[object]$Fence) {
    Require-H454 $script:mutationFenceActive 'FIXTURE_FENCE_MISSING'
    $script:mutationFenceActive=$false
}
function Reset-Fixture {
    $script:bridge=$true;$script:private=$false;$script:running=$false;$script:agentStaged=$false;$script:wrongStage=$false
    $script:events=@();$script:failEvent='';$script:failed=$false
    $script:mutationFenceActive=$false;$script:delayedStart=$false;$script:delayedStartPending=$false
}
function Get-H454OriginalRestoreState {
    return [pscustomobject]@{Agent=[pscustomobject]@{State=[pscustomobject]@{Running=$script:running}};
        Broker=[pscustomobject]@{Id=$brokerId};Plan=[pscustomobject]@{Id=('c'*64)};Bridge=[pscustomobject]@{Id=('d'*64)};
        OnBridge=$script:bridge;OnPrivate=$script:private}
}
function Assert-H454OriginalLiveRoute([object]$Snapshot,[string]$AgentId,[string]$DockerSha256){
    Require-H454 ($Snapshot.Agent.State.Running -and $Snapshot.OnPrivate -and -not $Snapshot.OnBridge) 'FIXTURE_ROUTE'
}
function Invoke-H454RecoveryDocker {
    param([string[]]$Arguments,[string]$DockerSha256,[byte[]]$InputBytes=$null)
    $op=$Arguments[0];$sub=if($Arguments.Count -gt 1){$Arguments[1]}else{''};$name='';$code=0;$out=''
    if($op -ceq 'network' -and $sub -ceq 'connect'){$name='connect';$script:private=$true}
    elseif($op -ceq 'network' -and $sub -ceq 'disconnect'){$name='disconnect';$script:bridge=$false}
    elseif($op -ceq 'start'){
        $name='start'
        if($script:delayedStart){
            $script:delayedStart=$false
            $script:delayedStartPending=$true
        }else{$script:running=$true}
    }
    elseif($op -ceq 'exec' -and $Arguments -ccontains '/usr/local/bin/h15-stage.sh'){
        $name='agent-stage';$data=[Text.Encoding]::UTF8.GetString($InputBytes)
        Require-H454 (-not $data.Contains($token) -and $data.Contains('brc_dev_'+('s'*43))) 'FIXTURE_AGENT_SECRET'
        $script:agentStaged=$true
    }elseif($op -ceq 'exec' -and $Arguments -ccontains '/opt/hermes-rollback/stage.cjs'){
        $name='broker-stage';Require-H454 ([Text.Encoding]::UTF8.GetString($InputBytes) -ceq $token -and $script:agentStaged) 'FIXTURE_BROKER_SECRET'
        $out='H454_BROKER_TOKEN_STAGED'
    }elseif($op -ceq 'exec' -and $Arguments -ccontains '--interactive'){
        if($script:agentStaged -and -not $script:wrongStage){$out='H454_STAGED_CREDENTIAL_MATCH'}else{$code=2}
    }elseif($op -ceq 'exec'){
        if($script:agentStaged -or $script:wrongStage){$code=2}else{$out='H454_STAGE_EMPTY'}
    }else{throw 'FIXTURE_UNEXPECTED_DOCKER'}
    if($name){
        $script:events+=@($name)
        if($name -ceq 'start' -and $script:delayedStartPending){throw 'H454_DOCKER_AMBIGUOUS'}
        if($name -ceq $script:failEvent -and -not $script:failed){$script:failed=$true;throw 'H454_DOCKER_AMBIGUOUS'}
    }
    return [pscustomobject]@{Code=$code;Output=$out}
}
$params=@{StateDir='synthetic';Lock=$null;MarkerSha256=('A'*64);SafetyCheck={return $true};Launcher='fixture';
    LauncherSha256=('B'*64);AgentId=$agentId;AgentImage=('sha256:'+('c'*64));AgentName='fixture-agent';DeviceId=$device;
    OldImage=('sha256:'+('d'*64));BrokerImage=('sha256:'+('e'*64));CaSha256=('C'*64);DockerSha256=('D'*64);
    VerifierPath=$Verifier;VerifierSha256=(Get-FileHash -LiteralPath $Verifier -Algorithm SHA256).Hash;
    TokenBytes=$credential.TokenBytes;AgentBytes=$credential.AgentBytes}
$bad=$null
try{
    Reset-Fixture;$refused=$false
    try{$null=Restore-H454Original @params -Apply}catch{$refused=$true}
    Require-H454 ($refused -and $script:events.Count -eq 0) 'FIXTURE_APPROVAL'
    $preview=Restore-H454Original @params
    Require-H454 ($preview.Status -ceq 'PREFLIGHT' -and $script:events.Count -eq 0) 'FIXTURE_PREVIEW'
    foreach($mode in @('direct','trial')){
        if($mode -ceq 'trial'){
            $params.TrialMutation={
                param([string[]]$Arguments,[byte[]]$InputBytes)
                $script:mutationCalls++
                return (Invoke-H454RecoveryDocker -Arguments $Arguments -DockerSha256 ('D'*64) -InputBytes $InputBytes)
            }
        }
        foreach($point in @('connect','disconnect','start','agent-stage','broker-stage')){
            Reset-Fixture;$script:mutationCalls=0;$script:failEvent=$point;$refused=$false
            try{$null=Restore-H454Original @params -Apply -OwnerApproved}catch{$refused=$_.Exception.Message -ceq 'H454_DOCKER_AMBIGUOUS'}
            Require-H454 $refused 'FIXTURE_AMBIGUOUS'
            $script:failEvent=''
            if($mode -ceq 'direct'){
                $before=$script:events.Count
                $reason=''
                try{$null=Restore-H454Original @params -Apply -OwnerApproved}catch{$reason=$_.Exception.Message}
                Require-H454 ($reason -ceq 'H454_MUTATION_UNSETTLED' -and
                    $script:events.Count -eq $before) 'FIXTURE_DIRECT_REPLAY_REFUSED'
                # Fixture-only representation of owner-confirmed manual settlement.
                $script:mutationFenceActive=$false
            }
            $result=Restore-H454Original @params -Apply -OwnerApproved
            Require-H454 ($result.Status -ceq 'ORIGINAL_STAGED' -and $script:running -and $script:private -and
                -not $script:bridge -and $script:agentStaged -and $script:events -cnotcontains 'stop') 'FIXTURE_RESUME'
            foreach($operation in @('connect','disconnect','start','agent-stage')){
                Require-H454 (@($script:events|Where-Object {$_ -ceq $operation}).Count -eq 1) 'FIXTURE_DUPLICATE_MUTATION'
            }
            if($mode -ceq 'trial'){Require-H454 ($script:mutationCalls -eq $script:events.Count) 'FIXTURE_MUTATION_BYPASS'}
        }
    }
    $params.Remove('TrialMutation')
    Reset-Fixture;$script:delayedStart=$true;$reason=''
    try{$null=Restore-H454Original @params -Apply -OwnerApproved}catch{$reason=$_.Exception.Message}
    Require-H454 ($reason -ceq 'H454_DOCKER_AMBIGUOUS' -and $script:delayedStartPending -and
        $script:mutationFenceActive) 'FIXTURE_DELAYED_START_ACCEPTED'
    $before=$script:events.Count
    $reason=''
    try{$null=Restore-H454Original @params -Apply -OwnerApproved}catch{$reason=$_.Exception.Message}
    Require-H454 ($reason -ceq 'H454_MUTATION_UNSETTLED' -and
        $script:events.Count -eq $before) 'FIXTURE_DELAYED_START_REPLAY'
    $script:running=$true;$script:delayedStartPending=$false
    $reason=''
    try{$null=Restore-H454Original @params -Apply -OwnerApproved}catch{$reason=$_.Exception.Message}
    Require-H454 ($reason -ceq 'H454_MUTATION_UNSETTLED') 'FIXTURE_DELAYED_POST_SETTLEMENT_REPLAY'
    $script:mutationFenceActive=$false
    $result=Restore-H454Original @params -Apply -OwnerApproved
    Require-H454 ($result.Status -ceq 'ORIGINAL_STAGED' -and
        $script:events.Count -eq ($before+2)) 'FIXTURE_DELAYED_MANUAL_RESUME'
    'PS51_SYNTHETIC_ORIGINAL_RESTORE_DELAYED_DOCKER=PASS'
    Reset-Fixture;$script:bridge=$false;$script:private=$true;$script:running=$true;$script:wrongStage=$true
    $refused=$false;try{$null=Restore-H454Original @params -Apply -OwnerApproved}catch{$refused=$true}
    Require-H454 ($refused -and $script:events -cnotcontains 'agent-stage' -and $script:events -cnotcontains 'broker-stage') 'FIXTURE_STAGED_DRIFT'
    Reset-Fixture;$refused=$false
    try{$null=Restore-H454Original @params -Apply -OwnerApproved -RestageOnly}catch{$refused=$true}
    Require-H454 ($refused -and $script:events.Count -eq 0) 'FIXTURE_MONITOR_STOPPED'
    $script:bridge=$false;$script:private=$true;$script:running=$true;$script:agentStaged=$true
    $monitor=Restore-H454Original @params -Apply -OwnerApproved -RestageOnly
    Require-H454 ($monitor.Status -ceq 'ORIGINAL_STAGED' -and ($script:events -join ',') -ceq 'broker-stage') 'FIXTURE_MONITOR_RESTAGE'
    Reset-Fixture
    $badText=[Text.Encoding]::UTF8.GetString($credential.AgentBytes).Replace('"pairedAt":"manual"','"pairedAt":"not-manual"')
    $bad=[Text.Encoding]::UTF8.GetBytes($badText)
    $params.AgentBytes=$bad;$refused=$false
    try{$null=Restore-H454Original @params -Apply -OwnerApproved}catch{$refused=$true}
    Require-H454 ($refused -and $script:events.Count -eq 0) 'FIXTURE_BAD_CREDENTIAL'
    'PS51_SYNTHETIC_ORIGINAL_RESTORE_INTERRUPTION=PASS'
}finally{
    [Array]::Clear($credential.TokenBytes,0,$credential.TokenBytes.Length);[Array]::Clear($credential.AgentBytes,0,$credential.AgentBytes.Length)
    if($null -ne $bad){[Array]::Clear($bad,0,$bad.Length)}
}
