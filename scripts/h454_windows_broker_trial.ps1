#requires -Version 5.1
# The caller owns runtime.lock and pins the sources, images and credentials.
function Get-H454BrokerTrialMarker([hashtable]$RestoreArgs,[string]$CandidateId,[string]$CandidateImage) {
    Require-H454 ($CandidateId -cmatch '^[a-f0-9]{64}$' -and $CandidateId -cne $RestoreArgs.AgentId -and
        $CandidateImage -cmatch '^sha256:[a-f0-9]{64}$' -and $CandidateImage -cne $RestoreArgs.AgentImage) 'H454_TRIAL_PINS'
    return [Text.UTF8Encoding]::new($false).GetBytes("H454-BROKER-TRIAL-1`n$($RestoreArgs.AgentId)`n$CandidateId`n$CandidateImage`n$($RestoreArgs.MarkerSha256)`n")
}

function Assert-H454BrokerTrialMarker([hashtable]$RestoreArgs,[string]$CandidateId,[string]$CandidateImage) {
    Assert-H454RecoveryLock $RestoreArgs.StateDir $RestoreArgs.Lock
    $bytes=Get-H454BrokerTrialMarker $RestoreArgs $CandidateId $CandidateImage
    Assert-H454WssTaskFile (Join-Path $RestoreArgs.StateDir 'h454-broker-trial.pending') (Hash-H454Bytes $bytes) 4096
}

function Get-H454BrokerTrialState([hashtable]$RestoreArgs,[string]$CandidateId,[string]$CandidateImage,[switch]$Pending) {
    if($Pending){Assert-H454BrokerTrialMarker $RestoreArgs $CandidateId $CandidateImage}
    $s=@{StateDir=$RestoreArgs.StateDir;Lock=$RestoreArgs.Lock;MarkerSha256=$RestoreArgs.MarkerSha256;
        SafetyCheck=$RestoreArgs.SafetyCheck;Launcher=$RestoreArgs.Launcher;LauncherSha256=$RestoreArgs.LauncherSha256;
        AgentId=$RestoreArgs.AgentId;AgentImage=$RestoreArgs.AgentImage;AgentName=$RestoreArgs.AgentName;
        OldImage=$RestoreArgs.OldImage;BrokerImage=$RestoreArgs.BrokerImage;CaSha256=$RestoreArgs.CaSha256;
        DockerSha256=$RestoreArgs.DockerSha256}
    Assert-H454RecoveryRouteSafety $s.StateDir $s.Lock $s.MarkerSha256 $s.SafetyCheck
    $label=$s.MarkerSha256.Substring(0,32).ToLowerInvariant();$networkName='h454-recovery-'+$label
    $network=Find-H454RecoveryObject 'network' $networkName $s.DockerSha256
    $plan=Assert-H454RecoveryNetwork $network $networkName $label
    $original=Find-H454RecoveryObject 'container' $s.AgentName $s.DockerSha256
    $candidate=Find-H454RecoveryObject 'container' 'hermes-h454-broker-candidate' $s.DockerSha256
    Require-H454 ($null -ne $original -and $original.Id -ceq $s.AgentId -and
        $null -ne $candidate -and $candidate.Id -ceq $CandidateId) 'H454_TRIAL_IDENTITY'
    $base=Get-H454CandidateImage $s.AgentImage $s.DockerSha256
    $image=Get-H454CandidateImage $CandidateImage $s.DockerSha256
    Assert-H454CandidateImage $base $image $s.AgentImage $CandidateImage
    $bridge=Find-H454RecoveryObject 'network' 'bridge' $s.DockerSha256
    Require-H454 ($null -ne $bridge -and $bridge.Driver -ceq 'bridge') 'H454_TRIAL_NETWORK'
    Assert-H454PreparedCandidate $candidate $original $image 'hermes-h454-broker-candidate' `
        $CandidateImage $s.AgentId $label $bridge.Id $networkName $plan.Id
    $names=@($candidate.NetworkSettings.Networks.PSObject.Properties.Name)
    $onPrivate=$names -ccontains $networkName;$onBridge=$names -ccontains 'bridge'
    if($onPrivate){$snapshot=Get-H454OriginalRestoreState @s -AlternateAgentId $CandidateId}
    else{$snapshot=Get-H454OriginalRestoreState @s}
    Require-H454 ($snapshot.Plan.Id -ceq $plan.Id -and $snapshot.Bridge.Id -ceq $bridge.Id) 'H454_TRIAL_NETWORK'
    if($candidate.State.Running){
        $view=[pscustomobject]@{Agent=$candidate;Broker=$snapshot.Broker;Network=$snapshot.Network;Plan=$snapshot.Plan;
            Bridge=$snapshot.Bridge;Label=$snapshot.Label;NetworkName=$snapshot.NetworkName;HostAddress=$snapshot.HostAddress;
            OnPrivate=$onPrivate;OnBridge=$onBridge}
        Assert-H454OriginalLiveRoute $view $CandidateId $s.DockerSha256
    }elseif($snapshot.Agent.State.Running){Assert-H454OriginalLiveRoute $snapshot $s.AgentId $s.DockerSha256}
    return [pscustomobject]@{Original=$snapshot;Candidate=$candidate;OnPrivate=$onPrivate;OnBridge=$onBridge}
}

function Assert-H454BrokerTrialSettled([hashtable]$RestoreArgs) {
    Assert-H454RecoveryLock $RestoreArgs.StateDir $RestoreArgs.Lock
    Require-H454 (-not (Test-Path -LiteralPath (Join-Path $RestoreArgs.StateDir 'h454-broker-trial.inflight'))) 'H454_TRIAL_OPERATION_UNKNOWN'
}

function Start-H454BrokerTrialOperation([hashtable]$RestoreArgs) {
    Assert-H454BrokerTrialSettled $RestoreArgs
    $path=Join-Path $RestoreArgs.StateDir 'h454-broker-trial.inflight'
    $bytes=[Text.Encoding]::UTF8.GetBytes('H454-BROKER-TRIAL-INFLIGHT-1')
    $stream=[IO.FileStream]::new($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    Assert-H454WssTaskFile $path (Hash-H454Bytes $bytes) 4096
}

function Complete-H454BrokerTrialOperation([hashtable]$RestoreArgs) {
    Assert-H454RecoveryLock $RestoreArgs.StateDir $RestoreArgs.Lock
    $path=Join-Path $RestoreArgs.StateDir 'h454-broker-trial.inflight'
    $bytes=[Text.Encoding]::UTF8.GetBytes('H454-BROKER-TRIAL-INFLIGHT-1')
    Assert-H454WssTaskFile $path (Hash-H454Bytes $bytes) 4096
    [IO.File]::Delete($path)
    Require-H454 (-not (Test-Path -LiteralPath $path)) 'H454_TRIAL_OPERATION_UNKNOWN'
}

function Invoke-H454BrokerTrialDocker([hashtable]$RestoreArgs,[string[]]$Arguments,[byte[]]$InputBytes=$null,
    [datetime]$WindowStartUtc,[datetime]$WindowEndUtc) {
    Start-H454BrokerTrialOperation $RestoreArgs
    if($Arguments[0] -ceq 'stop' -and $Arguments[-1] -ceq $RestoreArgs.AgentId){
        $now=[DateTime]::UtcNow
        if($WindowStartUtc.Kind -ne [DateTimeKind]::Utc -or $WindowEndUtc.Kind -ne [DateTimeKind]::Utc -or
            $now -lt $WindowStartUtc -or $now -ge $WindowEndUtc){
            Complete-H454BrokerTrialOperation $RestoreArgs
            throw 'H454_TRIAL_WINDOW'
        }
    }
    $result=Invoke-H454RecoveryDocker -Arguments $Arguments -DockerSha256 $RestoreArgs.DockerSha256 -InputBytes $InputBytes
    Require-H454 ($result.Code -eq 0) 'H454_TRIAL_DOCKER_HOLD'
    Complete-H454BrokerTrialOperation $RestoreArgs
    return $result.Output
}

function Assert-H454BrokerTrialCredential([hashtable]$RestoreArgs,[byte[]]$TokenBytes,[byte[]]$AgentBytes) {
    Require-H454 ($null -ne $TokenBytes -and $TokenBytes.Length -ge 48 -and $TokenBytes.Length -le 264 -and
        $null -ne $AgentBytes -and $AgentBytes.Length -gt 0 -and $AgentBytes.Length -le 16384) 'H454_TRIAL_CREDENTIAL'
    $utf8=[Text.UTF8Encoding]::new($false,$true)
    $token=$utf8.GetString($TokenBytes);$agentText=$utf8.GetString($AgentBytes);$surrogate='brc_dev_'+('s'*43)
    $agent=ConvertFrom-Json -InputObject $agentText -ErrorAction Stop
    Require-H454 ($token -cmatch '^brc_dev_[A-Za-z0-9_-]{40,256}$' -and $token -cne $surrogate -and
        $agentText.IndexOf($token,[StringComparison]::Ordinal) -lt 0 -and $agent.pairedAt -ceq 'manual' -and
        $agent.deviceToken -ceq $surrogate) 'H454_TRIAL_CREDENTIAL'
    $null=Convert-H454SecureCredential $agentText $RestoreArgs.DeviceId 'http://host.docker.internal:38180'
}

function Start-H454BrokerTrial([hashtable]$RestoreArgs,[string]$CandidateId,[string]$CandidateImage,
    [byte[]]$TokenBytes=$null,[byte[]]$AgentBytes=$null,[datetime]$WindowStartUtc,[datetime]$WindowEndUtc,
    [switch]$Apply,[switch]$OwnerApproved) {
    Require-H454 (-not $Apply -or $OwnerApproved) 'H454_TRIAL_APPROVAL'
    Assert-H454BrokerTrialSettled $RestoreArgs
    $marker=Join-Path $RestoreArgs.StateDir 'h454-broker-trial.pending'
    Require-H454 (-not (Test-Path -LiteralPath $marker)) 'H454_TRIAL_PENDING'
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage
    Require-H454 ($state.Original.Agent.State.Running -and $state.Original.OnPrivate -and -not $state.Original.OnBridge -and
        -not $state.Candidate.State.Running -and $state.Candidate.State.Status -ceq 'created' -and
        $state.OnBridge -and -not $state.OnPrivate) 'H454_TRIAL_START_STATE'
    if(-not $Apply){return [pscustomobject]@{Status='PREFLIGHT';CandidateId=$CandidateId}}
    $now=[DateTime]::UtcNow
    Require-H454 ($WindowStartUtc.Kind -eq [DateTimeKind]::Utc -and $WindowEndUtc.Kind -eq [DateTimeKind]::Utc -and
        $WindowStartUtc -lt $WindowEndUtc -and $now -ge $WindowStartUtc -and $now -lt $WindowEndUtc) 'H454_TRIAL_WINDOW'
    Assert-H454BrokerTrialCredential $RestoreArgs $TokenBytes $AgentBytes
    $verifier=Read-H454PinnedBytes $RestoreArgs.VerifierPath $RestoreArgs.VerifierSha256
    $bytes=Get-H454BrokerTrialMarker $RestoreArgs $CandidateId $CandidateImage
    Assert-H454RecoveryLock $RestoreArgs.StateDir $RestoreArgs.Lock
    $stream=[IO.FileStream]::new($marker,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    Assert-H454BrokerTrialMarker $RestoreArgs $CandidateId $CandidateImage
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    $now=[DateTime]::UtcNow
    Require-H454 ($now -ge $WindowStartUtc -and $now -lt $WindowEndUtc -and $state.Original.Agent.State.Running -and
        $state.Original.OnPrivate -and -not $state.Original.OnBridge -and $state.OnBridge -and -not $state.OnPrivate -and
        $state.Candidate.State.Status -ceq 'created') 'H454_TRIAL_STOP_GATE'
    $null=Invoke-H454BrokerTrialDocker $RestoreArgs @('stop','--time','10',$RestoreArgs.AgentId) -WindowStartUtc $WindowStartUtc -WindowEndUtc $WindowEndUtc
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    Require-H454 (-not $state.Original.Agent.State.Running -and $state.Original.OnPrivate -and -not $state.Original.OnBridge) 'H454_TRIAL_ORIGINAL_STOP'
    $null=Invoke-H454BrokerTrialDocker $RestoreArgs @('network','connect',$state.Original.Bridge.Id,$RestoreArgs.AgentId)
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    Require-H454 (-not $state.Original.Agent.State.Running -and $state.Original.OnPrivate -and $state.Original.OnBridge) 'H454_TRIAL_ORIGINAL_ROUTE'
    $null=Invoke-H454BrokerTrialDocker $RestoreArgs @('network','disconnect',$state.Original.Plan.Id,$RestoreArgs.AgentId)
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    Require-H454 (-not $state.Original.Agent.State.Running -and -not $state.Original.OnPrivate -and $state.Original.OnBridge -and
        $state.OnBridge -and -not $state.OnPrivate) 'H454_TRIAL_ORIGINAL_ROUTE'
    $null=Invoke-H454BrokerTrialDocker $RestoreArgs @('network','connect',$state.Original.Plan.Id,$CandidateId)
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    Require-H454 (-not $state.Candidate.State.Running -and $state.OnBridge -and $state.OnPrivate) 'H454_TRIAL_CANDIDATE_ROUTE'
    $null=Invoke-H454BrokerTrialDocker $RestoreArgs @('network','disconnect',$state.Original.Bridge.Id,$CandidateId)
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    Require-H454 (-not $state.Candidate.State.Running -and -not $state.OnBridge -and $state.OnPrivate) 'H454_TRIAL_CANDIDATE_ROUTE'
    $null=Invoke-H454BrokerTrialDocker $RestoreArgs @('start',$CandidateId)
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    Require-H454 ($state.Candidate.State.Running -and $state.OnPrivate -and -not $state.OnBridge) 'H454_TRIAL_CANDIDATE_START'
    $bootstrap="eval(Buffer.from(process.argv[1],'base64').toString())"
    $empty="const f=require('node:fs');try{const d=f.lstatSync('/run/brc');if(!d.isDirectory()||d.isSymbolicLink()||d.uid!==65534||(d.mode&511)!==448)throw 0;for(const p of ['ready','device.json','config.json']){try{f.lstatSync('/run/brc/'+p);throw 0}catch(e){if(e.code!=='ENOENT')throw 0}}process.stdout.write('H454_STAGE_EMPTY')}catch{process.exit(2)}"
    $empty64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($empty))
    Require-H454 ((Invoke-H454BrokerTrialDocker $RestoreArgs @('exec','--user','65534:65534',$CandidateId,'node','-e',$bootstrap,$empty64)) -ceq 'H454_STAGE_EMPTY') 'H454_TRIAL_STAGE_DRIFT'
    $null=Invoke-H454BrokerTrialDocker $RestoreArgs @('exec','--interactive','--user','65534:65534',$CandidateId,'/bin/sh','/usr/local/bin/h15-stage.sh') $AgentBytes
    $verifier64=[Convert]::ToBase64String($verifier)
    Require-H454 ((Invoke-H454BrokerTrialDocker $RestoreArgs @('exec','--interactive','--user','65534:65534',$CandidateId,'node','-e',$bootstrap,$verifier64) $AgentBytes) -ceq 'H454_STAGED_CREDENTIAL_MATCH') 'H454_TRIAL_STAGE_VERIFY'
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    Require-H454 ((Get-FileHash -LiteralPath $RestoreArgs.VerifierPath -Algorithm SHA256).Hash -ceq $RestoreArgs.VerifierSha256) 'H454_TRIAL_VERIFIER'
    Require-H454 ((Invoke-H454BrokerTrialDocker $RestoreArgs @('exec','--interactive','--user','65534:65534',$state.Original.Broker.Id,'node','/opt/hermes-rollback/stage.cjs') $TokenBytes) -ceq 'H454_BROKER_TOKEN_STAGED') 'H454_TRIAL_STAGE_BROKER'
    $null=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    return [pscustomobject]@{Status='CANDIDATE_STAGED_MCP_REQUIRED';CandidateId=$CandidateId}
}

function Restore-H454BrokerTrial([hashtable]$RestoreArgs,[string]$CandidateId,[string]$CandidateImage,
    [byte[]]$TokenBytes=$null,[byte[]]$AgentBytes=$null,[switch]$Apply,[switch]$OwnerApproved) {
    Require-H454 (-not $Apply -or $OwnerApproved) 'H454_TRIAL_APPROVAL'
    Assert-H454BrokerTrialMarker $RestoreArgs $CandidateId $CandidateImage
    Assert-H454BrokerTrialSettled $RestoreArgs
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    if(-not $Apply){return [pscustomobject]@{Status='RECOVERY_PREFLIGHT';CandidateRunning=$state.Candidate.State.Running}}
    Assert-H454BrokerTrialCredential $RestoreArgs $TokenBytes $AgentBytes
    $null=Read-H454PinnedBytes $RestoreArgs.VerifierPath $RestoreArgs.VerifierSha256
    if($state.Candidate.State.Running){
        Require-H454 (-not $state.Original.Agent.State.Running -and $state.OnPrivate -and -not $state.OnBridge) 'H454_TRIAL_RECOVERY_STATE'
        $null=Invoke-H454BrokerTrialDocker $RestoreArgs @('stop','--time','10',$CandidateId)
        $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    }
    Require-H454 (-not $state.Candidate.State.Running) 'H454_TRIAL_RECOVERY_STATE'
    if($state.OnPrivate -and -not $state.OnBridge){
        $null=Invoke-H454BrokerTrialDocker $RestoreArgs @('network','connect',$state.Original.Bridge.Id,$CandidateId)
        $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    }
    if($state.OnPrivate -and $state.OnBridge){
        Require-H454 (-not $state.Original.Agent.State.Running) 'H454_TRIAL_RECOVERY_STATE'
        $null=Invoke-H454BrokerTrialDocker $RestoreArgs @('network','disconnect',$state.Original.Plan.Id,$CandidateId)
        $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    }
    Require-H454 ($state.OnBridge -and -not $state.OnPrivate -and -not $state.Candidate.State.Running) 'H454_TRIAL_RECOVERY_STATE'
    Start-H454BrokerTrialOperation $RestoreArgs
    $restored=Restore-H454Original @RestoreArgs -TokenBytes $TokenBytes -AgentBytes $AgentBytes -Apply -OwnerApproved
    Require-H454 ($restored.Status -ceq 'ORIGINAL_STAGED' -and $restored.AgentId -ceq $RestoreArgs.AgentId) 'H454_TRIAL_RESTORE'
    Complete-H454BrokerTrialOperation $RestoreArgs
    Assert-H454BrokerTrialMarker $RestoreArgs $CandidateId $CandidateImage
    return [pscustomobject]@{Status='ORIGINAL_STAGED_MCP_REQUIRED';AgentId=$restored.AgentId}
}

function Complete-H454BrokerTrial([hashtable]$RestoreArgs,[string]$CandidateId,[string]$CandidateImage,
    [byte[]]$TokenBytes=$null,[byte[]]$AgentBytes=$null,[switch]$OriginalMcpObserved,[switch]$Apply,[switch]$OwnerApproved) {
    Require-H454 (-not $Apply -or ($OwnerApproved -and $OriginalMcpObserved)) 'H454_TRIAL_MCP_ACKNOWLEDGMENT'
    Assert-H454BrokerTrialMarker $RestoreArgs $CandidateId $CandidateImage
    Assert-H454BrokerTrialSettled $RestoreArgs
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    Require-H454 ($state.Original.Agent.State.Running -and $state.Original.OnPrivate -and -not $state.Original.OnBridge -and
        -not $state.Candidate.State.Running -and $state.OnBridge -and -not $state.OnPrivate) 'H454_TRIAL_RECOVERY_STATE'
    if(-not $Apply){return [pscustomobject]@{Status='ACKNOWLEDGMENT_PREFLIGHT'}}
    Assert-H454BrokerTrialCredential $RestoreArgs $TokenBytes $AgentBytes
    Start-H454BrokerTrialOperation $RestoreArgs
    $restored=Restore-H454Original @RestoreArgs -TokenBytes $TokenBytes -AgentBytes $AgentBytes -Apply -OwnerApproved -RestageOnly
    Require-H454 ($restored.Status -ceq 'ORIGINAL_STAGED' -and $restored.AgentId -ceq $RestoreArgs.AgentId) 'H454_TRIAL_RESTORE'
    Complete-H454BrokerTrialOperation $RestoreArgs
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    Require-H454 ($state.Original.Agent.State.Running -and -not $state.Candidate.State.Running -and
        $state.Original.OnPrivate -and -not $state.Original.OnBridge -and $state.OnBridge -and -not $state.OnPrivate) 'H454_TRIAL_RECOVERY_STATE'
    $marker=Join-Path $RestoreArgs.StateDir 'h454-broker-trial.pending'
    Assert-H454BrokerTrialMarker $RestoreArgs $CandidateId $CandidateImage
    [IO.File]::Delete($marker)
    Require-H454 (-not (Test-Path -LiteralPath $marker)) 'H454_TRIAL_MARKER'
    return [pscustomobject]@{Status='RECOVERY_ACKNOWLEDGED';AgentId=$RestoreArgs.AgentId}
}
