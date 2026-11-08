#requires -Version 5.1
# The caller pins every helper and owns the lock; a running original is never stopped.
function Get-H454OriginalRestoreState(
    [string]$StateDir,[IO.FileStream]$Lock,[string]$MarkerSha256,[scriptblock]$SafetyCheck,
    [string]$Launcher,[string]$LauncherSha256,[string]$AgentId,[string]$AgentImage,[string]$AgentName,
    [string]$OldImage,[string]$BrokerImage,[string]$CaSha256,[string]$DockerSha256,
    [string]$AlternateAgentId=''
) {
    Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
    $label=$MarkerSha256.Substring(0,32).ToLowerInvariant();$networkName='h454-recovery-'+$label
    $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
    $bridge=Find-H454RecoveryObject 'network' 'bridge' $DockerSha256
    $old=Find-H454RecoveryObject 'container' ($networkName+'-proxy') $DockerSha256
    $broker=Find-H454RecoveryObject 'container' ($networkName+'-broker') $DockerSha256
    $agent=Find-H454RecoveryObject 'container' $AgentName $DockerSha256
    Require-H454 ($null -ne $network -and $null -ne $bridge -and $bridge.Driver -ceq 'bridge' -and
        $bridge.Id -cmatch '^[a-f0-9]{64}$' -and $null -ne $old -and $null -ne $broker -and
        $null -ne $agent -and $agent.Id -ceq $AgentId) 'H454_RESTORE_IDENTITY'
    $plan=Assert-H454RecoveryNetwork $network $networkName $label
    $cmd=@($broker.Config.Cmd);Require-H454 ($cmd.Count -eq 3) 'H454_RESTORE_BROKER'
    $hostAddress=[string]$cmd[0];$hostNumber=Get-H454IPv4Number $hostAddress
    Require-H454 ((Test-H454PrivateIPv4 $hostNumber) -and ($hostNumber -lt $plan.Base -or $hostNumber -gt $plan.Last)) 'H454_RESTORE_BROKER'
    # Preserve the ordinary created/exited-state check. Opt into the narrow
    # Docker Desktop stale-ID exception only if the stopped old proxy has a
    # nonempty bridge ID different from the current bridge. New/running/broker
    # containers continue through strict identity checks.
    Require-H454 ($old.State.Running -is [bool] -and -not $old.State.Running) 'H454_RESTORE_OLD_PROXY'
    $oldBridge=$old.NetworkSettings.Networks.PSObject.Properties['bridge']
    $staleOldBridge=($null -ne $oldBridge -and
        -not [string]::IsNullOrEmpty([string]$oldBridge.Value.NetworkID) -and
        [string]$oldBridge.Value.NetworkID -cne $bridge.Id)
    Assert-H454RecoveryProxy $old ($networkName+'-proxy') $label $OldImage $hostAddress $CaSha256 $plan $bridge.Id -AllowStoppedLegacyProxyBridge:$staleOldBridge
    Assert-H454RecoveryProxy $broker ($networkName+'-broker') $label $BrokerImage $hostAddress $CaSha256 $plan $bridge.Id `
        -Connected -EntrypointPath '/opt/hermes-rollback/broker.mjs'
    Require-H454 ($broker.State.Running -and $agent.State.Running -is [bool] -and
        $agent.State.Paused -is [bool] -and -not $agent.State.Paused -and
        $agent.State.Restarting -is [bool] -and -not $agent.State.Restarting -and
        $agent.State.Dead -is [bool] -and -not $agent.State.Dead -and
        (($agent.State.Running -and $agent.State.Status -ceq 'running') -or
         (-not $agent.State.Running -and $agent.State.Status -ceq 'exited')) -and
        $agent.HostConfig.RestartPolicy.Name -ceq 'no') 'H454_RESTORE_STATE'
    $names=@($agent.NetworkSettings.Networks.PSObject.Properties.Name)
    $onBridge=$names -ccontains 'bridge';$onPrivate=$names -ccontains $networkName
    Require-H454 (($names.Count -eq 1 -and ($onBridge -or $onPrivate)) -or
        ($names.Count -eq 2 -and $onBridge -and $onPrivate)) 'H454_RESTORE_NETWORK'
    Require-H454 (-not $agent.State.Running -or ($names.Count -eq 1 -and $onPrivate)) 'H454_RESTORE_RUNNING_ROUTE'
    $expected=if($onBridge -and $onPrivate){@('bridge',$networkName)}elseif($onBridge){@('bridge')}else{@($networkName)}
    Assert-H454OriginalProfile $agent $Launcher $LauncherSha256 $AgentId $AgentImage $AgentName $expected
    foreach($pair in @(@('bridge',$bridge.Id),@($networkName,$plan.Id))){
        $endpoint=$agent.NetworkSettings.Networks.PSObject.Properties[$pair[0]]
        if($null -ne $endpoint){
            Require-H454 ($endpoint.Value.NetworkID -ceq $pair[1] -or
                (-not $agent.State.Running -and [string]::IsNullOrEmpty([string]$endpoint.Value.NetworkID))) 'H454_RESTORE_NETWORK'
            foreach($alias in @($endpoint.Value.Aliases)){
                Require-H454 ($null -eq $alias -or ($alias -is [string] -and
                    -not $alias.TrimEnd('.').Equals('host.docker.internal',[StringComparison]::OrdinalIgnoreCase))) 'H454_RESTORE_NETWORK'
            }
        }
    }
    $permittedAgent=$AgentId
    if($AlternateAgentId -cne ''){
        Require-H454 ($AlternateAgentId -cmatch '^[a-f0-9]{64}$' -and $AlternateAgentId -cne $AgentId -and
            -not $agent.State.Running -and $onBridge -and -not $onPrivate) 'H454_RESTORE_ALTERNATE'
        $permittedAgent=$AlternateAgentId
    }
    Assert-H454RecoveryRouteMembers $network $broker $DockerSha256 $permittedAgent
    $members=@($network.Containers.PSObject.Properties|ForEach-Object {$_.Name})
    Require-H454 ($members -ccontains $broker.Id -and
        (-not $agent.State.Running -or ($members.Count -eq 2 -and $members -ccontains $AgentId))) 'H454_RESTORE_MEMBERS'
    return [pscustomobject]@{Agent=$agent;Broker=$broker;Old=$old;Network=$network;Plan=$plan;Bridge=$bridge;
        Label=$label;NetworkName=$networkName;HostAddress=$hostAddress;OnBridge=$onBridge;OnPrivate=$onPrivate}
}

function Assert-H454OriginalLiveRoute([object]$Snapshot,[string]$AgentId,[string]$DockerSha256) {
    Require-H454 ($Snapshot.Agent.State.Running -and $Snapshot.OnPrivate -and -not $Snapshot.OnBridge) 'H454_RESTORE_RUNNING_ROUTE'
    $bootstrap="eval(Buffer.from(process.argv[1],'base64').toString())"
    $inspect=@'
const f=require('node:fs'),d=require('node:dns');
const hosts=f.readFileSync('/etc/hosts','utf8').split(/\r?\n/).some(l=>l.replace(/#.*/,'').trim().split(/\s+/).slice(1).some(x=>x.replace(/\.$/,'').toLowerCase()==='host.docker.internal'));
const route=f.readFileSync('/proc/net/route','utf8').trim().split(/\r?\n/).slice(1).some(l=>{const v=l.trim().split(/\s+/);return v[1]==='00000000'&&(parseInt(v[3],16)&1)!==0});
d.lookup('host.docker.internal',{all:true,verbatim:true},(e,a)=>{if(e||!a.length)process.exit(2);console.log(JSON.stringify({hosts,route,addresses:a.map(x=>x.address)}))});
'@
    $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($inspect))
    $checked=Invoke-H454RecoveryDocker -Arguments @('exec','--user','65534:65534',$AgentId,'node','-e',$bootstrap,$encoded) -DockerSha256 $DockerSha256
    Require-H454 ($checked.Code -eq 0 -and $checked.Output.Length -gt 0 -and $checked.Output.Length -le 8192) 'H454_RESTORE_ROUTE_PROBE'
    $answer=ConvertFrom-Json -InputObject $checked.Output -ErrorAction Stop
    Require-H454 ($answer.hosts -is [bool] -and -not $answer.hosts -and $answer.route -is [bool] -and -not $answer.route -and
        $answer.addresses -is [array]) 'H454_RESTORE_ROUTE_PROBE'
    Assert-H454RollbackAgentRoute $Snapshot.Network $Snapshot.Agent $Snapshot.Broker $Snapshot.Plan.Id $Snapshot.NetworkName `
        'com.hermes.h454.recovery' $Snapshot.Label $AgentId $Snapshot.Broker.Id $Snapshot.Bridge.Id 'bridge' $Snapshot.Plan.Cidr @($answer.addresses) $false
    $isolation="const n=require('node:net');const s=n.connect(38184,process.argv[2]);s.on('connect',()=>process.exit(2));s.on('error',e=>{if(!['ENETUNREACH','EHOSTUNREACH','ECONNREFUSED'].includes(e.code))process.exit(3);console.log('H454_DIRECT_UPSTREAM=REFUSED')});s.setTimeout(4000,()=>process.exit(4))"
    $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($isolation))
    $direct=Invoke-H454RecoveryDocker -Arguments @('exec','--user','65534:65534',$AgentId,'node','-e',$bootstrap,$encoded,$Snapshot.HostAddress) -DockerSha256 $DockerSha256
    Require-H454 ($direct.Code -eq 0 -and $direct.Output.Trim() -ceq 'H454_DIRECT_UPSTREAM=REFUSED') 'H454_RESTORE_DIRECT_ROUTE'
    $private=[string]$Snapshot.Broker.NetworkSettings.Networks.PSObject.Properties[$Snapshot.NetworkName].Value.IPAddress
    $upstream=[string]$Snapshot.Broker.NetworkSettings.Networks.bridge.IPAddress
    $closed="const n=require('node:net');const s=n.connect(38181,process.argv[2]);s.on('connect',()=>process.exit(2));s.on('error',e=>{if(e.code!=='ECONNREFUSED')process.exit(3);console.log('H454_STAGE_EXTERNAL=REFUSED')});s.setTimeout(4000,()=>process.exit(4))"
    $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($closed))
    $agentCheck=Invoke-H454RecoveryDocker -Arguments @('exec','--user','65534:65534',$AgentId,'node','-e',$bootstrap,$encoded,$private) -DockerSha256 $DockerSha256
    Require-H454 ($agentCheck.Code -eq 0 -and $agentCheck.Output.Trim() -ceq 'H454_STAGE_EXTERNAL=REFUSED') 'H454_RESTORE_BROKER_EXPOSURE'
    $listeners="const n=require('node:net');async function c(h,p,yes){await new Promise((r,j)=>{const s=n.connect(p,h);s.on('connect',()=>{s.destroy();yes?r():j(0)});s.on('error',e=>!yes&&e.code==='ECONNREFUSED'?r():j(0));s.setTimeout(3000,()=>{s.destroy();j(0)})})} (async()=>{await c(process.argv[2],38180,true);await c(process.argv[3],38180,false);await c(process.argv[2],38181,false);await c(process.argv[3],38181,false);await c('127.0.0.1',38181,true);console.log('H454_BROKER_LISTENERS=PASS')})().catch(()=>process.exit(2))"
    $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($listeners))
    $brokerCheck=Invoke-H454RecoveryDocker -Arguments @('exec','--user','65534:65534',$Snapshot.Broker.Id,'node','-e',$bootstrap,$encoded,$private,$upstream) -DockerSha256 $DockerSha256
    Require-H454 ($brokerCheck.Code -eq 0 -and $brokerCheck.Output.Trim() -ceq 'H454_BROKER_LISTENERS=PASS') 'H454_RESTORE_BROKER_EXPOSURE'
}

function Restore-H454Original(
    [string]$StateDir,[IO.FileStream]$Lock,[string]$MarkerSha256,[scriptblock]$SafetyCheck,
    [string]$Launcher,[string]$LauncherSha256,[string]$AgentId,[string]$AgentImage,[string]$AgentName,[string]$DeviceId,
    [string]$OldImage,[string]$BrokerImage,[string]$CaSha256,[string]$DockerSha256,
    [string]$VerifierPath,[string]$VerifierSha256,[byte[]]$TokenBytes=$null,[byte[]]$AgentBytes=$null,
    [switch]$Apply,[switch]$OwnerApproved,[switch]$RestageOnly,[scriptblock]$TrialMutation=$null
) {
    function Invoke-H454OriginalMutation([string[]]$Arguments,[byte[]]$InputBytes=$null) {
        if($null -ne $TrialMutation){return (& $TrialMutation $Arguments $InputBytes)}
        return (Invoke-H454RecoveryDocker -Arguments $Arguments -DockerSha256 $DockerSha256 -InputBytes $InputBytes)
    }
    Require-H454 (-not $Apply -or $OwnerApproved) 'H454_RESTORE_APPROVAL'
    foreach($hash in @($MarkerSha256,$LauncherSha256,$CaSha256,$DockerSha256,$VerifierSha256)){
        Require-H454 ($hash -cmatch '^[A-F0-9]{64}$') 'H454_RESTORE_PINS'
    }
    Require-H454 ($AgentId -cmatch '^[a-f0-9]{64}$' -and $AgentImage -cmatch '^sha256:[a-f0-9]{64}$' -and
        $DeviceId -cmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,127}$' -and
        $OldImage -cmatch '^sha256:[a-f0-9]{64}$' -and $BrokerImage -cmatch '^sha256:[a-f0-9]{64}$' -and
        $SafetyCheck -is [scriptblock]) 'H454_RESTORE_PINS'
    $verifier=Read-H454PinnedBytes $VerifierPath $VerifierSha256
    $verifierText=[Text.UTF8Encoding]::new($false,$true).GetString($verifier).Trim()
    Require-H454 ($verifierText.Length -gt 0 -and $verifierText.Length -le 8192) 'H454_RESTORE_VERIFIER'
    $stateArgs=@($StateDir,$Lock,$MarkerSha256,$SafetyCheck,$Launcher,$LauncherSha256,$AgentId,$AgentImage,$AgentName,
        $OldImage,$BrokerImage,$CaSha256,$DockerSha256)
    $snapshot=Get-H454OriginalRestoreState @stateArgs
    if(-not $Apply){return [pscustomobject]@{Status='PREFLIGHT';Running=$snapshot.Agent.State.Running;
        OnBridge=$snapshot.OnBridge;OnPrivate=$snapshot.OnPrivate}}
    Require-H454 ($null -ne $TokenBytes -and $TokenBytes.Length -ge 48 -and $TokenBytes.Length -le 264 -and
        $null -ne $AgentBytes -and $AgentBytes.Length -gt 0 -and $AgentBytes.Length -le 16384) 'H454_RESTORE_CREDENTIAL'
    $encoding=[Text.UTF8Encoding]::new($false,$true)
    $token=$encoding.GetString($TokenBytes);$agentText=$encoding.GetString($AgentBytes)
    $surrogate='brc_dev_'+('s'*43)
    Require-H454 ($token -cmatch '^brc_dev_[A-Za-z0-9_-]{40,256}$' -and $token -cne $surrogate -and
        $agentText.IndexOf($token,[StringComparison]::Ordinal) -lt 0) 'H454_RESTORE_CREDENTIAL'
    $rawAgent=ConvertFrom-Json -InputObject $agentText -ErrorAction Stop
    Require-H454 ($rawAgent.pairedAt -ceq 'manual' -and $rawAgent.deviceToken -ceq $surrogate) 'H454_RESTORE_CREDENTIAL'
    $validated=Convert-H454SecureCredential $agentText $DeviceId 'http://host.docker.internal:38180'
    $agentCredential=ConvertFrom-Json -InputObject $validated -ErrorAction Stop
    Require-H454 ($agentCredential.deviceToken -ceq $surrogate) 'H454_RESTORE_CREDENTIAL'
    if($RestageOnly){
        Require-H454 ($snapshot.Agent.State.Running -and $snapshot.OnPrivate -and -not $snapshot.OnBridge) 'H454_RESTORE_MONITOR_STATE'
    }
    $mutationFence=$null
    if($null -eq $TrialMutation){
        $mutationFence=Open-H454MutationFence $StateDir $Lock 'original-restore' $MarkerSha256
    }
    if($snapshot.OnBridge -and -not $snapshot.OnPrivate){
        Require-H454 (-not $snapshot.Agent.State.Running) 'H454_RESTORE_RUNNING_ROUTE'
        $snapshot=Get-H454OriginalRestoreState @stateArgs
        Require-H454 (-not $snapshot.Agent.State.Running -and $snapshot.OnBridge -and -not $snapshot.OnPrivate) 'H454_RESTORE_STATE'
        $connected=Invoke-H454OriginalMutation @('network','connect',$snapshot.Plan.Id,$AgentId)
        Require-H454 ($connected.Code -eq 0) 'H454_RESTORE_CONNECT'
        $snapshot=Get-H454OriginalRestoreState @stateArgs
    }
    if($snapshot.OnBridge -and $snapshot.OnPrivate){
        Require-H454 (-not $snapshot.Agent.State.Running) 'H454_RESTORE_RUNNING_ROUTE'
        $snapshot=Get-H454OriginalRestoreState @stateArgs
        Require-H454 (-not $snapshot.Agent.State.Running -and $snapshot.OnBridge -and $snapshot.OnPrivate) 'H454_RESTORE_STATE'
        $disconnected=Invoke-H454OriginalMutation @('network','disconnect',$snapshot.Bridge.Id,$AgentId)
        Require-H454 ($disconnected.Code -eq 0) 'H454_RESTORE_DISCONNECT'
        $snapshot=Get-H454OriginalRestoreState @stateArgs
    }
    Require-H454 ($snapshot.OnPrivate -and -not $snapshot.OnBridge) 'H454_RESTORE_NETWORK'
    if(-not $snapshot.Agent.State.Running){
        $snapshot=Get-H454OriginalRestoreState @stateArgs
        Require-H454 (-not $snapshot.Agent.State.Running -and $snapshot.OnPrivate -and -not $snapshot.OnBridge) 'H454_RESTORE_STATE'
        $started=Invoke-H454OriginalMutation @('start',$AgentId)
        Require-H454 ($started.Code -eq 0) 'H454_RESTORE_START'
        $snapshot=Get-H454OriginalRestoreState @stateArgs
    }
    Assert-H454OriginalLiveRoute $snapshot $AgentId $DockerSha256
    $bootstrap="eval(Buffer.from(process.argv[1],'base64').toString())"
    $verifier64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($verifierText))
    $verified=Invoke-H454RecoveryDocker -Arguments @('exec','--interactive','--user','65534:65534',$AgentId,'node','-e',$bootstrap,$verifier64) -DockerSha256 $DockerSha256 -InputBytes $AgentBytes
    if($verified.Code -ne 0 -or $verified.Output -cne 'H454_STAGED_CREDENTIAL_MATCH'){
        Require-H454 (-not $RestageOnly) 'H454_RESTORE_STAGED_DRIFT'
        $empty="const f=require('node:fs');try{const d=f.lstatSync('/run/brc');if(!d.isDirectory()||d.isSymbolicLink()||d.uid!==65534||(d.mode&511)!==448)throw 0;for(const p of ['ready','device.json','config.json']){try{f.lstatSync('/run/brc/'+p);throw 0}catch(e){if(e.code!=='ENOENT')throw 0}}process.stdout.write('H454_STAGE_EMPTY')}catch{process.exit(2)}"
        $empty64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($empty))
        $emptyResult=Invoke-H454RecoveryDocker -Arguments @('exec','--user','65534:65534',$AgentId,'node','-e',$bootstrap,$empty64) -DockerSha256 $DockerSha256
        Require-H454 ($emptyResult.Code -eq 0 -and $emptyResult.Output -ceq 'H454_STAGE_EMPTY') 'H454_RESTORE_STAGED_DRIFT'
        $snapshot=Get-H454OriginalRestoreState @stateArgs
        Assert-H454OriginalLiveRoute $snapshot $AgentId $DockerSha256
        $stage=Invoke-H454OriginalMutation @('exec','--interactive','--user','65534:65534',$AgentId,'/bin/sh','/usr/local/bin/h15-stage.sh') $AgentBytes
        Require-H454 ($stage.Code -eq 0) 'H454_RESTORE_STAGE_AGENT'
        $verified=Invoke-H454RecoveryDocker -Arguments @('exec','--interactive','--user','65534:65534',$AgentId,'node','-e',$bootstrap,$verifier64) -DockerSha256 $DockerSha256 -InputBytes $AgentBytes
        Require-H454 ($verified.Code -eq 0 -and $verified.Output -ceq 'H454_STAGED_CREDENTIAL_MATCH') 'H454_RESTORE_STAGED_DRIFT'
    }
    $snapshot=Get-H454OriginalRestoreState @stateArgs
    Assert-H454OriginalLiveRoute $snapshot $AgentId $DockerSha256
    Require-H454 ((Get-FileHash -LiteralPath $VerifierPath -Algorithm SHA256).Hash -ceq $VerifierSha256) 'H454_RESTORE_VERIFIER'
    $staged=Invoke-H454OriginalMutation @('exec','--interactive','--user','65534:65534',$snapshot.Broker.Id,'node','/opt/hermes-rollback/stage.cjs') $TokenBytes
    Require-H454 ($staged.Code -eq 0 -and $staged.Output -ceq 'H454_BROKER_TOKEN_STAGED') 'H454_RESTORE_STAGE_BROKER'
    $snapshot=Get-H454OriginalRestoreState @stateArgs
    Assert-H454OriginalLiveRoute $snapshot $AgentId $DockerSha256
    if($null -ne $mutationFence){Close-H454MutationFence $StateDir $Lock $mutationFence}
    return [pscustomobject]@{Status='ORIGINAL_STAGED';AgentId=$AgentId;BrokerId=$snapshot.Broker.Id}
}
