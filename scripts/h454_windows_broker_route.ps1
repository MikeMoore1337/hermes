#requires -Version 5.1
# The original is stopped; the caller holds the runtime lock and checks it before each mutation.
function Prepare-H454RecoveryBroker(
    [string]$StateDir,[IO.FileStream]$Lock,[string]$MarkerSha256,[string]$OldImage,[string]$BrokerImage,
    [string]$CaSha256,[string]$DockerSha256,[scriptblock]$SafetyCheck,[switch]$Apply,[switch]$OwnerApproved
) {
    Require-H454 (-not $Apply -or $OwnerApproved) 'H454_BROKER_APPROVAL'
    Require-H454 ($MarkerSha256 -cmatch '^[A-F0-9]{64}$' -and $CaSha256 -cmatch '^[A-F0-9]{64}$' -and
        $DockerSha256 -cmatch '^[A-F0-9]{64}$' -and $OldImage -cmatch '^sha256:[a-f0-9]{64}$' -and
        $BrokerImage -cmatch '^sha256:[a-f0-9]{64}$' -and $BrokerImage -cne $OldImage -and
        $SafetyCheck -is [scriptblock]) 'H454_BROKER_PINS'
    Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
    $label=$MarkerSha256.Substring(0,32).ToLowerInvariant()
    $networkName='h454-recovery-'+$label;$oldName=$networkName+'-proxy';$brokerName=$networkName+'-broker'
    $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
    $old=Find-H454RecoveryObject 'container' $oldName $DockerSha256
    $broker=Find-H454RecoveryObject 'container' $brokerName $DockerSha256
    Require-H454 ($null -ne $network -and $null -ne $old) 'H454_BROKER_MISSING_ROUTE'
    $plan=Assert-H454RecoveryNetwork $network $networkName $label
    $bridge=Find-H454RecoveryObject 'network' 'bridge' $DockerSha256
    Require-H454 ($null -ne $bridge -and $bridge.Driver -ceq 'bridge' -and $bridge.Id -cmatch '^[a-f0-9]{64}$') 'H454_BROKER_BRIDGE'
    $images=Invoke-H454RecoveryDocker -Arguments @('image','inspect',$BrokerImage) -DockerSha256 $DockerSha256
    Require-H454 ($images.Code -eq 0 -and $images.Output.Length -gt 0) 'H454_BROKER_IMAGE'
    $images=@($images.Output|ConvertFrom-Json -ErrorAction Stop)
    Require-H454 ($images.Count -eq 1 -and $images[0].Id -ceq $BrokerImage) 'H454_BROKER_IMAGE'
    $command=@($old.Config.Cmd);Require-H454 ($command.Count -eq 3) 'H454_BROKER_OLD_PROXY'
    $hostAddress=[string]$command[0];$hostNumber=Get-H454IPv4Number $hostAddress
    Require-H454 ((Test-H454PrivateIPv4 $hostNumber) -and ($hostNumber -lt $plan.Base -or $hostNumber -gt $plan.Last)) 'H454_BROKER_HOST'
    $oldConnected=($null -ne $old.NetworkSettings.Networks.PSObject.Properties[$networkName])
    Assert-H454RecoveryProxy $old $oldName $label $OldImage $hostAddress $CaSha256 $plan $bridge.Id -Connected:$oldConnected
    Require-H454 (-not $old.State.Running -or ($oldConnected -and $null -eq $broker)) 'H454_BROKER_OLD_PROXY'
    if($null -ne $broker){
        Require-H454 (-not $oldConnected -and -not $old.State.Running) 'H454_BROKER_COLLISION'
        $connected=($null -ne $broker.NetworkSettings.Networks.PSObject.Properties[$networkName])
        Assert-H454RecoveryProxy $broker $brokerName $label $BrokerImage $hostAddress $CaSha256 $plan $bridge.Id `
            -Connected:$connected -EntrypointPath '/opt/hermes-rollback/broker.mjs'
        Require-H454 (-not $broker.State.Running -or $connected) 'H454_BROKER_NETWORK'
        Assert-H454RecoveryRouteMembers $network $broker $DockerSha256
    }else{Assert-H454RecoveryRouteMembers $network $old $DockerSha256}
    if(-not $Apply){return [pscustomobject]@{Status='PREFLIGHT';OldRunning=$old.State.Running;BrokerPresent=($null -ne $broker)}}
    $mutationFence=Open-H454MutationFence $StateDir $Lock 'broker-route' $MarkerSha256
    if($old.State.Running){
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $old=Find-H454RecoveryObject 'container' $oldName $DockerSha256
        $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
        $null=Assert-H454RecoveryNetwork $network $networkName $label
        Assert-H454RecoveryProxy $old $oldName $label $OldImage $hostAddress $CaSha256 $plan $bridge.Id -Connected
        Assert-H454RecoveryRouteMembers $network $old $DockerSha256
        Require-H454 ($old.State.Running) 'H454_BROKER_OLD_PROXY'
        $stopped=Invoke-H454RecoveryDocker -Arguments @('stop','--time','5',$old.Id) -DockerSha256 $DockerSha256
        Require-H454 ($stopped.Code -eq 0) 'H454_BROKER_OLD_STOP'
        $old=Find-H454RecoveryObject 'container' $oldName $DockerSha256
        Require-H454 ($null -ne $old -and -not $old.State.Running) 'H454_BROKER_OLD_STOP'
        Assert-H454RecoveryProxy $old $oldName $label $OldImage $hostAddress $CaSha256 $plan $bridge.Id -Connected
    }
    if($oldConnected){
        $old=Find-H454RecoveryObject 'container' $oldName $DockerSha256
        Require-H454 ($null -ne $old -and -not $old.State.Running) 'H454_BROKER_OLD_PROXY'
        Assert-H454RecoveryProxy $old $oldName $label $OldImage $hostAddress $CaSha256 $plan $bridge.Id -Connected
        $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
        $null=Assert-H454RecoveryNetwork $network $networkName $label
        Assert-H454RecoveryRouteMembers $network $old $DockerSha256
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $disconnected=Invoke-H454RecoveryDocker -Arguments @('network','disconnect',$plan.Id,$old.Id) -DockerSha256 $DockerSha256
        Require-H454 ($disconnected.Code -eq 0) 'H454_BROKER_OLD_DISCONNECT'
        $old=Find-H454RecoveryObject 'container' $oldName $DockerSha256
        Require-H454 ($null -ne $old -and -not $old.State.Running) 'H454_BROKER_OLD_DISCONNECT'
        Assert-H454RecoveryProxy $old $oldName $label $OldImage $hostAddress $CaSha256 $plan $bridge.Id
    }
    if($null -eq $broker){
        $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
        $null=Assert-H454RecoveryNetwork $network $networkName $label
        Assert-H454RecoveryRouteMembers $network $null $DockerSha256
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $created=Invoke-H454RecoveryDocker -Arguments @('create','--pull=never','--name',$brokerName,'--network','bridge',
            '--restart','unless-stopped','--read-only','--user','65534:65534','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--pids-limit','32','--memory','128m',
            '--label',('com.hermes.h454.recovery='+$label),$BrokerImage,$hostAddress,$CaSha256.ToLowerInvariant(),$plan.Cidr) -DockerSha256 $DockerSha256
        Require-H454 ($created.Code -eq 0 -and $created.Output.Trim() -cmatch '^[a-f0-9]{64}$') 'H454_BROKER_CREATE'
        $broker=Find-H454RecoveryObject 'container' $brokerName $DockerSha256
        Require-H454 ($null -ne $broker -and $broker.Id -ceq $created.Output.Trim()) 'H454_BROKER_CREATE'
    }
    $connected=($null -ne $broker.NetworkSettings.Networks.PSObject.Properties[$networkName])
    Assert-H454RecoveryProxy $broker $brokerName $label $BrokerImage $hostAddress $CaSha256 $plan $bridge.Id `
        -Connected:$connected -EntrypointPath '/opt/hermes-rollback/broker.mjs'
    if(-not $connected){
        Require-H454 (-not $broker.State.Running) 'H454_BROKER_NETWORK'
        $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
        $null=Assert-H454RecoveryNetwork $network $networkName $label
        Assert-H454RecoveryRouteMembers $network $broker $DockerSha256
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $attached=Invoke-H454RecoveryDocker -Arguments @('network','connect','--alias','host.docker.internal',$plan.Id,$broker.Id) -DockerSha256 $DockerSha256
        Require-H454 ($attached.Code -eq 0) 'H454_BROKER_CONNECT'
        $broker=Find-H454RecoveryObject 'container' $brokerName $DockerSha256
    }
    Assert-H454RecoveryProxy $broker $brokerName $label $BrokerImage $hostAddress $CaSha256 $plan $bridge.Id `
        -Connected -EntrypointPath '/opt/hermes-rollback/broker.mjs'
    if(-not $broker.State.Running){
        $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
        $null=Assert-H454RecoveryNetwork $network $networkName $label
        Assert-H454RecoveryRouteMembers $network $broker $DockerSha256
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $started=Invoke-H454RecoveryDocker -Arguments @('start',$broker.Id) -DockerSha256 $DockerSha256
        Require-H454 ($started.Code -eq 0) 'H454_BROKER_START'
        $broker=Find-H454RecoveryObject 'container' $brokerName $DockerSha256
    }
    Require-H454 ($null -ne $broker -and $broker.State.Running) 'H454_BROKER_START'
    Assert-H454RecoveryProxy $broker $brokerName $label $BrokerImage $hostAddress $CaSha256 $plan $bridge.Id `
        -Connected -EntrypointPath '/opt/hermes-rollback/broker.mjs'
    $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
    $plan=Assert-H454RecoveryNetwork $network $networkName $label
    Assert-H454RecoveryRouteMembers $network $broker $DockerSha256
    $members=@($network.Containers.PSObject.Properties|ForEach-Object {$_.Name})
    Require-H454 ($members.Count -eq 1 -and $members[0] -ceq $broker.Id) 'H454_BROKER_MEMBERS'
    $privateAddress=[string]$broker.NetworkSettings.Networks.PSObject.Properties[$networkName].Value.IPAddress
    $upstreamAddress=[string]$broker.NetworkSettings.Networks.bridge.IPAddress
    $privateNumber=Get-H454IPv4Number $privateAddress;$upstreamNumber=Get-H454IPv4Number $upstreamAddress
    $gateway=Get-H454IPv4Number ([string]@($network.IPAM.Config)[0].Gateway)
    Require-H454 ($privateNumber -gt $plan.Base -and $privateNumber -lt $plan.Last -and $privateNumber -ne $gateway -and
        (Test-H454PrivateIPv4 $upstreamNumber) -and ($upstreamNumber -lt $plan.Base -or $upstreamNumber -gt $plan.Last)) 'H454_BROKER_NETWORK'
    $probe="const n=require('node:net');async function c(h,p,yes){await new Promise((r,j)=>{const s=n.connect(p,h);s.on('connect',()=>{s.destroy();yes?r():j(0)});s.on('error',e=>!yes&&e.code==='ECONNREFUSED'?r():j(0));s.setTimeout(3000,()=>{s.destroy();j(0)})})} (async()=>{await c(process.argv[2],38180,true);await c(process.argv[3],38180,false);await c(process.argv[2],38181,false);await c(process.argv[3],38181,false);await c('127.0.0.1',38181,true);console.log('H454_BROKER_LISTENERS=PASS')})().catch(()=>process.exit(2))"
    $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($probe))
    $bootstrap="eval(Buffer.from(process.argv[1],'base64').toString())"
    $ready=$false
    for($attempt=0;$attempt -lt 10 -and -not $ready;$attempt++){
        $checked=Invoke-H454RecoveryDocker -Arguments @('exec','--user','65534:65534',$broker.Id,'node','-e',$bootstrap,$encoded,$privateAddress,$upstreamAddress) -DockerSha256 $DockerSha256
        $ready=($checked.Code -eq 0 -and $checked.Output.Trim() -ceq 'H454_BROKER_LISTENERS=PASS')
        if(-not $ready){Start-Sleep -Milliseconds 250}
    }
    Require-H454 $ready 'H454_BROKER_LISTENERS'
    Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
    $old=Find-H454RecoveryObject 'container' $oldName $DockerSha256
    $broker=Find-H454RecoveryObject 'container' $brokerName $DockerSha256
    $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
    $plan=Assert-H454RecoveryNetwork $network $networkName $label
    Require-H454 ($null -ne $old -and -not $old.State.Running -and $null -ne $broker -and $broker.State.Running) 'H454_BROKER_STATE'
    Assert-H454RecoveryProxy $old $oldName $label $OldImage $hostAddress $CaSha256 $plan $bridge.Id
    Assert-H454RecoveryProxy $broker $brokerName $label $BrokerImage $hostAddress $CaSha256 $plan $bridge.Id `
        -Connected -EntrypointPath '/opt/hermes-rollback/broker.mjs'
    Assert-H454RecoveryRouteMembers $network $broker $DockerSha256
    $members=@($network.Containers.PSObject.Properties|ForEach-Object {$_.Name})
    Require-H454 ($members.Count -eq 1 -and $members[0] -ceq $broker.Id -and
        [string]$broker.NetworkSettings.Networks.PSObject.Properties[$networkName].Value.IPAddress -ceq $privateAddress -and
        [string]$broker.NetworkSettings.Networks.bridge.IPAddress -ceq $upstreamAddress) 'H454_BROKER_STATE'
    Close-H454MutationFence $StateDir $Lock $mutationFence
    return [pscustomobject]@{Status='BROKER_READY';NetworkId=$plan.Id;BrokerId=$broker.Id;OldProxyId=$old.Id}
}
