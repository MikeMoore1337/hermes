#requires -Version 5.1
# The caller owns the lock and supplies a trusted safety check for each mutation.
function Find-H454RecoveryObject([string]$Kind,[string]$Name,[string]$DockerSha256) {
    Require-H454 ($Kind -cin @('network','container') -and $Name -cmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,127}$') 'H454_ROUTE_INPUT'
    $listArgs=if($Kind -ceq 'network'){@('network','ls','--no-trunc','--quiet','--filter',('name='+$Name))}
        else{@('container','ls','--all','--no-trunc','--quiet','--filter',('name='+$Name))}
    $list=Invoke-H454RecoveryDocker -Arguments $listArgs -DockerSha256 $DockerSha256
    Require-H454 ($list.Code -eq 0) 'H454_ROUTE_LIST'
    $ids=@($list.Output -split "`r?`n" | Where-Object {-not [string]::IsNullOrWhiteSpace($_)})
    Require-H454 ($ids.Count -le 128) 'H454_ROUTE_LIST'
    $found=@()
    foreach($id in $ids){
        Require-H454 ($id -cmatch '^[a-f0-9]{64}$') 'H454_ROUTE_LIST'
        $inspection=Invoke-H454RecoveryDocker -Arguments @($Kind,'inspect',$id) -DockerSha256 $DockerSha256
        Require-H454 ($inspection.Code -eq 0 -and $inspection.Output.Length -gt 0) 'H454_ROUTE_INSPECT'
        $items=@($inspection.Output | ConvertFrom-Json -ErrorAction Stop)
        Require-H454 ($items.Count -eq 1 -and $items[0].Id -ceq $id) 'H454_ROUTE_INSPECT'
        $actual=if($Kind -ceq 'container'){[string]$items[0].Name -creplace '^/',''}else{[string]$items[0].Name}
        if($actual -ceq $Name){$found+=@($items[0])}
    }
    Require-H454 ($found.Count -le 1) 'H454_ROUTE_COLLISION'
    if($found.Count -eq 1){return $found[0]}
    return $null
}

function Assert-H454RecoveryNetwork([object]$Network,[string]$Name,[string]$LabelValue) {
    Require-H454 ($null -ne $Network -and $Network.Id -cmatch '^[a-f0-9]{64}$' -and $Network.Name -ceq $Name -and
        $Network.Driver -ceq 'bridge' -and $Network.Internal -is [bool] -and $Network.Internal -and
        $Network.EnableIPv6 -is [bool] -and -not $Network.EnableIPv6 -and $null -ne $Network.Labels) 'H454_ROUTE_NETWORK'
    $label=$Network.Labels.PSObject.Properties['com.hermes.h454.recovery']
    Require-H454 ($null -ne $label -and $label.Value -ceq $LabelValue) 'H454_ROUTE_COLLISION'
    $configs=@($Network.IPAM.Config)
    Require-H454 ($configs.Count -eq 1 -and [string]$configs[0].Subnet -cmatch '^((?:[0-9]{1,3}\.){3}[0-9]{1,3})/([8-9]|[12][0-9]|30)$') 'H454_ROUTE_NETWORK'
    $cidr=[string]$configs[0].Subnet;$base=Get-H454IPv4Number $Matches[1];$prefix=[int]$Matches[2]
    $size=[uint64]1 -shl (32-$prefix);$last=$base+$size-1;$gateway=Get-H454IPv4Number ([string]$configs[0].Gateway)
    Require-H454 (($base % $size) -eq 0 -and (Test-H454PrivateIPv4 $base) -and
        (Test-H454PrivateIPv4 $last) -and $gateway -gt $base -and $gateway -lt $last) 'H454_ROUTE_NETWORK'
    return [pscustomobject]@{Id=[string]$Network.Id;Name=$Name;Cidr=$cidr;Base=$base;Last=$last}
}

function Assert-H454RecoveryProxy(
    [object]$Proxy,[string]$Name,[string]$LabelValue,[string]$Image,[string]$HostAddress,
    [string]$CaSha256,[object]$Network,[string]$BridgeId,[switch]$Connected,
    [string]$EntrypointPath='/opt/hermes-rollback/proxy.mjs',
    [switch]$AllowStoppedLegacyProxyBridge
) {
    Require-H454 ($EntrypointPath -cin @('/opt/hermes-rollback/proxy.mjs','/opt/hermes-rollback/broker.mjs') -and
        $null -ne $Proxy -and $Proxy.Id -cmatch '^[a-f0-9]{64}$' -and
        $Proxy.Name -ceq ('/'+$Name) -and $Proxy.Image -ceq $Image -and
        $Proxy.Config.Labels.'com.hermes.h454.recovery' -ceq $LabelValue -and
        $Proxy.Config.User -ceq '65534:65534' -and @($Proxy.Config.Entrypoint).Count -eq 2 -and
        [string]$Proxy.Config.Entrypoint[0] -ceq 'node' -and
        [string]$Proxy.Config.Entrypoint[1] -ceq $EntrypointPath) 'H454_ROUTE_PROXY'
    Require-H454 ($Proxy.State.Running -is [bool] -and $Proxy.State.Paused -is [bool] -and -not $Proxy.State.Paused -and
        $Proxy.State.Restarting -is [bool] -and -not $Proxy.State.Restarting -and $Proxy.State.Dead -is [bool] -and -not $Proxy.State.Dead -and
        (($Proxy.State.Running -and [string]$Proxy.State.Status -ceq 'running') -or
         (-not $Proxy.State.Running -and [string]$Proxy.State.Status -cin @('created','exited')))) 'H454_ROUTE_PROXY'
    $cmd=@($Proxy.Config.Cmd)
    Require-H454 ($cmd.Count -eq 3 -and [string]$cmd[0] -ceq $HostAddress -and
        [string]$cmd[1] -ceq $CaSha256.ToLowerInvariant() -and [string]$cmd[2] -ceq $Network.Cidr) 'H454_ROUTE_PROXY'
    $hostConfig=$Proxy.HostConfig
    Require-H454 ($hostConfig.NetworkMode -ceq 'bridge' -and $hostConfig.ReadonlyRootfs -is [bool] -and $hostConfig.ReadonlyRootfs -and
        $hostConfig.Privileged -is [bool] -and -not $hostConfig.Privileged -and @($hostConfig.CapDrop) -ccontains 'ALL' -and
        ($null -eq $hostConfig.CapAdd -or @($hostConfig.CapAdd).Count -eq 0) -and
        @($hostConfig.SecurityOpt).Count -eq 1 -and [string]$hostConfig.SecurityOpt[0] -ceq 'no-new-privileges' -and
        $hostConfig.PidsLimit -eq 32 -and $hostConfig.Memory -eq 134217728 -and
        $hostConfig.RestartPolicy.Name -ceq 'unless-stopped' -and $hostConfig.PublishAllPorts -is [bool] -and -not $hostConfig.PublishAllPorts -and
        [string]$hostConfig.PidMode -cnotmatch '^(?:host|container:)' -and [string]$hostConfig.IpcMode -cnotmatch '^(?:host|container:)' -and
        ($null -eq $hostConfig.PortBindings -or @($hostConfig.PortBindings.PSObject.Properties).Count -eq 0) -and
        ($null -eq $hostConfig.Binds -or @($hostConfig.Binds).Count -eq 0) -and
        ($null -eq $hostConfig.Devices -or @($hostConfig.Devices).Count -eq 0) -and
        ($null -eq $hostConfig.DeviceRequests -or @($hostConfig.DeviceRequests).Count -eq 0) -and
        @($Proxy.Mounts).Count -eq 0) 'H454_ROUTE_PROXY'
    foreach($entry in @($Proxy.Config.Env)){
        Require-H454 ($entry -is [string] -and $entry -cnotmatch '^(?:NODE_OPTIONS|NODE_PATH|NODE_EXTRA_CA_CERTS|NODE_TLS_REJECT_UNAUTHORIZED|LD_PRELOAD|LD_LIBRARY_PATH)=') 'H454_ROUTE_PROXY_ENV'
    }
    $members=@($Proxy.NetworkSettings.Networks.PSObject.Properties)
    $bridge=$Proxy.NetworkSettings.Networks.PSObject.Properties['bridge']
    # Docker Desktop can leave a stopped legacy proxy with a stale, nonempty
    # bridge ID after bridge recreation. Never relax identity for a running
    # endpoint, the broker, a newly created proxy, or any attached private net.
    # Only the caller explicitly inspecting the owned *stopped old proxy*
    # may opt in; all image, label, capability and alias checks still apply.
    $legacyStoppedBridge=($AllowStoppedLegacyProxyBridge -and -not $Connected -and
        $EntrypointPath -ceq '/opt/hermes-rollback/proxy.mjs' -and
        $Name -cmatch '^h454-recovery-[a-f0-9]{32}-proxy
    foreach($alias in @($bridge.Value.Aliases)){
        Require-H454 ($null -eq $alias -or ($alias -is [string] -and
            -not $alias.TrimEnd('.').Equals('host.docker.internal',[StringComparison]::OrdinalIgnoreCase))) 'H454_ROUTE_PROXY_NETWORK'
    }
    if($Connected){
        $private=$Proxy.NetworkSettings.Networks.PSObject.Properties[$Network.Name]
        Require-H454 ($members.Count -eq 2 -and $null -ne $private -and ($private.Value.NetworkID -ceq $Network.Id -or
            (-not $Proxy.State.Running -and [string]::IsNullOrEmpty([string]$private.Value.NetworkID))) -and
            @($private.Value.Aliases) -ccontains 'host.docker.internal') 'H454_ROUTE_PROXY_NETWORK'
    }else{Require-H454 ($members.Count -eq 1) 'H454_ROUTE_PROXY_NETWORK'}
}

function Assert-H454RecoveryRouteMembers([object]$Network,[object]$Proxy,[string]$DockerSha256,[string]$AgentId='') {
    Require-H454 ([string]::IsNullOrEmpty($AgentId) -or ($AgentId -cmatch '^[a-f0-9]{64}$' -and
        ($null -eq $Proxy -or $AgentId -cne $Proxy.Id))) 'H454_ROUTE_MEMBERS'
    Require-H454 ($null -ne $Network -and $null -ne $Network.Containers) 'H454_ROUTE_MEMBERS'
    $members=@($Network.Containers.PSObject.Properties | ForEach-Object {$_.Name})
    foreach($member in $members){
        Require-H454 (($null -ne $Proxy -and $member -ceq $Proxy.Id) -or
            (-not [string]::IsNullOrEmpty($AgentId) -and $member -ceq $AgentId)) 'H454_ROUTE_MEMBERS'
    }
    Require-H454 ($members.Count -le 2 -and ($members.Count -le 1 -or -not [string]::IsNullOrEmpty($AgentId))) 'H454_ROUTE_MEMBERS'
    $list=Invoke-H454RecoveryDocker -Arguments @('container','ls','--all','--no-trunc','--format','{{.ID}}|{{.Networks}}') -DockerSha256 $DockerSha256
    Require-H454 ($list.Code -eq 0) 'H454_ROUTE_MEMBERS'
    $rows=@($list.Output -split "`r?`n" | Where-Object {-not [string]::IsNullOrWhiteSpace($_)})
    Require-H454 ($rows.Count -le 2048) 'H454_ROUTE_MEMBERS'
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($row in $rows){
        Require-H454 ($row -cmatch '^([a-f0-9]{64})\|(?:([a-zA-Z0-9_.-]+(?:,[a-zA-Z0-9_.-]+)*))?$' -and
            $seen.Add($Matches[1])) 'H454_ROUTE_MEMBERS'
        $id=$Matches[1];$names=if([string]::IsNullOrEmpty($Matches[2])){@()}else{@($Matches[2].Split(','))}
        if($names -ccontains [string]$Network.Name){
            Require-H454 (($null -ne $Proxy -and $id -ceq $Proxy.Id) -or
                (-not [string]::IsNullOrEmpty($AgentId) -and $id -ceq $AgentId)) 'H454_ROUTE_MEMBERS'
        }
    }
}

function Assert-H454RecoveryProbe(
    [object]$Probe,[string]$Name,[string]$LabelValue,[string]$Image,[string]$BridgeId,[string]$Bootstrap,[string]$Encoded
) {
    Require-H454 ($null -ne $Probe -and $Probe.Id -cmatch '^[a-f0-9]{64}$' -and $Probe.Name -ceq ('/'+$Name) -and
        $Probe.Image -ceq $Image -and $Probe.Config.Labels.'com.hermes.h454.recovery-probe' -ceq $LabelValue -and
        $Probe.Config.User -ceq '65534:65534' -and @($Probe.Config.Entrypoint).Count -eq 1 -and
        [string]$Probe.Config.Entrypoint[0] -ceq 'node') 'H454_ROUTE_PROBE_COLLISION'
    $cmd=@($Probe.Config.Cmd);$hostConfig=$Probe.HostConfig
    Require-H454 ($cmd.Count -eq 3 -and [string]$cmd[0] -ceq '-e' -and [string]$cmd[1] -ceq $Bootstrap -and
        [string]$cmd[2] -ceq $Encoded -and $hostConfig.NetworkMode -ceq 'bridge' -and
        $hostConfig.ReadonlyRootfs -is [bool] -and $hostConfig.ReadonlyRootfs -and
        $hostConfig.Privileged -is [bool] -and -not $hostConfig.Privileged -and $hostConfig.AutoRemove -is [bool] -and $hostConfig.AutoRemove -and
        @($hostConfig.CapDrop) -ccontains 'ALL' -and ($null -eq $hostConfig.CapAdd -or @($hostConfig.CapAdd).Count -eq 0) -and
        @($hostConfig.SecurityOpt).Count -eq 1 -and [string]$hostConfig.SecurityOpt[0] -ceq 'no-new-privileges' -and
        $hostConfig.PidsLimit -eq 32 -and $hostConfig.Memory -eq 134217728 -and $hostConfig.RestartPolicy.Name -ceq 'no' -and
        $hostConfig.PublishAllPorts -is [bool] -and -not $hostConfig.PublishAllPorts -and
        ($null -eq $hostConfig.PortBindings -or @($hostConfig.PortBindings.PSObject.Properties).Count -eq 0) -and
        ($null -eq $hostConfig.Binds -or @($hostConfig.Binds).Count -eq 0) -and @($Probe.Mounts).Count -eq 0) 'H454_ROUTE_PROBE_COLLISION'
    foreach($entry in @($Probe.Config.Env)){
        Require-H454 ($entry -is [string] -and $entry -cnotmatch '^(?:NODE_OPTIONS|NODE_PATH|NODE_EXTRA_CA_CERTS|NODE_TLS_REJECT_UNAUTHORIZED|LD_PRELOAD|LD_LIBRARY_PATH)=') 'H454_ROUTE_PROBE_COLLISION'
    }
    $networks=@($Probe.NetworkSettings.Networks.PSObject.Properties)
    $bridge=$Probe.NetworkSettings.Networks.PSObject.Properties['bridge']
    Require-H454 ($Probe.State.Running -is [bool] -and $networks.Count -eq 1 -and $null -ne $bridge -and
        ($bridge.Value.NetworkID -ceq $BridgeId -or (-not $Probe.State.Running -and
            [string]::IsNullOrEmpty([string]$bridge.Value.NetworkID)))) 'H454_ROUTE_PROBE_COLLISION'
}

function Assert-H454RecoveryRouteSafety(
    [string]$StateDir,[IO.FileStream]$Lock,[string]$MarkerSha256,[scriptblock]$SafetyCheck
) {
    Assert-H454RecoveryLock $StateDir $Lock
    Assert-H454WssTaskFile (Join-Path $StateDir 'h454-wss-transition.pending') $MarkerSha256 4096
    $safe=@(& $SafetyCheck)
    Require-H454 ($safe.Count -eq 1 -and $safe[0] -is [bool] -and $safe[0]) 'H454_ROUTE_SAFETY'
}

function Prepare-H454RecoveryRoute(
    [string]$StateDir,[IO.FileStream]$Lock,[string]$MarkerSha256,[string]$ProxyImage,
    [string]$CaSha256,[string]$DockerSha256,[scriptblock]$SafetyCheck,[switch]$Apply,[switch]$OwnerApproved
) {
    Require-H454 (-not $Apply -or $OwnerApproved) 'H454_ROUTE_APPROVAL'
    Require-H454 ($MarkerSha256 -cmatch '^[A-F0-9]{64}$' -and $CaSha256 -cmatch '^[A-F0-9]{64}$' -and
        $DockerSha256 -cmatch '^[A-F0-9]{64}$' -and $ProxyImage -cmatch '^sha256:[a-f0-9]{64}$' -and
        $SafetyCheck -is [scriptblock]) 'H454_ROUTE_PINS'
    Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
    $labelValue=$MarkerSha256.Substring(0,32).ToLowerInvariant()
    $networkName='h454-recovery-'+$labelValue;$proxyName=$networkName+'-proxy';$probeName=$networkName+'-probe'
    $imageResult=Invoke-H454RecoveryDocker -Arguments @('image','inspect',$ProxyImage) -DockerSha256 $DockerSha256
    Require-H454 ($imageResult.Code -eq 0 -and $imageResult.Output.Length -gt 0) 'H454_ROUTE_IMAGE'
    $images=@($imageResult.Output | ConvertFrom-Json -ErrorAction Stop)
    Require-H454 ($images.Count -eq 1 -and $images[0].Id -ceq $ProxyImage) 'H454_ROUTE_IMAGE'
    $bridge=Find-H454RecoveryObject 'network' 'bridge' $DockerSha256
    Require-H454 ($null -ne $bridge -and $bridge.Driver -ceq 'bridge' -and $bridge.Id -cmatch '^[a-f0-9]{64}$') 'H454_ROUTE_BRIDGE'
    $lookup="const d=require('node:dns');d.lookup('host.docker.internal',{all:true},(e,a)=>{if(e)process.exit(2);const x=[...new Set(a.filter(z=>z.family===4).map(z=>z.address))];if(x.length!==1)process.exit(3);console.log(x[0])})"
    $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($lookup))
    $bootstrap="eval(Buffer.from(process.argv[1],'base64').toString())"
    $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
    $proxy=Find-H454RecoveryObject 'container' $proxyName $DockerSha256
    $probe=Find-H454RecoveryObject 'container' $probeName $DockerSha256
    Require-H454 ($null -eq $proxy -or $null -ne $network) 'H454_ROUTE_COLLISION'
    if($null -ne $probe){Assert-H454RecoveryProbe $probe $probeName $labelValue $ProxyImage $bridge.Id $bootstrap $encoded}
    $plan=$null
    if($null -ne $network){
        $plan=Assert-H454RecoveryNetwork $network $networkName $labelValue
        Assert-H454RecoveryRouteMembers $network $proxy $DockerSha256
    }
    if($null -ne $proxy){
        $cmd=@($proxy.Config.Cmd);Require-H454 ($cmd.Count -eq 3) 'H454_ROUTE_PROXY'
        $hostAddress=[string]$cmd[0];$hostNumber=Get-H454IPv4Number $hostAddress
        Require-H454 ((Test-H454PrivateIPv4 $hostNumber) -and ($hostNumber -lt $plan.Base -or $hostNumber -gt $plan.Last)) 'H454_ROUTE_HOST'
        $connected=($null -ne $proxy.NetworkSettings.Networks.PSObject.Properties[$networkName])
        Assert-H454RecoveryProxy $proxy $proxyName $labelValue $ProxyImage $hostAddress $CaSha256 $plan $bridge.Id -Connected:$connected
        Require-H454 ($proxy.State.Running -is [bool] -and $proxy.State.Paused -is [bool] -and -not $proxy.State.Paused -and
            $proxy.State.Restarting -is [bool] -and -not $proxy.State.Restarting -and $proxy.State.Dead -is [bool] -and
            -not $proxy.State.Dead -and (-not $proxy.State.Running -or $connected)) 'H454_ROUTE_PROXY_NETWORK'
    }
    if(-not $Apply){return [pscustomobject]@{Status='PREFLIGHT';NetworkPresent=($null -ne $network);ProxyPresent=($null -ne $proxy);ProbePresent=($null -ne $probe)}}
    if($null -ne $probe){
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $currentProbe=Find-H454RecoveryObject 'container' $probeName $DockerSha256
        Require-H454 ($null -ne $currentProbe -and $currentProbe.Id -ceq $probe.Id) 'H454_ROUTE_PROBE_COLLISION'
        Assert-H454RecoveryProbe $currentProbe $probeName $labelValue $ProxyImage $bridge.Id $bootstrap $encoded
        $removed=Invoke-H454RecoveryDocker -Arguments @('container','rm','--force',$currentProbe.Id) -DockerSha256 $DockerSha256
        Require-H454 ($removed.Code -eq 0 -and $null -eq (Find-H454RecoveryObject 'container' $probeName $DockerSha256)) 'H454_ROUTE_PROBE_REMAINS'
    }
    if($null -eq $network){
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $created=Invoke-H454RecoveryDocker -Arguments @('network','create','--internal','--label',('com.hermes.h454.recovery='+$labelValue),$networkName) -DockerSha256 $DockerSha256
        Require-H454 ($created.Code -eq 0 -and $created.Output.Trim() -cmatch '^[a-f0-9]{64}$') 'H454_ROUTE_CREATE'
        $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
        Require-H454 ($null -ne $network -and $network.Id -ceq $created.Output.Trim()) 'H454_ROUTE_CREATE'
        $plan=Assert-H454RecoveryNetwork $network $networkName $labelValue
        Assert-H454RecoveryRouteMembers $network $null $DockerSha256
    }
    Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
    $resolved=Invoke-H454RecoveryDocker -Arguments @('run','--rm','--pull=never','--network','bridge','--name',$probeName,
        '--label',('com.hermes.h454.recovery-probe='+$labelValue),'--read-only','--user','65534:65534','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--pids-limit','32','--memory','128m','--entrypoint','node',$ProxyImage,'-e',$bootstrap,$encoded) -DockerSha256 $DockerSha256
    Require-H454 ($resolved.Code -eq 0) 'H454_ROUTE_HOST'
    Require-H454 ($null -eq (Find-H454RecoveryObject 'container' $probeName $DockerSha256)) 'H454_ROUTE_PROBE_REMAINS'
    $hostAddress=$resolved.Output.Trim();$hostNumber=Get-H454IPv4Number $hostAddress
    Require-H454 ((Test-H454PrivateIPv4 $hostNumber) -and ($hostNumber -lt $plan.Base -or $hostNumber -gt $plan.Last)) 'H454_ROUTE_HOST'
    if($null -eq $proxy){
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $created=Invoke-H454RecoveryDocker -Arguments @('create','--pull=never','--name',$proxyName,'--network','bridge',
            '--restart','unless-stopped','--read-only','--user','65534:65534','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--pids-limit','32','--memory','128m',
            '--label',('com.hermes.h454.recovery='+$labelValue),$ProxyImage,$hostAddress,$CaSha256.ToLowerInvariant(),$plan.Cidr) -DockerSha256 $DockerSha256
        Require-H454 ($created.Code -eq 0 -and $created.Output.Trim() -cmatch '^[a-f0-9]{64}$') 'H454_ROUTE_CREATE'
        $proxy=Find-H454RecoveryObject 'container' $proxyName $DockerSha256
        Require-H454 ($null -ne $proxy -and $proxy.Id -ceq $created.Output.Trim()) 'H454_ROUTE_CREATE'
    }
    $connected=($null -ne $proxy.NetworkSettings.Networks.PSObject.Properties[$networkName])
    Assert-H454RecoveryProxy $proxy $proxyName $labelValue $ProxyImage $hostAddress $CaSha256 $plan $bridge.Id -Connected:$connected
    if(-not $connected){
        Require-H454 (-not $proxy.State.Running) 'H454_ROUTE_PROXY_NETWORK'
        $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
        $null=Assert-H454RecoveryNetwork $network $networkName $labelValue
        Assert-H454RecoveryRouteMembers $network $proxy $DockerSha256
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $connectedResult=Invoke-H454RecoveryDocker -Arguments @('network','connect','--alias','host.docker.internal',$plan.Id,$proxy.Id) -DockerSha256 $DockerSha256
        Require-H454 ($connectedResult.Code -eq 0) 'H454_ROUTE_CONNECT'
        $proxy=Find-H454RecoveryObject 'container' $proxyName $DockerSha256
    }
    Assert-H454RecoveryProxy $proxy $proxyName $labelValue $ProxyImage $hostAddress $CaSha256 $plan $bridge.Id -Connected
    if(-not $proxy.State.Running){
        $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
        $null=Assert-H454RecoveryNetwork $network $networkName $labelValue
        Assert-H454RecoveryRouteMembers $network $proxy $DockerSha256
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $started=Invoke-H454RecoveryDocker -Arguments @('start',$proxy.Id) -DockerSha256 $DockerSha256
        Require-H454 ($started.Code -eq 0) 'H454_ROUTE_START'
        $proxy=Find-H454RecoveryObject 'container' $proxyName $DockerSha256
    }
    Require-H454 ($null -ne $proxy -and $proxy.State.Running -is [bool] -and $proxy.State.Running) 'H454_ROUTE_START'
    Assert-H454RecoveryProxy $proxy $proxyName $labelValue $ProxyImage $hostAddress $CaSha256 $plan $bridge.Id -Connected
    $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
    $plan=Assert-H454RecoveryNetwork $network $networkName $labelValue
    Assert-H454RecoveryRouteMembers $network $proxy $DockerSha256
    $members=@($network.Containers.PSObject.Properties | ForEach-Object {$_.Name})
    Require-H454 ($members.Count -eq 1 -and $members[0] -ceq $proxy.Id) 'H454_ROUTE_MEMBERS'
    $upstreamAddress=[string]$proxy.NetworkSettings.Networks.bridge.IPAddress
    $upstreamNumber=Get-H454IPv4Number $upstreamAddress
    Require-H454 ((Test-H454PrivateIPv4 $upstreamNumber) -and ($upstreamNumber -lt $plan.Base -or $upstreamNumber -gt $plan.Last)) 'H454_ROUTE_PROXY_NETWORK'
    $closed="const n=require('node:net');const s=n.connect(38180,process.argv[2]);s.on('connect',()=>process.exit(2));s.on('error',e=>{if(e.code==='ECONNREFUSED')console.log('H454_UPSTREAM_PLAINTEXT=REFUSED');else process.exit(3)});setTimeout(()=>process.exit(4),4000).unref()"
    $closed64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($closed))
    $closedResult=Invoke-H454RecoveryDocker -Arguments @('exec','--user','65534:65534',$proxy.Id,'node','-e',$bootstrap,$closed64,$upstreamAddress) -DockerSha256 $DockerSha256
    Require-H454 ($closedResult.Code -eq 0 -and $closedResult.Output.Trim() -ceq 'H454_UPSTREAM_PLAINTEXT=REFUSED') 'H454_ROUTE_PROXY_EXPOSURE'
    Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
    $privateAddress=[string]$proxy.NetworkSettings.Networks.PSObject.Properties[$networkName].Value.IPAddress
    $privateNumber=Get-H454IPv4Number $privateAddress
    Require-H454 ($privateNumber -gt $plan.Base -and $privateNumber -lt $plan.Last) 'H454_ROUTE_PROXY_NETWORK'
    $unauthorized="const n=require('node:net'),c=require('node:crypto');const k=c.randomBytes(16).toString('base64');const s=n.connect(38180,process.argv[2]);let b='';s.setTimeout(10000,()=>process.exit(2));s.on('error',()=>process.exit(3));s.on('connect',()=>s.write('GET /ws HTTP/1.1\r\nHost: host.docker.internal\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nAuthorization: Bearer brc_dev_'+('A'.repeat(43))+'\r\nSec-WebSocket-Key: '+k+'\r\nSec-WebSocket-Version: 13\r\nX-BRC-Protocol: 1\r\n\r\n'));s.on('data',x=>{b+=x.toString('latin1');if(b.includes('\r\n')){const line=b.split('\r\n')[0];s.destroy();if(!/^HTTP\/1\.1 (401|403) /.test(line))process.exit(4);console.log('H454_SYNTHETIC_BEARER=REFUSED')}});s.on('end',()=>process.exit(5))"
    $unauthorized64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($unauthorized))
    $probeResult=Invoke-H454RecoveryDocker -Arguments @('exec','--user','65534:65534',$proxy.Id,'node','-e',$bootstrap,$unauthorized64,$privateAddress) -DockerSha256 $DockerSha256
    Require-H454 ($probeResult.Code -eq 0 -and $probeResult.Output.Trim() -ceq 'H454_SYNTHETIC_BEARER=REFUSED') 'H454_ROUTE_PROBE'
    Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
    return [pscustomobject]@{Status='ROUTE_READY';NetworkId=$plan.Id;NetworkName=$networkName;Cidr=$plan.Cidr;
        ProxyId=[string]$proxy.Id;ProxyName=$proxyName;BridgeId=[string]$bridge.Id;LabelValue=$labelValue;HostAddress=$hostAddress}
}
 -and
        $Proxy.State.Running -eq $false -and [string]$Proxy.State.Status -ceq 'exited' -and
        $members.Count -eq 1 -and $null -ne $bridge -and
        [string]$bridge.Value.NetworkID -cmatch '^[a-f0-9]{64}
    foreach($alias in @($bridge.Value.Aliases)){
        Require-H454 ($null -eq $alias -or ($alias -is [string] -and
            -not $alias.TrimEnd('.').Equals('host.docker.internal',[StringComparison]::OrdinalIgnoreCase))) 'H454_ROUTE_PROXY_NETWORK'
    }
    if($Connected){
        $private=$Proxy.NetworkSettings.Networks.PSObject.Properties[$Network.Name]
        Require-H454 ($members.Count -eq 2 -and $null -ne $private -and ($private.Value.NetworkID -ceq $Network.Id -or
            (-not $Proxy.State.Running -and [string]::IsNullOrEmpty([string]$private.Value.NetworkID))) -and
            @($private.Value.Aliases) -ccontains 'host.docker.internal') 'H454_ROUTE_PROXY_NETWORK'
    }else{Require-H454 ($members.Count -eq 1) 'H454_ROUTE_PROXY_NETWORK'}
}

function Assert-H454RecoveryRouteMembers([object]$Network,[object]$Proxy,[string]$DockerSha256,[string]$AgentId='') {
    Require-H454 ([string]::IsNullOrEmpty($AgentId) -or ($AgentId -cmatch '^[a-f0-9]{64}$' -and
        ($null -eq $Proxy -or $AgentId -cne $Proxy.Id))) 'H454_ROUTE_MEMBERS'
    Require-H454 ($null -ne $Network -and $null -ne $Network.Containers) 'H454_ROUTE_MEMBERS'
    $members=@($Network.Containers.PSObject.Properties | ForEach-Object {$_.Name})
    foreach($member in $members){
        Require-H454 (($null -ne $Proxy -and $member -ceq $Proxy.Id) -or
            (-not [string]::IsNullOrEmpty($AgentId) -and $member -ceq $AgentId)) 'H454_ROUTE_MEMBERS'
    }
    Require-H454 ($members.Count -le 2 -and ($members.Count -le 1 -or -not [string]::IsNullOrEmpty($AgentId))) 'H454_ROUTE_MEMBERS'
    $list=Invoke-H454RecoveryDocker -Arguments @('container','ls','--all','--no-trunc','--format','{{.ID}}|{{.Networks}}') -DockerSha256 $DockerSha256
    Require-H454 ($list.Code -eq 0) 'H454_ROUTE_MEMBERS'
    $rows=@($list.Output -split "`r?`n" | Where-Object {-not [string]::IsNullOrWhiteSpace($_)})
    Require-H454 ($rows.Count -le 2048) 'H454_ROUTE_MEMBERS'
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($row in $rows){
        Require-H454 ($row -cmatch '^([a-f0-9]{64})\|(?:([a-zA-Z0-9_.-]+(?:,[a-zA-Z0-9_.-]+)*))?$' -and
            $seen.Add($Matches[1])) 'H454_ROUTE_MEMBERS'
        $id=$Matches[1];$names=if([string]::IsNullOrEmpty($Matches[2])){@()}else{@($Matches[2].Split(','))}
        if($names -ccontains [string]$Network.Name){
            Require-H454 (($null -ne $Proxy -and $id -ceq $Proxy.Id) -or
                (-not [string]::IsNullOrEmpty($AgentId) -and $id -ceq $AgentId)) 'H454_ROUTE_MEMBERS'
        }
    }
}

function Assert-H454RecoveryProbe(
    [object]$Probe,[string]$Name,[string]$LabelValue,[string]$Image,[string]$BridgeId,[string]$Bootstrap,[string]$Encoded
) {
    Require-H454 ($null -ne $Probe -and $Probe.Id -cmatch '^[a-f0-9]{64}$' -and $Probe.Name -ceq ('/'+$Name) -and
        $Probe.Image -ceq $Image -and $Probe.Config.Labels.'com.hermes.h454.recovery-probe' -ceq $LabelValue -and
        $Probe.Config.User -ceq '65534:65534' -and @($Probe.Config.Entrypoint).Count -eq 1 -and
        [string]$Probe.Config.Entrypoint[0] -ceq 'node') 'H454_ROUTE_PROBE_COLLISION'
    $cmd=@($Probe.Config.Cmd);$hostConfig=$Probe.HostConfig
    Require-H454 ($cmd.Count -eq 3 -and [string]$cmd[0] -ceq '-e' -and [string]$cmd[1] -ceq $Bootstrap -and
        [string]$cmd[2] -ceq $Encoded -and $hostConfig.NetworkMode -ceq 'bridge' -and
        $hostConfig.ReadonlyRootfs -is [bool] -and $hostConfig.ReadonlyRootfs -and
        $hostConfig.Privileged -is [bool] -and -not $hostConfig.Privileged -and $hostConfig.AutoRemove -is [bool] -and $hostConfig.AutoRemove -and
        @($hostConfig.CapDrop) -ccontains 'ALL' -and ($null -eq $hostConfig.CapAdd -or @($hostConfig.CapAdd).Count -eq 0) -and
        @($hostConfig.SecurityOpt).Count -eq 1 -and [string]$hostConfig.SecurityOpt[0] -ceq 'no-new-privileges' -and
        $hostConfig.PidsLimit -eq 32 -and $hostConfig.Memory -eq 134217728 -and $hostConfig.RestartPolicy.Name -ceq 'no' -and
        $hostConfig.PublishAllPorts -is [bool] -and -not $hostConfig.PublishAllPorts -and
        ($null -eq $hostConfig.PortBindings -or @($hostConfig.PortBindings.PSObject.Properties).Count -eq 0) -and
        ($null -eq $hostConfig.Binds -or @($hostConfig.Binds).Count -eq 0) -and @($Probe.Mounts).Count -eq 0) 'H454_ROUTE_PROBE_COLLISION'
    foreach($entry in @($Probe.Config.Env)){
        Require-H454 ($entry -is [string] -and $entry -cnotmatch '^(?:NODE_OPTIONS|NODE_PATH|NODE_EXTRA_CA_CERTS|NODE_TLS_REJECT_UNAUTHORIZED|LD_PRELOAD|LD_LIBRARY_PATH)=') 'H454_ROUTE_PROBE_COLLISION'
    }
    $networks=@($Probe.NetworkSettings.Networks.PSObject.Properties)
    $bridge=$Probe.NetworkSettings.Networks.PSObject.Properties['bridge']
    Require-H454 ($Probe.State.Running -is [bool] -and $networks.Count -eq 1 -and $null -ne $bridge -and
        ($bridge.Value.NetworkID -ceq $BridgeId -or (-not $Probe.State.Running -and
            [string]::IsNullOrEmpty([string]$bridge.Value.NetworkID)))) 'H454_ROUTE_PROBE_COLLISION'
}

function Assert-H454RecoveryRouteSafety(
    [string]$StateDir,[IO.FileStream]$Lock,[string]$MarkerSha256,[scriptblock]$SafetyCheck
) {
    Assert-H454RecoveryLock $StateDir $Lock
    Assert-H454WssTaskFile (Join-Path $StateDir 'h454-wss-transition.pending') $MarkerSha256 4096
    $safe=@(& $SafetyCheck)
    Require-H454 ($safe.Count -eq 1 -and $safe[0] -is [bool] -and $safe[0]) 'H454_ROUTE_SAFETY'
}

function Prepare-H454RecoveryRoute(
    [string]$StateDir,[IO.FileStream]$Lock,[string]$MarkerSha256,[string]$ProxyImage,
    [string]$CaSha256,[string]$DockerSha256,[scriptblock]$SafetyCheck,[switch]$Apply,[switch]$OwnerApproved
) {
    Require-H454 (-not $Apply -or $OwnerApproved) 'H454_ROUTE_APPROVAL'
    Require-H454 ($MarkerSha256 -cmatch '^[A-F0-9]{64}$' -and $CaSha256 -cmatch '^[A-F0-9]{64}$' -and
        $DockerSha256 -cmatch '^[A-F0-9]{64}$' -and $ProxyImage -cmatch '^sha256:[a-f0-9]{64}$' -and
        $SafetyCheck -is [scriptblock]) 'H454_ROUTE_PINS'
    Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
    $labelValue=$MarkerSha256.Substring(0,32).ToLowerInvariant()
    $networkName='h454-recovery-'+$labelValue;$proxyName=$networkName+'-proxy';$probeName=$networkName+'-probe'
    $imageResult=Invoke-H454RecoveryDocker -Arguments @('image','inspect',$ProxyImage) -DockerSha256 $DockerSha256
    Require-H454 ($imageResult.Code -eq 0 -and $imageResult.Output.Length -gt 0) 'H454_ROUTE_IMAGE'
    $images=@($imageResult.Output | ConvertFrom-Json -ErrorAction Stop)
    Require-H454 ($images.Count -eq 1 -and $images[0].Id -ceq $ProxyImage) 'H454_ROUTE_IMAGE'
    $bridge=Find-H454RecoveryObject 'network' 'bridge' $DockerSha256
    Require-H454 ($null -ne $bridge -and $bridge.Driver -ceq 'bridge' -and $bridge.Id -cmatch '^[a-f0-9]{64}$') 'H454_ROUTE_BRIDGE'
    $lookup="const d=require('node:dns');d.lookup('host.docker.internal',{all:true},(e,a)=>{if(e)process.exit(2);const x=[...new Set(a.filter(z=>z.family===4).map(z=>z.address))];if(x.length!==1)process.exit(3);console.log(x[0])})"
    $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($lookup))
    $bootstrap="eval(Buffer.from(process.argv[1],'base64').toString())"
    $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
    $proxy=Find-H454RecoveryObject 'container' $proxyName $DockerSha256
    $probe=Find-H454RecoveryObject 'container' $probeName $DockerSha256
    Require-H454 ($null -eq $proxy -or $null -ne $network) 'H454_ROUTE_COLLISION'
    if($null -ne $probe){Assert-H454RecoveryProbe $probe $probeName $labelValue $ProxyImage $bridge.Id $bootstrap $encoded}
    $plan=$null
    if($null -ne $network){
        $plan=Assert-H454RecoveryNetwork $network $networkName $labelValue
        Assert-H454RecoveryRouteMembers $network $proxy $DockerSha256
    }
    if($null -ne $proxy){
        $cmd=@($proxy.Config.Cmd);Require-H454 ($cmd.Count -eq 3) 'H454_ROUTE_PROXY'
        $hostAddress=[string]$cmd[0];$hostNumber=Get-H454IPv4Number $hostAddress
        Require-H454 ((Test-H454PrivateIPv4 $hostNumber) -and ($hostNumber -lt $plan.Base -or $hostNumber -gt $plan.Last)) 'H454_ROUTE_HOST'
        $connected=($null -ne $proxy.NetworkSettings.Networks.PSObject.Properties[$networkName])
        Assert-H454RecoveryProxy $proxy $proxyName $labelValue $ProxyImage $hostAddress $CaSha256 $plan $bridge.Id -Connected:$connected
        Require-H454 ($proxy.State.Running -is [bool] -and $proxy.State.Paused -is [bool] -and -not $proxy.State.Paused -and
            $proxy.State.Restarting -is [bool] -and -not $proxy.State.Restarting -and $proxy.State.Dead -is [bool] -and
            -not $proxy.State.Dead -and (-not $proxy.State.Running -or $connected)) 'H454_ROUTE_PROXY_NETWORK'
    }
    if(-not $Apply){return [pscustomobject]@{Status='PREFLIGHT';NetworkPresent=($null -ne $network);ProxyPresent=($null -ne $proxy);ProbePresent=($null -ne $probe)}}
    if($null -ne $probe){
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $currentProbe=Find-H454RecoveryObject 'container' $probeName $DockerSha256
        Require-H454 ($null -ne $currentProbe -and $currentProbe.Id -ceq $probe.Id) 'H454_ROUTE_PROBE_COLLISION'
        Assert-H454RecoveryProbe $currentProbe $probeName $labelValue $ProxyImage $bridge.Id $bootstrap $encoded
        $removed=Invoke-H454RecoveryDocker -Arguments @('container','rm','--force',$currentProbe.Id) -DockerSha256 $DockerSha256
        Require-H454 ($removed.Code -eq 0 -and $null -eq (Find-H454RecoveryObject 'container' $probeName $DockerSha256)) 'H454_ROUTE_PROBE_REMAINS'
    }
    if($null -eq $network){
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $created=Invoke-H454RecoveryDocker -Arguments @('network','create','--internal','--label',('com.hermes.h454.recovery='+$labelValue),$networkName) -DockerSha256 $DockerSha256
        Require-H454 ($created.Code -eq 0 -and $created.Output.Trim() -cmatch '^[a-f0-9]{64}$') 'H454_ROUTE_CREATE'
        $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
        Require-H454 ($null -ne $network -and $network.Id -ceq $created.Output.Trim()) 'H454_ROUTE_CREATE'
        $plan=Assert-H454RecoveryNetwork $network $networkName $labelValue
        Assert-H454RecoveryRouteMembers $network $null $DockerSha256
    }
    Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
    $resolved=Invoke-H454RecoveryDocker -Arguments @('run','--rm','--pull=never','--network','bridge','--name',$probeName,
        '--label',('com.hermes.h454.recovery-probe='+$labelValue),'--read-only','--user','65534:65534','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--pids-limit','32','--memory','128m','--entrypoint','node',$ProxyImage,'-e',$bootstrap,$encoded) -DockerSha256 $DockerSha256
    Require-H454 ($resolved.Code -eq 0) 'H454_ROUTE_HOST'
    Require-H454 ($null -eq (Find-H454RecoveryObject 'container' $probeName $DockerSha256)) 'H454_ROUTE_PROBE_REMAINS'
    $hostAddress=$resolved.Output.Trim();$hostNumber=Get-H454IPv4Number $hostAddress
    Require-H454 ((Test-H454PrivateIPv4 $hostNumber) -and ($hostNumber -lt $plan.Base -or $hostNumber -gt $plan.Last)) 'H454_ROUTE_HOST'
    if($null -eq $proxy){
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $created=Invoke-H454RecoveryDocker -Arguments @('create','--pull=never','--name',$proxyName,'--network','bridge',
            '--restart','unless-stopped','--read-only','--user','65534:65534','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--pids-limit','32','--memory','128m',
            '--label',('com.hermes.h454.recovery='+$labelValue),$ProxyImage,$hostAddress,$CaSha256.ToLowerInvariant(),$plan.Cidr) -DockerSha256 $DockerSha256
        Require-H454 ($created.Code -eq 0 -and $created.Output.Trim() -cmatch '^[a-f0-9]{64}$') 'H454_ROUTE_CREATE'
        $proxy=Find-H454RecoveryObject 'container' $proxyName $DockerSha256
        Require-H454 ($null -ne $proxy -and $proxy.Id -ceq $created.Output.Trim()) 'H454_ROUTE_CREATE'
    }
    $connected=($null -ne $proxy.NetworkSettings.Networks.PSObject.Properties[$networkName])
    Assert-H454RecoveryProxy $proxy $proxyName $labelValue $ProxyImage $hostAddress $CaSha256 $plan $bridge.Id -Connected:$connected
    if(-not $connected){
        Require-H454 (-not $proxy.State.Running) 'H454_ROUTE_PROXY_NETWORK'
        $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
        $null=Assert-H454RecoveryNetwork $network $networkName $labelValue
        Assert-H454RecoveryRouteMembers $network $proxy $DockerSha256
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $connectedResult=Invoke-H454RecoveryDocker -Arguments @('network','connect','--alias','host.docker.internal',$plan.Id,$proxy.Id) -DockerSha256 $DockerSha256
        Require-H454 ($connectedResult.Code -eq 0) 'H454_ROUTE_CONNECT'
        $proxy=Find-H454RecoveryObject 'container' $proxyName $DockerSha256
    }
    Assert-H454RecoveryProxy $proxy $proxyName $labelValue $ProxyImage $hostAddress $CaSha256 $plan $bridge.Id -Connected
    if(-not $proxy.State.Running){
        $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
        $null=Assert-H454RecoveryNetwork $network $networkName $labelValue
        Assert-H454RecoveryRouteMembers $network $proxy $DockerSha256
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $started=Invoke-H454RecoveryDocker -Arguments @('start',$proxy.Id) -DockerSha256 $DockerSha256
        Require-H454 ($started.Code -eq 0) 'H454_ROUTE_START'
        $proxy=Find-H454RecoveryObject 'container' $proxyName $DockerSha256
    }
    Require-H454 ($null -ne $proxy -and $proxy.State.Running -is [bool] -and $proxy.State.Running) 'H454_ROUTE_START'
    Assert-H454RecoveryProxy $proxy $proxyName $labelValue $ProxyImage $hostAddress $CaSha256 $plan $bridge.Id -Connected
    $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
    $plan=Assert-H454RecoveryNetwork $network $networkName $labelValue
    Assert-H454RecoveryRouteMembers $network $proxy $DockerSha256
    $members=@($network.Containers.PSObject.Properties | ForEach-Object {$_.Name})
    Require-H454 ($members.Count -eq 1 -and $members[0] -ceq $proxy.Id) 'H454_ROUTE_MEMBERS'
    $upstreamAddress=[string]$proxy.NetworkSettings.Networks.bridge.IPAddress
    $upstreamNumber=Get-H454IPv4Number $upstreamAddress
    Require-H454 ((Test-H454PrivateIPv4 $upstreamNumber) -and ($upstreamNumber -lt $plan.Base -or $upstreamNumber -gt $plan.Last)) 'H454_ROUTE_PROXY_NETWORK'
    $closed="const n=require('node:net');const s=n.connect(38180,process.argv[2]);s.on('connect',()=>process.exit(2));s.on('error',e=>{if(e.code==='ECONNREFUSED')console.log('H454_UPSTREAM_PLAINTEXT=REFUSED');else process.exit(3)});setTimeout(()=>process.exit(4),4000).unref()"
    $closed64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($closed))
    $closedResult=Invoke-H454RecoveryDocker -Arguments @('exec','--user','65534:65534',$proxy.Id,'node','-e',$bootstrap,$closed64,$upstreamAddress) -DockerSha256 $DockerSha256
    Require-H454 ($closedResult.Code -eq 0 -and $closedResult.Output.Trim() -ceq 'H454_UPSTREAM_PLAINTEXT=REFUSED') 'H454_ROUTE_PROXY_EXPOSURE'
    Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
    $privateAddress=[string]$proxy.NetworkSettings.Networks.PSObject.Properties[$networkName].Value.IPAddress
    $privateNumber=Get-H454IPv4Number $privateAddress
    Require-H454 ($privateNumber -gt $plan.Base -and $privateNumber -lt $plan.Last) 'H454_ROUTE_PROXY_NETWORK'
    $unauthorized="const n=require('node:net'),c=require('node:crypto');const k=c.randomBytes(16).toString('base64');const s=n.connect(38180,process.argv[2]);let b='';s.setTimeout(10000,()=>process.exit(2));s.on('error',()=>process.exit(3));s.on('connect',()=>s.write('GET /ws HTTP/1.1\r\nHost: host.docker.internal\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nAuthorization: Bearer brc_dev_'+('A'.repeat(43))+'\r\nSec-WebSocket-Key: '+k+'\r\nSec-WebSocket-Version: 13\r\nX-BRC-Protocol: 1\r\n\r\n'));s.on('data',x=>{b+=x.toString('latin1');if(b.includes('\r\n')){const line=b.split('\r\n')[0];s.destroy();if(!/^HTTP\/1\.1 (401|403) /.test(line))process.exit(4);console.log('H454_SYNTHETIC_BEARER=REFUSED')}});s.on('end',()=>process.exit(5))"
    $unauthorized64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($unauthorized))
    $probeResult=Invoke-H454RecoveryDocker -Arguments @('exec','--user','65534:65534',$proxy.Id,'node','-e',$bootstrap,$unauthorized64,$privateAddress) -DockerSha256 $DockerSha256
    Require-H454 ($probeResult.Code -eq 0 -and $probeResult.Output.Trim() -ceq 'H454_SYNTHETIC_BEARER=REFUSED') 'H454_ROUTE_PROBE'
    Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
    return [pscustomobject]@{Status='ROUTE_READY';NetworkId=$plan.Id;NetworkName=$networkName;Cidr=$plan.Cidr;
        ProxyId=[string]$proxy.Id;ProxyName=$proxyName;BridgeId=[string]$bridge.Id;LabelValue=$labelValue;HostAddress=$hostAddress}
}
)
    Require-H454 (-not $AllowStoppedLegacyProxyBridge -or $legacyStoppedBridge) 'H454_ROUTE_PROXY_NETWORK'
    Require-H454 ($null -ne $bridge -and ($bridge.Value.NetworkID -ceq $BridgeId -or
        (-not $Proxy.State.Running -and [string]::IsNullOrEmpty([string]$bridge.Value.NetworkID)) -or
        $legacyStoppedBridge)) 'H454_ROUTE_PROXY_NETWORK'
    foreach($alias in @($bridge.Value.Aliases)){
        Require-H454 ($null -eq $alias -or ($alias -is [string] -and
            -not $alias.TrimEnd('.').Equals('host.docker.internal',[StringComparison]::OrdinalIgnoreCase))) 'H454_ROUTE_PROXY_NETWORK'
    }
    if($Connected){
        $private=$Proxy.NetworkSettings.Networks.PSObject.Properties[$Network.Name]
        Require-H454 ($members.Count -eq 2 -and $null -ne $private -and ($private.Value.NetworkID -ceq $Network.Id -or
            (-not $Proxy.State.Running -and [string]::IsNullOrEmpty([string]$private.Value.NetworkID))) -and
            @($private.Value.Aliases) -ccontains 'host.docker.internal') 'H454_ROUTE_PROXY_NETWORK'
    }else{Require-H454 ($members.Count -eq 1) 'H454_ROUTE_PROXY_NETWORK'}
}

function Assert-H454RecoveryRouteMembers([object]$Network,[object]$Proxy,[string]$DockerSha256,[string]$AgentId='') {
    Require-H454 ([string]::IsNullOrEmpty($AgentId) -or ($AgentId -cmatch '^[a-f0-9]{64}$' -and
        ($null -eq $Proxy -or $AgentId -cne $Proxy.Id))) 'H454_ROUTE_MEMBERS'
    Require-H454 ($null -ne $Network -and $null -ne $Network.Containers) 'H454_ROUTE_MEMBERS'
    $members=@($Network.Containers.PSObject.Properties | ForEach-Object {$_.Name})
    foreach($member in $members){
        Require-H454 (($null -ne $Proxy -and $member -ceq $Proxy.Id) -or
            (-not [string]::IsNullOrEmpty($AgentId) -and $member -ceq $AgentId)) 'H454_ROUTE_MEMBERS'
    }
    Require-H454 ($members.Count -le 2 -and ($members.Count -le 1 -or -not [string]::IsNullOrEmpty($AgentId))) 'H454_ROUTE_MEMBERS'
    $list=Invoke-H454RecoveryDocker -Arguments @('container','ls','--all','--no-trunc','--format','{{.ID}}|{{.Networks}}') -DockerSha256 $DockerSha256
    Require-H454 ($list.Code -eq 0) 'H454_ROUTE_MEMBERS'
    $rows=@($list.Output -split "`r?`n" | Where-Object {-not [string]::IsNullOrWhiteSpace($_)})
    Require-H454 ($rows.Count -le 2048) 'H454_ROUTE_MEMBERS'
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($row in $rows){
        Require-H454 ($row -cmatch '^([a-f0-9]{64})\|(?:([a-zA-Z0-9_.-]+(?:,[a-zA-Z0-9_.-]+)*))?$' -and
            $seen.Add($Matches[1])) 'H454_ROUTE_MEMBERS'
        $id=$Matches[1];$names=if([string]::IsNullOrEmpty($Matches[2])){@()}else{@($Matches[2].Split(','))}
        if($names -ccontains [string]$Network.Name){
            Require-H454 (($null -ne $Proxy -and $id -ceq $Proxy.Id) -or
                (-not [string]::IsNullOrEmpty($AgentId) -and $id -ceq $AgentId)) 'H454_ROUTE_MEMBERS'
        }
    }
}

function Assert-H454RecoveryProbe(
    [object]$Probe,[string]$Name,[string]$LabelValue,[string]$Image,[string]$BridgeId,[string]$Bootstrap,[string]$Encoded
) {
    Require-H454 ($null -ne $Probe -and $Probe.Id -cmatch '^[a-f0-9]{64}$' -and $Probe.Name -ceq ('/'+$Name) -and
        $Probe.Image -ceq $Image -and $Probe.Config.Labels.'com.hermes.h454.recovery-probe' -ceq $LabelValue -and
        $Probe.Config.User -ceq '65534:65534' -and @($Probe.Config.Entrypoint).Count -eq 1 -and
        [string]$Probe.Config.Entrypoint[0] -ceq 'node') 'H454_ROUTE_PROBE_COLLISION'
    $cmd=@($Probe.Config.Cmd);$hostConfig=$Probe.HostConfig
    Require-H454 ($cmd.Count -eq 3 -and [string]$cmd[0] -ceq '-e' -and [string]$cmd[1] -ceq $Bootstrap -and
        [string]$cmd[2] -ceq $Encoded -and $hostConfig.NetworkMode -ceq 'bridge' -and
        $hostConfig.ReadonlyRootfs -is [bool] -and $hostConfig.ReadonlyRootfs -and
        $hostConfig.Privileged -is [bool] -and -not $hostConfig.Privileged -and $hostConfig.AutoRemove -is [bool] -and $hostConfig.AutoRemove -and
        @($hostConfig.CapDrop) -ccontains 'ALL' -and ($null -eq $hostConfig.CapAdd -or @($hostConfig.CapAdd).Count -eq 0) -and
        @($hostConfig.SecurityOpt).Count -eq 1 -and [string]$hostConfig.SecurityOpt[0] -ceq 'no-new-privileges' -and
        $hostConfig.PidsLimit -eq 32 -and $hostConfig.Memory -eq 134217728 -and $hostConfig.RestartPolicy.Name -ceq 'no' -and
        $hostConfig.PublishAllPorts -is [bool] -and -not $hostConfig.PublishAllPorts -and
        ($null -eq $hostConfig.PortBindings -or @($hostConfig.PortBindings.PSObject.Properties).Count -eq 0) -and
        ($null -eq $hostConfig.Binds -or @($hostConfig.Binds).Count -eq 0) -and @($Probe.Mounts).Count -eq 0) 'H454_ROUTE_PROBE_COLLISION'
    foreach($entry in @($Probe.Config.Env)){
        Require-H454 ($entry -is [string] -and $entry -cnotmatch '^(?:NODE_OPTIONS|NODE_PATH|NODE_EXTRA_CA_CERTS|NODE_TLS_REJECT_UNAUTHORIZED|LD_PRELOAD|LD_LIBRARY_PATH)=') 'H454_ROUTE_PROBE_COLLISION'
    }
    $networks=@($Probe.NetworkSettings.Networks.PSObject.Properties)
    $bridge=$Probe.NetworkSettings.Networks.PSObject.Properties['bridge']
    Require-H454 ($Probe.State.Running -is [bool] -and $networks.Count -eq 1 -and $null -ne $bridge -and
        ($bridge.Value.NetworkID -ceq $BridgeId -or (-not $Probe.State.Running -and
            [string]::IsNullOrEmpty([string]$bridge.Value.NetworkID)))) 'H454_ROUTE_PROBE_COLLISION'
}

function Assert-H454RecoveryRouteSafety(
    [string]$StateDir,[IO.FileStream]$Lock,[string]$MarkerSha256,[scriptblock]$SafetyCheck
) {
    Assert-H454RecoveryLock $StateDir $Lock
    Assert-H454WssTaskFile (Join-Path $StateDir 'h454-wss-transition.pending') $MarkerSha256 4096
    $safe=@(& $SafetyCheck)
    Require-H454 ($safe.Count -eq 1 -and $safe[0] -is [bool] -and $safe[0]) 'H454_ROUTE_SAFETY'
}

function Prepare-H454RecoveryRoute(
    [string]$StateDir,[IO.FileStream]$Lock,[string]$MarkerSha256,[string]$ProxyImage,
    [string]$CaSha256,[string]$DockerSha256,[scriptblock]$SafetyCheck,[switch]$Apply,[switch]$OwnerApproved
) {
    Require-H454 (-not $Apply -or $OwnerApproved) 'H454_ROUTE_APPROVAL'
    Require-H454 ($MarkerSha256 -cmatch '^[A-F0-9]{64}$' -and $CaSha256 -cmatch '^[A-F0-9]{64}$' -and
        $DockerSha256 -cmatch '^[A-F0-9]{64}$' -and $ProxyImage -cmatch '^sha256:[a-f0-9]{64}$' -and
        $SafetyCheck -is [scriptblock]) 'H454_ROUTE_PINS'
    Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
    $labelValue=$MarkerSha256.Substring(0,32).ToLowerInvariant()
    $networkName='h454-recovery-'+$labelValue;$proxyName=$networkName+'-proxy';$probeName=$networkName+'-probe'
    $imageResult=Invoke-H454RecoveryDocker -Arguments @('image','inspect',$ProxyImage) -DockerSha256 $DockerSha256
    Require-H454 ($imageResult.Code -eq 0 -and $imageResult.Output.Length -gt 0) 'H454_ROUTE_IMAGE'
    $images=@($imageResult.Output | ConvertFrom-Json -ErrorAction Stop)
    Require-H454 ($images.Count -eq 1 -and $images[0].Id -ceq $ProxyImage) 'H454_ROUTE_IMAGE'
    $bridge=Find-H454RecoveryObject 'network' 'bridge' $DockerSha256
    Require-H454 ($null -ne $bridge -and $bridge.Driver -ceq 'bridge' -and $bridge.Id -cmatch '^[a-f0-9]{64}$') 'H454_ROUTE_BRIDGE'
    $lookup="const d=require('node:dns');d.lookup('host.docker.internal',{all:true},(e,a)=>{if(e)process.exit(2);const x=[...new Set(a.filter(z=>z.family===4).map(z=>z.address))];if(x.length!==1)process.exit(3);console.log(x[0])})"
    $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($lookup))
    $bootstrap="eval(Buffer.from(process.argv[1],'base64').toString())"
    $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
    $proxy=Find-H454RecoveryObject 'container' $proxyName $DockerSha256
    $probe=Find-H454RecoveryObject 'container' $probeName $DockerSha256
    Require-H454 ($null -eq $proxy -or $null -ne $network) 'H454_ROUTE_COLLISION'
    if($null -ne $probe){Assert-H454RecoveryProbe $probe $probeName $labelValue $ProxyImage $bridge.Id $bootstrap $encoded}
    $plan=$null
    if($null -ne $network){
        $plan=Assert-H454RecoveryNetwork $network $networkName $labelValue
        Assert-H454RecoveryRouteMembers $network $proxy $DockerSha256
    }
    if($null -ne $proxy){
        $cmd=@($proxy.Config.Cmd);Require-H454 ($cmd.Count -eq 3) 'H454_ROUTE_PROXY'
        $hostAddress=[string]$cmd[0];$hostNumber=Get-H454IPv4Number $hostAddress
        Require-H454 ((Test-H454PrivateIPv4 $hostNumber) -and ($hostNumber -lt $plan.Base -or $hostNumber -gt $plan.Last)) 'H454_ROUTE_HOST'
        $connected=($null -ne $proxy.NetworkSettings.Networks.PSObject.Properties[$networkName])
        Assert-H454RecoveryProxy $proxy $proxyName $labelValue $ProxyImage $hostAddress $CaSha256 $plan $bridge.Id -Connected:$connected
        Require-H454 ($proxy.State.Running -is [bool] -and $proxy.State.Paused -is [bool] -and -not $proxy.State.Paused -and
            $proxy.State.Restarting -is [bool] -and -not $proxy.State.Restarting -and $proxy.State.Dead -is [bool] -and
            -not $proxy.State.Dead -and (-not $proxy.State.Running -or $connected)) 'H454_ROUTE_PROXY_NETWORK'
    }
    if(-not $Apply){return [pscustomobject]@{Status='PREFLIGHT';NetworkPresent=($null -ne $network);ProxyPresent=($null -ne $proxy);ProbePresent=($null -ne $probe)}}
    if($null -ne $probe){
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $currentProbe=Find-H454RecoveryObject 'container' $probeName $DockerSha256
        Require-H454 ($null -ne $currentProbe -and $currentProbe.Id -ceq $probe.Id) 'H454_ROUTE_PROBE_COLLISION'
        Assert-H454RecoveryProbe $currentProbe $probeName $labelValue $ProxyImage $bridge.Id $bootstrap $encoded
        $removed=Invoke-H454RecoveryDocker -Arguments @('container','rm','--force',$currentProbe.Id) -DockerSha256 $DockerSha256
        Require-H454 ($removed.Code -eq 0 -and $null -eq (Find-H454RecoveryObject 'container' $probeName $DockerSha256)) 'H454_ROUTE_PROBE_REMAINS'
    }
    if($null -eq $network){
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $created=Invoke-H454RecoveryDocker -Arguments @('network','create','--internal','--label',('com.hermes.h454.recovery='+$labelValue),$networkName) -DockerSha256 $DockerSha256
        Require-H454 ($created.Code -eq 0 -and $created.Output.Trim() -cmatch '^[a-f0-9]{64}$') 'H454_ROUTE_CREATE'
        $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
        Require-H454 ($null -ne $network -and $network.Id -ceq $created.Output.Trim()) 'H454_ROUTE_CREATE'
        $plan=Assert-H454RecoveryNetwork $network $networkName $labelValue
        Assert-H454RecoveryRouteMembers $network $null $DockerSha256
    }
    Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
    $resolved=Invoke-H454RecoveryDocker -Arguments @('run','--rm','--pull=never','--network','bridge','--name',$probeName,
        '--label',('com.hermes.h454.recovery-probe='+$labelValue),'--read-only','--user','65534:65534','--cap-drop','ALL',
        '--security-opt','no-new-privileges','--pids-limit','32','--memory','128m','--entrypoint','node',$ProxyImage,'-e',$bootstrap,$encoded) -DockerSha256 $DockerSha256
    Require-H454 ($resolved.Code -eq 0) 'H454_ROUTE_HOST'
    Require-H454 ($null -eq (Find-H454RecoveryObject 'container' $probeName $DockerSha256)) 'H454_ROUTE_PROBE_REMAINS'
    $hostAddress=$resolved.Output.Trim();$hostNumber=Get-H454IPv4Number $hostAddress
    Require-H454 ((Test-H454PrivateIPv4 $hostNumber) -and ($hostNumber -lt $plan.Base -or $hostNumber -gt $plan.Last)) 'H454_ROUTE_HOST'
    if($null -eq $proxy){
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $created=Invoke-H454RecoveryDocker -Arguments @('create','--pull=never','--name',$proxyName,'--network','bridge',
            '--restart','unless-stopped','--read-only','--user','65534:65534','--cap-drop','ALL',
            '--security-opt','no-new-privileges','--pids-limit','32','--memory','128m',
            '--label',('com.hermes.h454.recovery='+$labelValue),$ProxyImage,$hostAddress,$CaSha256.ToLowerInvariant(),$plan.Cidr) -DockerSha256 $DockerSha256
        Require-H454 ($created.Code -eq 0 -and $created.Output.Trim() -cmatch '^[a-f0-9]{64}$') 'H454_ROUTE_CREATE'
        $proxy=Find-H454RecoveryObject 'container' $proxyName $DockerSha256
        Require-H454 ($null -ne $proxy -and $proxy.Id -ceq $created.Output.Trim()) 'H454_ROUTE_CREATE'
    }
    $connected=($null -ne $proxy.NetworkSettings.Networks.PSObject.Properties[$networkName])
    Assert-H454RecoveryProxy $proxy $proxyName $labelValue $ProxyImage $hostAddress $CaSha256 $plan $bridge.Id -Connected:$connected
    if(-not $connected){
        Require-H454 (-not $proxy.State.Running) 'H454_ROUTE_PROXY_NETWORK'
        $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
        $null=Assert-H454RecoveryNetwork $network $networkName $labelValue
        Assert-H454RecoveryRouteMembers $network $proxy $DockerSha256
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $connectedResult=Invoke-H454RecoveryDocker -Arguments @('network','connect','--alias','host.docker.internal',$plan.Id,$proxy.Id) -DockerSha256 $DockerSha256
        Require-H454 ($connectedResult.Code -eq 0) 'H454_ROUTE_CONNECT'
        $proxy=Find-H454RecoveryObject 'container' $proxyName $DockerSha256
    }
    Assert-H454RecoveryProxy $proxy $proxyName $labelValue $ProxyImage $hostAddress $CaSha256 $plan $bridge.Id -Connected
    if(-not $proxy.State.Running){
        $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
        $null=Assert-H454RecoveryNetwork $network $networkName $labelValue
        Assert-H454RecoveryRouteMembers $network $proxy $DockerSha256
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $started=Invoke-H454RecoveryDocker -Arguments @('start',$proxy.Id) -DockerSha256 $DockerSha256
        Require-H454 ($started.Code -eq 0) 'H454_ROUTE_START'
        $proxy=Find-H454RecoveryObject 'container' $proxyName $DockerSha256
    }
    Require-H454 ($null -ne $proxy -and $proxy.State.Running -is [bool] -and $proxy.State.Running) 'H454_ROUTE_START'
    Assert-H454RecoveryProxy $proxy $proxyName $labelValue $ProxyImage $hostAddress $CaSha256 $plan $bridge.Id -Connected
    $network=Find-H454RecoveryObject 'network' $networkName $DockerSha256
    $plan=Assert-H454RecoveryNetwork $network $networkName $labelValue
    Assert-H454RecoveryRouteMembers $network $proxy $DockerSha256
    $members=@($network.Containers.PSObject.Properties | ForEach-Object {$_.Name})
    Require-H454 ($members.Count -eq 1 -and $members[0] -ceq $proxy.Id) 'H454_ROUTE_MEMBERS'
    $upstreamAddress=[string]$proxy.NetworkSettings.Networks.bridge.IPAddress
    $upstreamNumber=Get-H454IPv4Number $upstreamAddress
    Require-H454 ((Test-H454PrivateIPv4 $upstreamNumber) -and ($upstreamNumber -lt $plan.Base -or $upstreamNumber -gt $plan.Last)) 'H454_ROUTE_PROXY_NETWORK'
    $closed="const n=require('node:net');const s=n.connect(38180,process.argv[2]);s.on('connect',()=>process.exit(2));s.on('error',e=>{if(e.code==='ECONNREFUSED')console.log('H454_UPSTREAM_PLAINTEXT=REFUSED');else process.exit(3)});setTimeout(()=>process.exit(4),4000).unref()"
    $closed64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($closed))
    $closedResult=Invoke-H454RecoveryDocker -Arguments @('exec','--user','65534:65534',$proxy.Id,'node','-e',$bootstrap,$closed64,$upstreamAddress) -DockerSha256 $DockerSha256
    Require-H454 ($closedResult.Code -eq 0 -and $closedResult.Output.Trim() -ceq 'H454_UPSTREAM_PLAINTEXT=REFUSED') 'H454_ROUTE_PROXY_EXPOSURE'
    Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
    $privateAddress=[string]$proxy.NetworkSettings.Networks.PSObject.Properties[$networkName].Value.IPAddress
    $privateNumber=Get-H454IPv4Number $privateAddress
    Require-H454 ($privateNumber -gt $plan.Base -and $privateNumber -lt $plan.Last) 'H454_ROUTE_PROXY_NETWORK'
    $unauthorized="const n=require('node:net'),c=require('node:crypto');const k=c.randomBytes(16).toString('base64');const s=n.connect(38180,process.argv[2]);let b='';s.setTimeout(10000,()=>process.exit(2));s.on('error',()=>process.exit(3));s.on('connect',()=>s.write('GET /ws HTTP/1.1\r\nHost: host.docker.internal\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nAuthorization: Bearer brc_dev_'+('A'.repeat(43))+'\r\nSec-WebSocket-Key: '+k+'\r\nSec-WebSocket-Version: 13\r\nX-BRC-Protocol: 1\r\n\r\n'));s.on('data',x=>{b+=x.toString('latin1');if(b.includes('\r\n')){const line=b.split('\r\n')[0];s.destroy();if(!/^HTTP\/1\.1 (401|403) /.test(line))process.exit(4);console.log('H454_SYNTHETIC_BEARER=REFUSED')}});s.on('end',()=>process.exit(5))"
    $unauthorized64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($unauthorized))
    $probeResult=Invoke-H454RecoveryDocker -Arguments @('exec','--user','65534:65534',$proxy.Id,'node','-e',$bootstrap,$unauthorized64,$privateAddress) -DockerSha256 $DockerSha256
    Require-H454 ($probeResult.Code -eq 0 -and $probeResult.Output.Trim() -ceq 'H454_SYNTHETIC_BEARER=REFUSED') 'H454_ROUTE_PROBE'
    Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
    return [pscustomobject]@{Status='ROUTE_READY';NetworkId=$plan.Id;NetworkName=$networkName;Cidr=$plan.Cidr;
        ProxyId=[string]$proxy.Id;ProxyName=$proxyName;BridgeId=[string]$bridge.Id;LabelValue=$labelValue;HostAddress=$hostAddress}
}
