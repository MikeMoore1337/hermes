#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$Source)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. $Source
function Require-H454([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
$networkId='a'*64;$agentId='b'*64;$proxyId='c'*64;$otherId='d'*64
$labelName='com.hermes.h454.synthetic';$labelValue='e'*32;$networkName='h454-test-network'
function TestNetwork {
    $members=[ordered]@{};$members[$agentId]=[pscustomobject]@{};$members[$proxyId]=[pscustomobject]@{}
    $labels=[ordered]@{};$labels[$labelName]=$labelValue
    return [pscustomobject]@{Id=$networkId;Name=$networkName;Driver='bridge';Internal=$true;EnableIPv6=$false;
        Labels=[pscustomobject]$labels;Containers=[pscustomobject]$members}
}
function Check([object]$Network,[string]$Agent=$agentId,[string]$Proxy=$proxyId){
    Assert-H454InternalNetworkMembers $Network $networkId $networkName $labelName $labelValue $Agent $Proxy
}
Check (TestNetwork)
foreach($case in @('foreign','missing','replacement','internal','ipv6','driver','id','name','label','same-id')){
    $network=TestNetwork;$agent=$agentId;$proxy=$proxyId
    switch($case){
        'foreign' {$network.Containers | Add-Member -NotePropertyName $otherId -NotePropertyValue ([pscustomobject]@{})}
        'missing' {$network.Containers.PSObject.Properties.Remove($agentId)}
        'replacement' {$network.Containers.PSObject.Properties.Remove($agentId);$network.Containers | Add-Member -NotePropertyName $otherId -NotePropertyValue ([pscustomobject]@{})}
        'internal' {$network.Internal=$false}
        'ipv6' {$network.EnableIPv6=$true}
        'driver' {$network.Driver='host'}
        'id' {$network.Id='f'*64}
        'name' {$network.Name='foreign-network'}
        'label' {$network.Labels.PSObject.Properties[$labelName].Value='f'*32}
        'same-id' {$proxy=$agentId}
    }
    $refused=$false;try {Check $network $agent $proxy} catch {$refused=$true}
    Require-H454 $refused ('NETWORK_FIXTURE_ACCEPTED_'+$case)
}
function TestRoute {
    $network=TestNetwork
    $network | Add-Member -NotePropertyName IPAM -NotePropertyValue ([pscustomobject]@{
        Config=@([pscustomobject]@{Subnet='172.20.0.0/16';Gateway='172.20.0.1'})})
    $network.Containers.PSObject.Properties[$agentId].Value=[pscustomobject]@{IPv4Address='172.20.0.2/16'}
    $network.Containers.PSObject.Properties[$proxyId].Value=[pscustomobject]@{IPv4Address='172.20.0.3/16'}
    $agentEndpoint=[pscustomobject]@{NetworkID=$networkId;IPAddress='172.20.0.2';GlobalIPv6Address='';Aliases=@()}
    $proxyEndpoint=[pscustomobject]@{NetworkID=$networkId;IPAddress='172.20.0.3';GlobalIPv6Address='';Aliases=@('host.docker.internal')}
    $upstreamEndpoint=[pscustomobject]@{NetworkID=('f'*64);IPAddress='172.21.0.2';GlobalIPv6Address='';Aliases=@('synthetic-upstream')}
    $agentNetworks=[ordered]@{};$agentNetworks[$networkName]=$agentEndpoint
    $proxyNetworks=[ordered]@{};$proxyNetworks[$networkName]=$proxyEndpoint;$proxyNetworks['h454-upstream']=$upstreamEndpoint
    return [pscustomobject]@{Network=$network;
        Agent=[pscustomobject]@{Id=$agentId;State=[pscustomobject]@{Running=$true};HostConfig=[pscustomobject]@{ExtraHosts=$null};
            NetworkSettings=[pscustomobject]@{Networks=[pscustomobject]$agentNetworks}};
        Proxy=[pscustomobject]@{Id=$proxyId;State=[pscustomobject]@{Running=$true};
            NetworkSettings=[pscustomobject]@{Networks=[pscustomobject]$proxyNetworks}};
        Cidr='172.20.0.0/16';Resolved=@('172.20.0.3');Override=$false}
}
function CheckRoute([object]$Route) {
    Assert-H454RollbackAgentRoute $Route.Network $Route.Agent $Route.Proxy $networkId $networkName $labelName $labelValue `
        $agentId $proxyId ('f'*64) 'h454-upstream' $Route.Cidr $Route.Resolved $Route.Override
}
CheckRoute (TestRoute)
foreach($subnet in @(
    @('10.0.0.0/8','10.0.0.1','10.0.0.2','10.0.0.3',8),
    @('192.168.0.0/16','192.168.0.1','192.168.0.2','192.168.0.3',16)
)){
    $route=TestRoute;$route.Cidr=$subnet[0];$route.Network.IPAM.Config[0].Subnet=$subnet[0]
    $route.Network.IPAM.Config[0].Gateway=$subnet[1]
    $route.Agent.NetworkSettings.Networks.PSObject.Properties[$networkName].Value.IPAddress=$subnet[2]
    $route.Proxy.NetworkSettings.Networks.PSObject.Properties[$networkName].Value.IPAddress=$subnet[3]
    $route.Network.Containers.PSObject.Properties[$agentId].Value.IPv4Address=$subnet[2]+'/'+$subnet[4]
    $route.Network.Containers.PSObject.Properties[$proxyId].Value.IPv4Address=$subnet[3]+'/'+$subnet[4]
    $route.Resolved=@($subnet[3]);CheckRoute $route
}
foreach($case in @('agent-extra','proxy-extra','wrong-upstream','missing-alias','upstream-alias','upstream-alias-case','host-file','unknown-host-file',
                   'extra-hosts','dns-empty','dns-wrong','dns-mixed','dns-scalar','wrong-member-address','public-address','ipv6-address',
                   'agent-id','proxy-stopped','foreign-member','missing-ipam','multiple-subnets','wrong-cidr','cidr-host-bits',
                   'prefix-drift','gateway-outside','address-outside','gateway-as-address','public-cidr',
                   'upstream-overlap','upstream-public','upstream-missing')) {
    $route=TestRoute
    $agentEndpoint=$route.Agent.NetworkSettings.Networks.PSObject.Properties[$networkName].Value
    $proxyEndpoint=$route.Proxy.NetworkSettings.Networks.PSObject.Properties[$networkName].Value
    $upstreamEndpoint=$route.Proxy.NetworkSettings.Networks.PSObject.Properties['h454-upstream'].Value
    switch($case) {
        'agent-extra' {$route.Agent.NetworkSettings.Networks | Add-Member -NotePropertyName 'foreign' -NotePropertyValue ([pscustomobject]@{})}
        'proxy-extra' {$route.Proxy.NetworkSettings.Networks | Add-Member -NotePropertyName 'foreign' -NotePropertyValue ([pscustomobject]@{})}
        'wrong-upstream' {$upstreamEndpoint.NetworkID='e'*64}
        'missing-alias' {$proxyEndpoint.Aliases=@('wrong')}
        'upstream-alias' {$upstreamEndpoint.Aliases=@('host.docker.internal')}
        'upstream-alias-case' {$upstreamEndpoint.Aliases=@('HOST.DOCKER.INTERNAL.')}
        'host-file' {$route.Override=$true}
        'unknown-host-file' {$route.Override=$null}
        'extra-hosts' {$route.Agent.HostConfig.ExtraHosts=@('host.docker.internal:127.0.0.1')}
        'dns-empty' {$route.Resolved=@()}
        'dns-wrong' {$route.Resolved=@('172.20.0.4')}
        'dns-mixed' {$route.Resolved=@('172.20.0.3','172.20.0.4')}
        'dns-scalar' {$route.Resolved='172.20.0.3'}
        'wrong-member-address' {$route.Network.Containers.PSObject.Properties[$proxyId].Value.IPv4Address='172.20.0.4/16'}
        'public-address' {$proxyEndpoint.IPAddress='8.8.8.8';$route.Network.Containers.PSObject.Properties[$proxyId].Value.IPv4Address='8.8.8.8/16';$route.Resolved=@('8.8.8.8')}
        'ipv6-address' {$agentEndpoint.GlobalIPv6Address='fd00::1'}
        'agent-id' {$route.Agent.Id=$otherId}
        'proxy-stopped' {$route.Proxy.State.Running=$false}
        'foreign-member' {$route.Network.Containers | Add-Member -NotePropertyName $otherId -NotePropertyValue ([pscustomobject]@{})}
        'missing-ipam' {$route.Network.IPAM.Config=@()}
        'multiple-subnets' {$route.Network.IPAM.Config+=@([pscustomobject]@{Subnet='172.21.0.0/16';Gateway='172.21.0.1'})}
        'wrong-cidr' {$route.Cidr='172.21.0.0/16'}
        'cidr-host-bits' {$route.Cidr='172.20.0.2/16';$route.Network.IPAM.Config[0].Subnet=$route.Cidr}
        'prefix-drift' {$route.Network.Containers.PSObject.Properties[$proxyId].Value.IPv4Address='172.20.0.3/24'}
        'gateway-outside' {$route.Network.IPAM.Config[0].Gateway='172.21.0.1'}
        'address-outside' {$proxyEndpoint.IPAddress='172.21.0.3';$route.Network.Containers.PSObject.Properties[$proxyId].Value.IPv4Address='172.21.0.3/16';$route.Resolved=@('172.21.0.3')}
        'gateway-as-address' {$agentEndpoint.IPAddress='172.20.0.1';$route.Network.Containers.PSObject.Properties[$agentId].Value.IPv4Address='172.20.0.1/16'}
        'public-cidr' {$route.Cidr='172.0.0.0/8';$route.Network.IPAM.Config[0].Subnet=$route.Cidr}
        'upstream-overlap' {$upstreamEndpoint.IPAddress='172.20.0.99'}
        'upstream-public' {$upstreamEndpoint.IPAddress='8.8.8.8'}
        'upstream-missing' {$upstreamEndpoint.IPAddress=''}
    }
    $refused=$false;try {CheckRoute $route} catch {$refused=$true}
    Require-H454 $refused ('ROUTE_FIXTURE_ACCEPTED_'+$case)
}
. (Join-Path $PSScriptRoot 'h454_windows_recovery_route.ps1')
$recoveryValue='e'*32;$recoveryName='h454-test-network';$proxyName='h454-test-proxy';$proxyImage='sha256:'+('a'*64);$caHash='B'*64
function TestRecoveryRoute {
    $route=TestRoute
    $route.Network.Labels | Add-Member -NotePropertyName 'com.hermes.h454.recovery' -NotePropertyValue $recoveryValue
    $bridge=$route.Proxy.NetworkSettings.Networks.'h454-upstream'
    $route.Proxy.NetworkSettings.Networks.PSObject.Properties.Remove('h454-upstream')
    $route.Proxy.NetworkSettings.Networks | Add-Member -NotePropertyName 'bridge' -NotePropertyValue $bridge
    $route.Proxy | Add-Member -NotePropertyName Name -NotePropertyValue ('/'+$proxyName)
    $route.Proxy | Add-Member -NotePropertyName Image -NotePropertyValue $proxyImage
    $route.Proxy.State=[pscustomobject]@{Running=$true;Status='running';Paused=$false;Restarting=$false;Dead=$false}
    $route.Proxy | Add-Member -NotePropertyName Mounts -NotePropertyValue @()
    $route.Proxy | Add-Member -NotePropertyName Config -NotePropertyValue ([pscustomobject]@{
        Labels=[pscustomobject]@{'com.hermes.h454.recovery'=$recoveryValue};User='65534:65534';
        Entrypoint=@('node','/opt/hermes-rollback/proxy.mjs');Cmd=@('172.21.0.1',$caHash.ToLowerInvariant(),$route.Cidr);Env=@('NODE_VERSION=synthetic')})
    $route.Proxy | Add-Member -NotePropertyName HostConfig -NotePropertyValue ([pscustomobject]@{
        NetworkMode='bridge';ReadonlyRootfs=$true;Privileged=$false;CapDrop=@('ALL');CapAdd=$null;SecurityOpt=@('no-new-privileges');
        PidsLimit=32;Memory=134217728;RestartPolicy=[pscustomobject]@{Name='unless-stopped'};PublishAllPorts=$false;
        PortBindings=$null;Binds=$null;Devices=$null;DeviceRequests=$null;PidMode='';IpcMode='private'})
    return $route
}
function CheckRecoveryRoute([object]$Route){
    $plan=Assert-H454RecoveryNetwork $Route.Network $recoveryName $recoveryValue
    Assert-H454RecoveryProxy $Route.Proxy $proxyName $recoveryValue $proxyImage '172.21.0.1' $caHash $plan ('f'*64) -Connected
}
CheckRecoveryRoute (TestRecoveryRoute)
$brokerRoute=TestRecoveryRoute
$brokerRoute.Proxy.Config.Entrypoint[1]='/opt/hermes-rollback/broker.mjs'
$brokerPlan=Assert-H454RecoveryNetwork $brokerRoute.Network $recoveryName $recoveryValue
Assert-H454RecoveryProxy $brokerRoute.Proxy $proxyName $recoveryValue $proxyImage '172.21.0.1' $caHash $brokerPlan ('f'*64) -Connected -EntrypointPath '/opt/hermes-rollback/broker.mjs'
$refused=$false;try{CheckRecoveryRoute $brokerRoute}catch{$refused=$true}
Require-H454 $refused 'RECOVERY_ROUTE_WRONG_ENTRYPOINT'
function Invoke-H454RecoveryDocker {[CmdletBinding()]param([string[]]$Arguments,[string]$DockerSha256);$script:routeDockerCalls++;return [pscustomobject]@{Code=0;Output=$script:routeContainerListing}}
$script:routeDockerCalls=0;$script:routeContainerListing=$proxyId+'|'+$recoveryName
$stopped=TestRecoveryRoute
$stopped.Proxy.State=[pscustomobject]@{Running=$false;Status='created';Paused=$false;Restarting=$false;Dead=$false}
$stopped.Proxy.NetworkSettings.Networks.bridge.NetworkID=''
$stopped.Proxy.NetworkSettings.Networks.PSObject.Properties[$recoveryName].Value.NetworkID=''
CheckRecoveryRoute $stopped
$stopped.Proxy.State=[pscustomobject]@{Running=$true;Status='running';Paused=$false;Restarting=$false;Dead=$false}
$refused=$false;try{CheckRecoveryRoute $stopped}catch{$refused=$true}
Require-H454 $refused 'RECOVERY_ROUTE_RUNNING_WITHOUT_NETWORK_ID'
$stopped.Proxy.State=[pscustomobject]@{Running=$false;Status='created';Paused=$false;Restarting=$false;Dead=$false}
$stopped.Proxy.NetworkSettings.Networks.bridge.NetworkID='d'*64
$refused=$false;try{CheckRecoveryRoute $stopped}catch{$refused=$true}
Require-H454 $refused 'RECOVERY_ROUTE_STOPPED_WRONG_NETWORK_ID'

# Docker Desktop can leave the exact stopped old proxy with a stale bridge
# identity. The exception is explicit and may not apply to an active broker.
function Test-StoppedLegacyProxy {
    $route=TestRecoveryRoute
    $route.Proxy.Name='/h454-recovery-'+$recoveryValue+'-proxy'
    $route.Proxy.State=[pscustomobject]@{Running=$false;Status='exited';Paused=$false;Restarting=$false;Dead=$false}
    $route.Proxy.NetworkSettings.Networks.PSObject.Properties.Remove($recoveryName)
    $route.Proxy.NetworkSettings.Networks.bridge.NetworkID='d'*64
    return $route
}
function Assert-StoppedLegacyProxy([object]$Route,[switch]$Connected,[string]$EntrypointPath='/opt/hermes-rollback/proxy.mjs') {
    $plan=Assert-H454RecoveryNetwork $Route.Network $recoveryName $recoveryValue
    Assert-H454RecoveryProxy $Route.Proxy ('h454-recovery-'+$recoveryValue+'-proxy') $recoveryValue $proxyImage '172.21.0.1' $caHash $plan ('f'*64) -Connected:$Connected -EntrypointPath $EntrypointPath -AllowStoppedLegacyProxyBridge
}
$legacy=Test-StoppedLegacyProxy
$legacyPlan=Assert-H454RecoveryNetwork $legacy.Network $recoveryName $recoveryValue
$refused=$false
try { Assert-H454RecoveryProxy $legacy.Proxy ('h454-recovery-'+$recoveryValue+'-proxy') $recoveryValue $proxyImage '172.21.0.1' $caHash $legacyPlan ('f'*64) }
catch{$refused=$_.Exception.Message -ceq 'H454_ROUTE_PROXY_NETWORK'}
Require-H454 $refused 'RECOVERY_LEGACY_STALE_DENIED_BY_DEFAULT'
Assert-StoppedLegacyProxy $legacy
foreach($case in @('running','created','broker','connected','extra-network','wrong-image','wrong-label','wrong-name','wrong-alias','malformed-network-id','privileged')){
    $candidate=Test-StoppedLegacyProxy
    $connected=$false;$entry='/opt/hermes-rollback/proxy.mjs'
    switch($case){
        'running' {$candidate.Proxy.State.Running=$true;$candidate.Proxy.State.Status='running'}
        'created' {$candidate.Proxy.State.Status='created'}
        'broker' {$candidate.Proxy.Config.Entrypoint[1]='/opt/hermes-rollback/broker.mjs';$entry='/opt/hermes-rollback/broker.mjs'}
        'connected' {$connected=$true}
        'extra-network' {$candidate.Proxy.NetworkSettings.Networks | Add-Member -NotePropertyName 'foreign' -NotePropertyValue ([pscustomobject]@{})}
        'wrong-image' {$candidate.Proxy.Image='sha256:'+('0'*64)}
        'wrong-label' {$candidate.Proxy.Config.Labels.'com.hermes.h454.recovery'='d'*32}
        'wrong-name' {$candidate.Proxy.Name='/h454-unowned-proxy'}
        'wrong-alias' {$candidate.Proxy.NetworkSettings.Networks.bridge.Aliases=@('host.docker.internal')}
        'malformed-network-id' {$candidate.Proxy.NetworkSettings.Networks.bridge.NetworkID='d'*63}
        'privileged' {$candidate.Proxy.HostConfig.Privileged=$true}
    }
    $refused=$false
    try{Assert-StoppedLegacyProxy $candidate -Connected:$connected -EntrypointPath $entry}catch{$refused=$true}
    Require-H454 $refused ('RECOVERY_LEGACY_STALE_UNSAFE_ACCEPTED_'+$case)
}
'PS51_SYNTHETIC_STOPPED_LEGACY_PROXY_BRIDGE_EXCEPTION=PASS'
$membership=TestRecoveryRoute
$refused=$false;try{Assert-H454RecoveryRouteMembers $membership.Network $membership.Proxy ('C'*64)}catch{$refused=$true}
Require-H454 $refused 'RECOVERY_ROUTE_FOREIGN_MEMBER'
$script:routeContainerListing=$proxyId+'|'+$recoveryName+"`n"+$agentId+'|'+$recoveryName
Assert-H454RecoveryRouteMembers $membership.Network $membership.Proxy ('C'*64) $agentId
$membership.Network.Containers.PSObject.Properties.Remove($agentId)
$script:routeContainerListing=$proxyId+'|'+$recoveryName+"`n"+$agentId+'|'+$recoveryName
$refused=$false;try{Assert-H454RecoveryRouteMembers $membership.Network $membership.Proxy ('C'*64)}catch{$refused=$true}
Require-H454 $refused 'RECOVERY_ROUTE_STOPPED_FOREIGN_MEMBER'
Assert-H454RecoveryRouteMembers $membership.Network $membership.Proxy ('C'*64) $agentId
$refused=$false;try{Assert-H454RecoveryRouteMembers $membership.Network $membership.Proxy ('C'*64) $otherId}catch{$refused=$true}
Require-H454 $refused 'RECOVERY_ROUTE_STOPPED_WRONG_AGENT'
$script:routeContainerListing=$proxyId+'|'+$recoveryName
Assert-H454RecoveryRouteMembers $membership.Network $membership.Proxy ('C'*64)
$script:routeContainerListing=$proxyId+'|'+$recoveryName+"`n"+$proxyId+'|'+$recoveryName
$refused=$false;try{Assert-H454RecoveryRouteMembers $membership.Network $membership.Proxy ('C'*64)}catch{$refused=$true}
Require-H454 $refused 'RECOVERY_ROUTE_DUPLICATE_MEMBER'
$membership.Network.Containers.PSObject.Properties.Remove($proxyId)
$script:routeContainerListing=''
Assert-H454RecoveryRouteMembers $membership.Network $null ('C'*64)
foreach($case in @('label','public-network','proxy-image','proxy-label','proxy-user','proxy-command','privileged','writable-root',
                   'cap-add','security-opt','restart','mount','env','bridge-id','missing-alias','third-network')){
    $route=TestRecoveryRoute
    switch($case){
        'label' {$route.Network.Labels.'com.hermes.h454.recovery'='f'*32}
        'public-network' {$route.Network.Internal=$false}
        'proxy-image' {$route.Proxy.Image='sha256:'+('b'*64)}
        'proxy-label' {$route.Proxy.Config.Labels.'com.hermes.h454.recovery'='f'*32}
        'proxy-user' {$route.Proxy.Config.User='0:0'}
        'proxy-command' {$route.Proxy.Config.Cmd[0]='172.21.0.9'}
        'privileged' {$route.Proxy.HostConfig.Privileged=$true}
        'writable-root' {$route.Proxy.HostConfig.ReadonlyRootfs=$false}
        'cap-add' {$route.Proxy.HostConfig.CapAdd=@('SYS_ADMIN')}
        'security-opt' {$route.Proxy.HostConfig.SecurityOpt=@()}
        'restart' {$route.Proxy.HostConfig.RestartPolicy.Name='always'}
        'mount' {$route.Proxy.Mounts=@([pscustomobject]@{Destination='/opt/hermes-rollback'})}
        'env' {$route.Proxy.Config.Env=@('NODE_OPTIONS=fixture')}
        'bridge-id' {$route.Proxy.NetworkSettings.Networks.bridge.NetworkID='d'*64}
        'missing-alias' {$route.Proxy.NetworkSettings.Networks.PSObject.Properties[$recoveryName].Value.Aliases=@()}
        'third-network' {$route.Proxy.NetworkSettings.Networks|Add-Member -NotePropertyName 'foreign' -NotePropertyValue ([pscustomobject]@{})}
    }
    $refused=$false;try{CheckRecoveryRoute $route}catch{$refused=$true}
    Require-H454 $refused ('RECOVERY_ROUTE_FIXTURE_ACCEPTED_'+$case)
}
function TestRecoveryProbe {
    $route=TestRecoveryRoute;$probe=$route.Proxy
    $probe.Name='/h454-test-probe';$probe.Config.Labels=[pscustomobject]@{'com.hermes.h454.recovery-probe'=$recoveryValue}
    $probe.Config.Entrypoint=@('node');$probe.Config.Cmd=@('-e','synthetic-bootstrap','c3ludGhldGlj')
    $probe.HostConfig | Add-Member -NotePropertyName AutoRemove -NotePropertyValue $true
    $probe.HostConfig.RestartPolicy.Name='no'
    $probe.NetworkSettings.Networks.PSObject.Properties.Remove($recoveryName)
    return $probe
}
function CheckRecoveryProbe([object]$Probe){
    Assert-H454RecoveryProbe $Probe 'h454-test-probe' $recoveryValue $proxyImage ('f'*64) 'synthetic-bootstrap' 'c3ludGhldGlj'
}
CheckRecoveryProbe (TestRecoveryProbe)
foreach($case in @('label','image','command','user','restart','mount','env','network')){
    $probe=TestRecoveryProbe
    switch($case){
        'label' {$probe.Config.Labels.'com.hermes.h454.recovery-probe'='f'*32}
        'image' {$probe.Image='sha256:'+('b'*64)}
        'command' {$probe.Config.Cmd[2]='foreign'}
        'user' {$probe.Config.User='0:0'}
        'restart' {$probe.HostConfig.RestartPolicy.Name='always'}
        'mount' {$probe.Mounts=@([pscustomobject]@{Destination='/workspace'})}
        'env' {$probe.Config.Env=@('NODE_OPTIONS=fixture')}
        'network' {$probe.NetworkSettings.Networks|Add-Member -NotePropertyName 'foreign' -NotePropertyValue ([pscustomobject]@{})}
    }
    $refused=$false;try{CheckRecoveryProbe $probe}catch{$refused=$true}
    Require-H454 $refused ('RECOVERY_PROBE_FIXTURE_ACCEPTED_'+$case)
}
function Assert-H454RecoveryLock([string]$StateDir,[IO.FileStream]$Lock){}
function Assert-H454WssTaskFile([string]$Path,[string]$Sha256,[int]$Max){if($script:badMarker){throw 'FIXTURE_MARKER'}}
$script:routeDockerCalls=0;$script:badMarker=$false
$markerHash='A'*64;$image='sha256:'+('a'*64);$ca='B'*64;$dockerHash='C'*64
$refused=$false
try{$null=Prepare-H454RecoveryRoute $env:TEMP $null $markerHash $image $ca $dockerHash {$true} -Apply}catch{$refused=$_.Exception.Message -ceq 'H454_ROUTE_APPROVAL'}
Require-H454 ($refused -and $script:routeDockerCalls -eq 0) 'RECOVERY_ROUTE_APPROVAL'
$refused=$false
try{$null=Prepare-H454RecoveryRoute $env:TEMP $null 'bad' $image $ca $dockerHash {$true} -Apply -OwnerApproved}catch{$refused=$_.Exception.Message -ceq 'H454_ROUTE_PINS'}
Require-H454 ($refused -and $script:routeDockerCalls -eq 0) 'RECOVERY_ROUTE_PINS'
foreach($check in @({$false},{$true;$true})){
    $refused=$false
    try{$null=Prepare-H454RecoveryRoute $env:TEMP $null $markerHash $image $ca $dockerHash $check -Apply -OwnerApproved}catch{$refused=$_.Exception.Message -ceq 'H454_ROUTE_SAFETY'}
    Require-H454 ($refused -and $script:routeDockerCalls -eq 0) 'RECOVERY_ROUTE_SAFETY'
}
$script:badMarker=$true;$refused=$false
try{$null=Prepare-H454RecoveryRoute $env:TEMP $null $markerHash $image $ca $dockerHash {$true} -Apply -OwnerApproved}catch{$refused=$_.Exception.Message -ceq 'FIXTURE_MARKER'}
Require-H454 ($refused -and $script:routeDockerCalls -eq 0) 'RECOVERY_ROUTE_MARKER'
'PS51_RECOVERY_ROUTE_PROFILE=PASS'
'PS51_ISOLATED_NETWORK_MEMBERSHIP=PASS'
'PS51_ISOLATED_AGENT_ROUTE=PASS'
