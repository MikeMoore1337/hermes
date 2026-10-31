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
        Resolved=@('172.20.0.3');Override=$false}
}
function CheckRoute([object]$Route) {
    Assert-H454RollbackAgentRoute $Route.Network $Route.Agent $Route.Proxy $networkId $networkName $labelName $labelValue `
        $agentId $proxyId ('f'*64) 'h454-upstream' $Route.Resolved $Route.Override
}
CheckRoute (TestRoute)
foreach($case in @('agent-extra','proxy-extra','wrong-upstream','missing-alias','upstream-alias','upstream-alias-case','host-file','unknown-host-file',
                   'extra-hosts','dns-empty','dns-wrong','dns-mixed','dns-scalar','wrong-member-address','public-address','ipv6-address',
                   'agent-id','proxy-stopped','foreign-member')) {
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
    }
    $refused=$false;try {CheckRoute $route} catch {$refused=$true}
    Require-H454 $refused ('ROUTE_FIXTURE_ACCEPTED_'+$case)
}
'PS51_ISOLATED_NETWORK_MEMBERSHIP=PASS'
'PS51_ISOLATED_AGENT_ROUTE=PASS'
