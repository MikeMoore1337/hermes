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
'PS51_ISOLATED_NETWORK_MEMBERSHIP=PASS'
