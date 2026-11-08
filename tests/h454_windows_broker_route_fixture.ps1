#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$Source)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\scripts\h454_windows_network_guard_e2e.ps1') -Source $Source
. (Join-Path $PSScriptRoot '..\scripts\h454_windows_broker_route.ps1')
$marker='E'*64;$recoveryValue='e'*32;$networkName='h454-recovery-'+$recoveryValue;$recoveryName=$networkName
$proxyName=$networkName+'-proxy';$brokerName=$networkName+'-broker';$brokerImage='sha256:'+('f'*64);$brokerId='9'*64
$bridge=[pscustomobject]@{Id=('f'*64);Name='bridge';Driver='bridge'}
$script:route=$null;$script:broker=$null;$script:events=@();$script:checks=0;$script:failAt=0
$script:mutationFenceActive=$false;$script:delayStart=$false;$script:pendingStart=$false
function Open-H454MutationFence([string]$StateDir,[IO.FileStream]$Lock,[string]$Scope,[string]$MarkerSha256) {
    Require-H454 (-not $script:mutationFenceActive) 'H454_MUTATION_UNSETTLED'
    $script:mutationFenceActive=$true
    return [pscustomobject]@{Scope=$Scope}
}
function Close-H454MutationFence([string]$StateDir,[IO.FileStream]$Lock,[object]$Fence){
    Require-H454 $script:mutationFenceActive 'FIXTURE_FENCE_MISSING'
    $script:mutationFenceActive=$false
}
function Reset-Fixture {
    $script:route=TestRecoveryRoute
    $script:route.Network.Containers.PSObject.Properties.Remove($agentId)
    $script:broker=$null;$script:events=@();$script:checks=0;$script:failAt=0
    $script:mutationFenceActive=$false;$script:delayStart=$false;$script:pendingStart=$false
}
function Find-H454RecoveryObject([string]$Kind,[string]$Name,[string]$DockerSha256){
    if($Kind -ceq 'network' -and $Name -ceq 'bridge'){return $bridge}
    if($Kind -ceq 'network' -and $Name -ceq $networkName){return $script:route.Network}
    if($Kind -ceq 'container' -and $Name -ceq $proxyName){return $script:route.Proxy}
    if($Kind -ceq 'container' -and $Name -ceq $brokerName){return $script:broker}
    return $null
}
function Assert-H454RecoveryRouteSafety([string]$StateDir,[IO.FileStream]$Lock,[string]$MarkerSha256,[scriptblock]$SafetyCheck){
    $script:checks++
    if($script:checks -eq $script:failAt){throw 'H454_ROUTE_SAFETY'}
    if(-not (& $SafetyCheck)){throw 'H454_ROUTE_SAFETY'}
}
function Invoke-H454RecoveryDocker {
    param([string[]]$Arguments,[string]$DockerSha256)
    $first=$Arguments[0];$second=if($Arguments.Count -gt 1){$Arguments[1]}else{''};$out=''
    if($first -ceq 'image' -and $second -ceq 'inspect'){
        $out=ConvertTo-Json -Compress -InputObject @([pscustomobject]@{Id=$brokerImage})
    }elseif($first -ceq 'container' -and $second -ceq 'ls'){
        $rows=@();foreach($item in @($script:route.Proxy,$script:broker)){
            if($null -ne $item){$rows+=($item.Id+'|'+(@($item.NetworkSettings.Networks.PSObject.Properties.Name) -join ','))}
        };$out=$rows -join "`n"
    }elseif($first -ceq 'stop'){
        $script:events+=@('stop');$script:route.Proxy.State.Running=$false;$script:route.Proxy.State.Status='exited'
    }elseif($first -ceq 'network' -and $second -ceq 'disconnect'){
        $script:events+=@('disconnect');$script:route.Proxy.NetworkSettings.Networks.PSObject.Properties.Remove($networkName)
        $script:route.Network.Containers.PSObject.Properties.Remove($proxyId)
    }elseif($first -ceq 'create'){
        $script:events+=@('create')
        $script:broker=ConvertFrom-Json -InputObject (ConvertTo-Json -InputObject $script:route.Proxy -Depth 30 -Compress)
        $script:broker.Id=$brokerId;$script:broker.Name='/'+$brokerName;$script:broker.Image=$brokerImage
        $script:broker.Config.Entrypoint[1]='/opt/hermes-rollback/broker.mjs'
        $script:broker.State.Status='created';$out=$brokerId
    }elseif($first -ceq 'network' -and $second -ceq 'connect'){
        $script:events+=@('connect')
        $endpoint=[pscustomobject]@{NetworkID=$networkId;IPAddress='172.20.0.3';GlobalIPv6Address='';Aliases=@('host.docker.internal')}
        $script:broker.NetworkSettings.Networks|Add-Member -NotePropertyName $networkName -NotePropertyValue $endpoint
    }elseif($first -ceq 'start'){
        $script:events+=@('start')
        if($script:delayStart){
            $script:delayStart=$false;$script:pendingStart=$true
            throw 'H454_DOCKER_AMBIGUOUS'
        }
        $script:broker.State.Running=$true;$script:broker.State.Status='running'
        $script:route.Network.Containers|Add-Member -NotePropertyName $brokerId -NotePropertyValue ([pscustomobject]@{IPv4Address='172.20.0.3/16'})
    }elseif($first -ceq 'exec'){$out='H454_BROKER_LISTENERS=PASS'}
    else{throw 'SYNTHETIC_UNEXPECTED_DOCKER'}
    return [pscustomobject]@{Code=0;Output=$out}
}
$safety={return $true}
Reset-Fixture
$refused=$false
try{$null=Prepare-H454RecoveryBroker 'fixture' $null $marker $proxyImage $brokerImage $caHash ('C'*64) $safety -Apply}catch{$refused=$true}
Require-H454 ($refused -and $script:events.Count -eq 0) 'BROKER_ROUTE_APPROVAL'
foreach($point in @(2,3,4,5,6,7)){
    Reset-Fixture;$script:failAt=$point;$refused=$false
    try{$null=Prepare-H454RecoveryBroker 'fixture' $null $marker $proxyImage $brokerImage $caHash ('C'*64) $safety -Apply -OwnerApproved}
    catch{$refused=$_.Exception.Message -ceq 'H454_ROUTE_SAFETY'}
    Require-H454 $refused 'BROKER_ROUTE_FAILURE_INJECTION'
    $script:failAt=0
    $before=$script:events.Count;$reason=''
    try{$null=Prepare-H454RecoveryBroker 'fixture' $null $marker $proxyImage $brokerImage $caHash ('C'*64) $safety -Apply -OwnerApproved}
    catch{$reason=$_.Exception.Message}
    Require-H454 ($reason -ceq 'H454_MUTATION_UNSETTLED' -and
        $script:events.Count -eq $before) 'BROKER_ROUTE_REPLAY_BLOCKED'
    # Fixture-only owner-confirmed settlement; not a production bypass.
    $script:mutationFenceActive=$false
    $result=Prepare-H454RecoveryBroker 'fixture' $null $marker $proxyImage $brokerImage $caHash ('C'*64) $safety -Apply -OwnerApproved
    Require-H454 ($result.Status -ceq 'BROKER_READY' -and $result.BrokerId -ceq $brokerId -and
        ($script:events -join ',') -ceq 'stop,disconnect,create,connect,start') 'BROKER_ROUTE_RESUME'
    $again=Prepare-H454RecoveryBroker 'fixture' $null $marker $proxyImage $brokerImage $caHash ('C'*64) $safety -Apply -OwnerApproved
    Require-H454 ($again.Status -ceq 'BROKER_READY' -and ($script:events -join ',') -ceq 'stop,disconnect,create,connect,start') 'BROKER_ROUTE_IDEMPOTENCY'
}
Reset-Fixture;$script:delayStart=$true;$reason=''
try{$null=Prepare-H454RecoveryBroker 'fixture' $null $marker $proxyImage $brokerImage $caHash ('C'*64) $safety -Apply -OwnerApproved}
catch{$reason=$_.Exception.Message}
Require-H454 ($reason -ceq 'H454_DOCKER_AMBIGUOUS' -and
    $script:pendingStart -and $script:mutationFenceActive) 'BROKER_DELAYED_START'
$before=$script:events.Count;$refused=$false
try{$null=Prepare-H454RecoveryBroker 'fixture' $null $marker $proxyImage $brokerImage $caHash ('C'*64) $safety -Apply -OwnerApproved}
catch{$refused=$true}
Require-H454 ($refused -and $script:events.Count -eq $before) 'BROKER_DELAYED_NO_REPLAY'
$script:broker.State.Running=$true;$script:broker.State.Status='running'
$script:route.Network.Containers|Add-Member -NotePropertyName $brokerId -NotePropertyValue ([pscustomobject]@{IPv4Address='172.20.0.3/16'})
$script:pendingStart=$false;$reason=''
try{$null=Prepare-H454RecoveryBroker 'fixture' $null $marker $proxyImage $brokerImage $caHash ('C'*64) $safety -Apply -OwnerApproved}
catch{$reason=$_.Exception.Message}
Require-H454 ($reason -ceq 'H454_MUTATION_UNSETTLED' -and
    $script:events.Count -eq $before) 'BROKER_DELAYED_AFTER_SETTLEMENT_HOLD'
$script:mutationFenceActive=$false
$done=Prepare-H454RecoveryBroker 'fixture' $null $marker $proxyImage $brokerImage $caHash ('C'*64) $safety -Apply -OwnerApproved
Require-H454 ($done.Status -ceq 'BROKER_READY' -and $script:events.Count -eq $before) 'BROKER_DELAYED_MANUAL_RESUME'
'PS51_SYNTHETIC_BROKER_ROUTE_DELAYED_DOCKER=PASS'
'PS51_SYNTHETIC_BROKER_ROUTE_INTERRUPTION=PASS'
