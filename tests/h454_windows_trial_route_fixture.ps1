$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\scripts\h454_windows_network_guard.ps1')
. (Join-Path $PSScriptRoot '..\scripts\h454_windows_recovery_route.ps1')
. (Join-Path $PSScriptRoot '..\scripts\h454_windows_original_restore.ps1')
function Require-H454([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
$script:agentId='a'*64;$script:candidateId='b'*64;$script:brokerId='c'*64
$script:bridgeId='d'*64;$script:privateId='e'*64;$script:marker='F'*64
$script:networkName='h454-recovery-'+('f'*32)
$script:agent=[pscustomobject]@{Id=$script:agentId;State=[pscustomobject]@{Running=$false;Status='exited';Paused=$false;Restarting=$false;Dead=$false};
    HostConfig=[pscustomobject]@{RestartPolicy=[pscustomobject]@{Name='no'}};
    NetworkSettings=[pscustomobject]@{Networks=[pscustomobject]@{bridge=[pscustomobject]@{NetworkID=$script:bridgeId;Aliases=@()}}}}
$script:broker=[pscustomobject]@{Id=$script:brokerId;Config=[pscustomobject]@{Cmd=@('10.1.2.3','fixture','fixture')};State=[pscustomobject]@{Running=$true}}
$script:old=[pscustomobject]@{State=[pscustomobject]@{Running=$false;Status='exited'};
    NetworkSettings=[pscustomobject]@{Networks=[pscustomobject]@{
        bridge=[pscustomobject]@{NetworkID=$script:bridgeId;Aliases=@()}}}}
$script:bridge=[pscustomobject]@{Id=$script:bridgeId;Driver='bridge'}
$script:network=[pscustomobject]@{Id=$script:privateId;Name=$script:networkName;Containers=[pscustomobject]@{}}
$script:extra=''
function Assert-H454RecoveryRouteSafety {return}
function Assert-H454RecoveryNetwork {return [pscustomobject]@{Id=$script:privateId;Base=[uint64]0;Last=[uint64]0}}
function Assert-H454RecoveryProxy {return}
function Assert-H454OriginalProfile {return}
function Find-H454RecoveryObject($Kind,$Name,$DockerSha256){
    if($Kind -ceq 'network' -and $Name -ceq $script:networkName){return $script:network}
    if($Kind -ceq 'network' -and $Name -ceq 'bridge'){return $script:bridge}
    if($Name -ceq ($script:networkName+'-proxy')){return $script:old}
    if($Name -ceq ($script:networkName+'-broker')){return $script:broker}
    if($Name -ceq 'fixture-agent'){return $script:agent}
    throw 'FIXTURE_LOOKUP'
}
function Invoke-H454RecoveryDocker([string[]]$Arguments,[string]$DockerSha256){
    $rows=@($script:brokerId+'|bridge,'+$script:networkName)
    $agentNetworks=@($script:agent.NetworkSettings.Networks.PSObject.Properties.Name) -join ','
    $rows+=@($script:agentId+'|'+$agentNetworks)
    if($script:extra -cne ''){$rows+=@($script:extra+'|'+$script:networkName)}
    return [pscustomobject]@{Code=0;Output=($rows -join "`n")}
}
function Set-Members([string[]]$Ids){
    $members=[ordered]@{};foreach($id in $Ids){$members[$id]=[pscustomobject]@{}}
    $script:network.Containers=[pscustomobject]$members
}
$params=@{StateDir='fixture';Lock=$null;MarkerSha256=$script:marker;SafetyCheck={return $true};Launcher='fixture';
    LauncherSha256=('A'*64);AgentId=$script:agentId;AgentImage=('sha256:'+('1'*64));AgentName='fixture-agent';
    OldImage=('sha256:'+('2'*64));BrokerImage=('sha256:'+('3'*64));CaSha256=('B'*64);DockerSha256=('C'*64)}
Set-Members @($script:brokerId,$script:candidateId)
$script:extra=$script:candidateId
$snapshot=Get-H454OriginalRestoreState @params -AlternateAgentId $script:candidateId
Require-H454 ($snapshot.OnBridge -and -not $snapshot.OnPrivate -and -not $snapshot.Agent.State.Running) 'FIXTURE_ALTERNATE'
foreach($case in @('default_refuses_candidate','same_identity','original_running','original_private','foreign_member')){
    $saved=ConvertTo-Json -Depth 10 -Compress -InputObject $script:agent
    $savedExtra=$script:extra;$alternate=$script:candidateId
    switch($case){
        'same_identity'{$alternate=$script:agentId}
        'original_running'{$script:agent.State.Running=$true;$script:agent.State.Status='running'}
        'original_private'{$script:agent.NetworkSettings.Networks|Add-Member -NotePropertyName $script:networkName -NotePropertyValue ([pscustomobject]@{NetworkID=$script:privateId;Aliases=@()})}
        'foreign_member'{$script:extra='9'*64}
    }
    $refused=$false
    try{if($case -ceq 'default_refuses_candidate'){$null=Get-H454OriginalRestoreState @params}else{$null=Get-H454OriginalRestoreState @params -AlternateAgentId $alternate}}catch{$refused=$true}
    Require-H454 $refused 'FIXTURE_ALTERNATE_DRIFT'
    $script:agent=ConvertFrom-Json -InputObject $saved;$script:extra=$savedExtra
}
$script:agent.State.Running=$true;$script:agent.State.Status='running'
$script:agent.NetworkSettings.Networks=[pscustomobject]@{}
$script:agent.NetworkSettings.Networks|Add-Member -NotePropertyName $script:networkName -NotePropertyValue ([pscustomobject]@{NetworkID=$script:privateId;Aliases=@()})
$script:extra='';Set-Members @($script:brokerId,$script:agentId)
$snapshot=Get-H454OriginalRestoreState @params
Require-H454 ($snapshot.Agent.State.Running -and $snapshot.OnPrivate -and -not $snapshot.OnBridge) 'FIXTURE_ORIGINAL'
'PS51_SYNTHETIC_TRIAL_ROUTE=PASS'
