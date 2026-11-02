#requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\scripts\h454_windows_candidate_prepare.ps1')
function Require-H454([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
$script:agentId='a'*64;$script:baseId='sha256:'+('b'*64);$script:imageId='sha256:'+('c'*64)
$script:candidateId='d'*64;$script:marker='E'*64;$script:label='e'*32
$config=[pscustomobject]@{Entrypoint=@('/bin/sh','/entry');Cmd=@();Env=@('HOME=/run/brc');WorkingDir='/workspace';User='65534:65534'}
$script:base=[pscustomobject]@{Id=$script:baseId;Config=$config;RootFS=[pscustomobject]@{Layers=@('layer1','layer2')}}
$script:image=[pscustomobject]@{Id=$script:imageId;Config=$config;RootFS=[pscustomobject]@{Layers=@('layer1','layer2','layer3')}}
$tmpfs=[pscustomobject]@{'/run/brc'='rw,nosuid,nodev,noexec,uid=65534,gid=65534,mode=0700,size=8m';
    '/tmp'='rw,nosuid,nodev,noexec,uid=65534,gid=65534,mode=0700,size=64m'}
$mount=[pscustomobject]@{Type='bind';Destination='/workspace';RW=$true}
$script:original=[pscustomobject]@{Id=$script:agentId;Config=[pscustomobject]@{Labels=[pscustomobject]@{'com.hermes.scope'='fixture'}};
    State=[pscustomobject]@{Running=$true};HostConfig=[pscustomobject]@{Tmpfs=$tmpfs};Mounts=@($mount)}
$script:candidate=$null;$script:creates=0;$script:checks=0;$script:failAt=0;$script:ambiguous=$false
function Get-H454OriginalRestoreState {
    param($StateDir,$Lock,$MarkerSha256,$SafetyCheck,$Launcher,$LauncherSha256,$AgentId,$AgentImage,$AgentName,
        $OldImage,$BrokerImage,$CaSha256,$DockerSha256)
    $script:checks++;if($script:checks -eq $script:failAt){throw 'H454_ROUTE_SAFETY'}
    Require-H454 ($AgentId -ceq $script:agentId -and $script:original.State.Running) 'FIXTURE_ORIGINAL'
    return [pscustomobject]@{Agent=$script:original}
}
function Assert-H454OriginalLiveRoute($Snapshot,$AgentId,$DockerSha256){
    Require-H454 ($Snapshot.Agent.Id -ceq $script:agentId -and $Snapshot.Agent.State.Running) 'FIXTURE_ROUTE'
}
function Get-H454CandidateImage($Image,$DockerSha256){
    if($Image -ceq $script:baseId){return $script:base}
    if($Image -ceq $script:imageId){return $script:image}
    throw 'FIXTURE_IMAGE'
}
function Find-H454RecoveryObject($Kind,$Name,$DockerSha256){
    Require-H454 ($Kind -ceq 'container' -and $Name -ceq 'hermes-h454-broker-candidate') 'FIXTURE_LOOKUP'
    return $script:candidate
}
function Invoke-H454RecoveryDocker {
    param([string[]]$Arguments,[string]$DockerSha256)
    Require-H454 ($Arguments[0] -ceq 'create' -and $Arguments -ccontains '--network' -and
        $Arguments -ccontains 'none' -and $Arguments -ccontains '--volumes-from' -and
        $Arguments -ccontains $script:agentId -and $Arguments -ccontains $script:imageId) 'FIXTURE_CREATE_ARGUMENTS'
    $script:creates++
    $script:candidate=[pscustomobject]@{Id=$script:candidateId;Name='/hermes-h454-broker-candidate';Image=$script:imageId;
        State=[pscustomobject]@{Running=$false;Status='created';Paused=$false;Restarting=$false;Dead=$false};
        Config=[pscustomobject]@{User='65534:65534';WorkingDir='/workspace';Entrypoint=$config.Entrypoint;Cmd=$config.Cmd;Env=$config.Env;
            Labels=[pscustomobject]@{'com.hermes.scope'='fixture';'com.hermes.h454.candidate'=$script:label}};
        HostConfig=[pscustomobject]@{NetworkMode='none';ReadonlyRootfs=$true;Privileged=$false;Init=$true;PidsLimit=128;
            Memory=536870912;NanoCpus=1000000000;RestartPolicy=[pscustomobject]@{Name='no'};CapDrop=@('ALL');CapAdd=@();
            SecurityOpt=@('no-new-privileges');PublishAllPorts=$false;PortBindings=$null;ExtraHosts=@();Binds=@();
            Devices=@();DeviceRequests=@();PidMode='';IpcMode='private';VolumesFrom=@($script:agentId);
            Tmpfs=(ConvertFrom-Json -InputObject (ConvertTo-Json -Compress -InputObject $tmpfs))};
        NetworkSettings=[pscustomobject]@{Networks=[pscustomobject]@{none=[pscustomobject]@{}}};
        Mounts=@([pscustomobject]@{Type='bind';Destination='/workspace';RW=$true})}
    if($script:ambiguous){$script:ambiguous=$false;throw 'H454_DOCKER_AMBIGUOUS'}
    return [pscustomobject]@{Code=0;Output=$script:candidateId}
}
$params=@{StateDir='fixture';Lock=$null;MarkerSha256=$script:marker;SafetyCheck={return $true};Launcher='fixture';
    LauncherSha256=('A'*64);AgentId=$script:agentId;AgentImage=$script:baseId;AgentName='fixture';
    OldImage=('sha256:'+('f'*64));BrokerImage=('sha256:'+('e'*64));CaSha256=('A'*64);DockerSha256=('B'*64)}
$preview=Prepare-H454BrokerCandidate $params $script:imageId
Require-H454 ($preview.Status -ceq 'PREFLIGHT' -and -not $preview.Present -and $script:creates -eq 0) 'FIXTURE_PREVIEW'
$refused=$false;try{$null=Prepare-H454BrokerCandidate $params $script:imageId -Apply}catch{$refused=$true}
Require-H454 ($refused -and $script:creates -eq 0) 'FIXTURE_APPROVAL'
$script:checks=0;$script:failAt=2;$refused=$false
try{$null=Prepare-H454BrokerCandidate $params $script:imageId -Apply -OwnerApproved}catch{$refused=$true}
Require-H454 ($refused -and $script:creates -eq 0) 'FIXTURE_LOCK_LOSS'
$script:checks=0;$script:failAt=0;$script:ambiguous=$true;$refused=$false
try{$null=Prepare-H454BrokerCandidate $params $script:imageId -Apply -OwnerApproved}catch{$refused=$_.Exception.Message -ceq 'H454_DOCKER_AMBIGUOUS'}
Require-H454 ($refused -and $script:creates -eq 1 -and $null -ne $script:candidate) 'FIXTURE_AMBIGUOUS'
$result=Prepare-H454BrokerCandidate $params $script:imageId -Apply -OwnerApproved
Require-H454 ($result.Status -ceq 'CANDIDATE_CREATED_STOPPED' -and $result.CandidateId -ceq $script:candidateId -and
    $script:creates -eq 1) 'FIXTURE_RESUME'
foreach($change in @('running','network','mount','volume','caps','label','tmpfs')){
    $saved=ConvertTo-Json -Depth 30 -Compress -InputObject $script:candidate
    switch($change){
        'running'{$script:candidate.State.Running=$true}
        'network'{$script:candidate.HostConfig.NetworkMode='bridge'}
        'mount'{$script:candidate.Mounts[0].Destination='/other'}
        'volume'{$script:candidate.HostConfig.VolumesFrom=@('f'*64)}
        'caps'{$script:candidate.HostConfig.CapAdd=@('SYS_ADMIN')}
        'label'{$script:candidate.Config.Labels.'com.hermes.h454.candidate'='foreign'}
        'tmpfs'{$script:candidate.HostConfig.Tmpfs.'/tmp'='rw'}
    }
    $refused=$false;try{$null=Prepare-H454BrokerCandidate $params $script:imageId -Apply -OwnerApproved}catch{$refused=$true}
    Require-H454 ($refused -and $script:creates -eq 1) 'FIXTURE_DRIFT'
    $script:candidate=ConvertFrom-Json -InputObject $saved
    $valid=Prepare-H454BrokerCandidate $params $script:imageId -Apply -OwnerApproved
    Require-H454 ($valid.CandidateId -ceq $script:candidateId -and $script:creates -eq 1) 'FIXTURE_DRIFT_RESET'
}
$script:image.RootFS.Layers=@('foreign','layer2','layer3');$refused=$false
try{$null=Prepare-H454BrokerCandidate $params $script:imageId -Apply -OwnerApproved}catch{$refused=$true}
Require-H454 ($refused -and $script:creates -eq 1) 'FIXTURE_IMAGE_DRIFT'
'PS51_SYNTHETIC_CANDIDATE_PREPARE=PASS'
