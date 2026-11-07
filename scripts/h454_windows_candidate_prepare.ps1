#requires -Version 5.1
# The caller owns the recovery lock; this only creates a stopped candidate.
function Get-H454CandidateImage([string]$Image,[string]$DockerSha256) {
    $result=Invoke-H454RecoveryDocker -Arguments @('image','inspect',$Image) -DockerSha256 $DockerSha256
    Require-H454 ($result.Code -eq 0 -and $result.Output.Length -gt 0) 'H454_CANDIDATE_IMAGE'
    $items=@($result.Output | ConvertFrom-Json -ErrorAction Stop)
    Require-H454 ($items.Count -eq 1 -and $items[0].Id -ceq $Image) 'H454_CANDIDATE_IMAGE'
    return $items[0]
}

function Assert-H454CandidateImage([object]$Base,[object]$Candidate,[string]$BaseId,[string]$CandidateId) {
    Require-H454 ($null -ne $Base -and $null -ne $Candidate -and $Base.Id -ceq $BaseId -and
        $Candidate.Id -ceq $CandidateId -and $BaseId -cne $CandidateId -and
        $null -ne $Base.Config -and $null -ne $Candidate.Config) 'H454_CANDIDATE_IMAGE'
    foreach($name in @('Entrypoint','Cmd','Env','WorkingDir','User')){
        $beforeProperty=$Base.Config.PSObject.Properties[$name];$afterProperty=$Candidate.Config.PSObject.Properties[$name]
        Require-H454 ($name -ceq 'Cmd' -or ($null -ne $beforeProperty -and $null -ne $afterProperty)) 'H454_CANDIDATE_IMAGE_PROFILE'
        $beforeValue=if($null -eq $beforeProperty){$null}else{$beforeProperty.Value}
        $afterValue=if($null -eq $afterProperty){$null}else{$afterProperty.Value}
        $a=ConvertTo-Json -Compress -Depth 10 -InputObject $beforeValue
        $b=ConvertTo-Json -Compress -Depth 10 -InputObject $afterValue
        Require-H454 ($a -ceq $b) 'H454_CANDIDATE_IMAGE_PROFILE'
    }
    $before=@($Base.RootFS.Layers);$after=@($Candidate.RootFS.Layers)
    Require-H454 ($before.Count -gt 0 -and $after.Count -gt $before.Count) 'H454_CANDIDATE_IMAGE_LAYERS'
    for($i=0;$i -lt $before.Count;$i++){
        Require-H454 ($before[$i] -is [string] -and $before[$i] -ceq $after[$i]) 'H454_CANDIDATE_IMAGE_LAYERS'
    }
}

function Assert-H454PreparedCandidate([object]$Candidate,[object]$Original,[object]$Image,
    [string]$Name,[string]$ImageId,[string]$AgentId,[string]$Label,[string]$BridgeId,
    [string]$PrivateNetworkName='', [string]$PrivateNetworkId='') {
    $transition=($PrivateNetworkName -cne '' -or $PrivateNetworkId -cne '')
    if($transition){
        Require-H454 ($PrivateNetworkName -cmatch '^h454-recovery-[a-f0-9]{32}$' -and
            $PrivateNetworkId -cmatch '^[a-f0-9]{64}$' -and $PrivateNetworkId -cne $BridgeId) 'H454_CANDIDATE_NETWORK'
    }
    Require-H454 ($null -ne $Candidate -and $Candidate.Id -cmatch '^[a-f0-9]{64}$' -and
        $Candidate.Name -ceq ('/'+$Name) -and $Candidate.Image -ceq $ImageId -and
        $Candidate.State.Running -is [bool] -and
        (($Candidate.State.Running -and $transition -and $Candidate.State.Status -ceq 'running') -or
         (-not $Candidate.State.Running -and $Candidate.State.Status -ceq 'created') -or
         (-not $Candidate.State.Running -and $transition -and $Candidate.State.Status -ceq 'exited')) -and
        $Candidate.State.Paused -is [bool] -and -not $Candidate.State.Paused -and
        $Candidate.State.Restarting -is [bool] -and -not $Candidate.State.Restarting -and
        $Candidate.State.Dead -is [bool] -and -not $Candidate.State.Dead) 'H454_CANDIDATE_STATE'
    $cfg=$Candidate.Config;$hostConfig=$Candidate.HostConfig
    Require-H454 ($null -ne $cfg -and $null -ne $hostConfig -and $cfg.User -ceq '65534:65534' -and
        $cfg.WorkingDir -ceq '/workspace' -and $cfg.Labels.'com.hermes.h454.candidate' -ceq $Label) 'H454_CANDIDATE_PROFILE'
    foreach($name in @('Entrypoint','Cmd','Env')){
        $actualProperty=$cfg.PSObject.Properties[$name];$imageProperty=$Image.Config.PSObject.Properties[$name]
        Require-H454 ($name -ceq 'Cmd' -or ($null -ne $actualProperty -and $null -ne $imageProperty)) 'H454_CANDIDATE_PROFILE'
        $actualValue=if($null -eq $actualProperty){$null}else{$actualProperty.Value}
        $imageValue=if($null -eq $imageProperty){$null}else{$imageProperty.Value}
        Require-H454 ((ConvertTo-Json -Compress -Depth 10 -InputObject $actualValue) -ceq
            (ConvertTo-Json -Compress -Depth 10 -InputObject $imageValue)) 'H454_CANDIDATE_PROFILE'
    }
    $oldLabels=@($Original.Config.Labels.PSObject.Properties);$newLabels=@($cfg.Labels.PSObject.Properties)
    Require-H454 ($newLabels.Count -eq $oldLabels.Count+1) 'H454_CANDIDATE_LABELS'
    foreach($entry in $oldLabels){
        $other=$cfg.Labels.PSObject.Properties[$entry.Name]
        Require-H454 ($null -ne $other -and $other.Value -ceq $entry.Value) 'H454_CANDIDATE_LABELS'
    }
    Require-H454 ($hostConfig.NetworkMode -ceq 'bridge' -and $hostConfig.ReadonlyRootfs -is [bool] -and $hostConfig.ReadonlyRootfs -and
        $hostConfig.Privileged -is [bool] -and -not $hostConfig.Privileged -and $hostConfig.Init -is [bool] -and $hostConfig.Init -and
        $hostConfig.PidsLimit -eq 128 -and $hostConfig.Memory -eq 536870912 -and $hostConfig.NanoCpus -eq 1000000000 -and
        $hostConfig.RestartPolicy.Name -ceq 'no' -and @($hostConfig.CapDrop).Count -eq 1 -and
        @($hostConfig.CapDrop) -ccontains 'ALL' -and ($null -eq $hostConfig.CapAdd -or @($hostConfig.CapAdd).Count -eq 0) -and
        @($hostConfig.SecurityOpt).Count -eq 1 -and [string]$hostConfig.SecurityOpt[0] -ceq 'no-new-privileges' -and
        $hostConfig.PublishAllPorts -is [bool] -and -not $hostConfig.PublishAllPorts -and
        ($null -eq $hostConfig.PortBindings -or @($hostConfig.PortBindings.PSObject.Properties).Count -eq 0) -and
        ($null -eq $hostConfig.ExtraHosts -or @($hostConfig.ExtraHosts).Count -eq 0) -and
        ($null -eq $hostConfig.Dns -or @($hostConfig.Dns).Count -eq 0) -and
        ($null -eq $hostConfig.DnsOptions -or @($hostConfig.DnsOptions).Count -eq 0) -and
        ($null -eq $hostConfig.DnsSearch -or @($hostConfig.DnsSearch).Count -eq 0) -and
        ($null -eq $hostConfig.Links -or @($hostConfig.Links).Count -eq 0) -and
        ($null -eq $hostConfig.Binds -or @($hostConfig.Binds).Count -eq 0) -and
        ($null -eq $hostConfig.Devices -or @($hostConfig.Devices).Count -eq 0) -and
        ($null -eq $hostConfig.DeviceRequests -or @($hostConfig.DeviceRequests).Count -eq 0) -and
        [string]$hostConfig.PidMode -cnotmatch '^(?:host|container:)' -and
        [string]$hostConfig.IpcMode -cnotmatch '^(?:host|container:)') 'H454_CANDIDATE_PROFILE'
    $networks=@($Candidate.NetworkSettings.Networks.PSObject.Properties.Name)
    $bridge=$Candidate.NetworkSettings.Networks.PSObject.Properties['bridge']
    $private=if($transition){$Candidate.NetworkSettings.Networks.PSObject.Properties[$PrivateNetworkName]}else{$null}
    $onBridge=($null -ne $bridge);$onPrivate=($null -ne $private)
    Require-H454 ($BridgeId -cmatch '^[a-f0-9]{64}$' -and
        (($networks.Count -eq 1 -and ($onBridge -or $onPrivate)) -or
         ($transition -and -not $Candidate.State.Running -and $networks.Count -eq 2 -and $onBridge -and $onPrivate)) -and
        (-not $Candidate.State.Running -or ($onPrivate -and -not $onBridge)) -and
        @($hostConfig.VolumesFrom).Count -eq 1 -and [string]$hostConfig.VolumesFrom[0] -ceq $AgentId -and
        @($Original.Mounts).Count -eq 1 -and @($Candidate.Mounts).Count -eq 1) 'H454_CANDIDATE_MOUNT'
    foreach($pair in @(@($bridge,$BridgeId),@($private,$PrivateNetworkId))){
        $endpoint=$pair[0]
        if($null -ne $endpoint){
            Require-H454 ($endpoint.Value.NetworkID -ceq $pair[1] -or
                (-not $Candidate.State.Running -and [string]::IsNullOrEmpty([string]$endpoint.Value.NetworkID))) 'H454_CANDIDATE_NETWORK'
            foreach($alias in @($endpoint.Value.Aliases)){
                Require-H454 ($null -eq $alias -or ($alias -is [string] -and
                    -not $alias.TrimEnd('.').Equals('host.docker.internal',[StringComparison]::OrdinalIgnoreCase))) 'H454_CANDIDATE_NETWORK'
            }
        }
    }
    foreach($mount in @($Original.Mounts[0],$Candidate.Mounts[0])){
        Require-H454 ($mount.Type -ceq 'bind' -and $mount.Destination -ceq '/workspace' -and
            $mount.RW -is [bool] -and $mount.RW) 'H454_CANDIDATE_MOUNT'
    }
    $tmpfs=@($hostConfig.Tmpfs.PSObject.Properties)
    Require-H454 ($tmpfs.Count -eq 2) 'H454_CANDIDATE_TMPFS'
    foreach($name in @('/run/brc','/tmp')){
        $expected=$Original.HostConfig.Tmpfs.PSObject.Properties[$name]
        $actual=$hostConfig.Tmpfs.PSObject.Properties[$name]
        Require-H454 ($null -ne $expected -and $null -ne $actual -and $actual.Value -ceq $expected.Value) 'H454_CANDIDATE_TMPFS'
    }
}

function Prepare-H454BrokerCandidate([hashtable]$RestoreArgs,[string]$CandidateImage,
    [switch]$Apply,[switch]$OwnerApproved) {
    Require-H454 (-not $Apply -or $OwnerApproved) 'H454_CANDIDATE_APPROVAL'
    Require-H454 ($null -ne $RestoreArgs -and $CandidateImage -cmatch '^sha256:[a-f0-9]{64}$' -and
        $CandidateImage -cne $RestoreArgs.AgentImage) 'H454_CANDIDATE_PINS'
    $s=@{StateDir=$RestoreArgs.StateDir;Lock=$RestoreArgs.Lock;MarkerSha256=$RestoreArgs.MarkerSha256;
        SafetyCheck=$RestoreArgs.SafetyCheck;Launcher=$RestoreArgs.Launcher;LauncherSha256=$RestoreArgs.LauncherSha256;
        AgentId=$RestoreArgs.AgentId;AgentImage=$RestoreArgs.AgentImage;AgentName=$RestoreArgs.AgentName;
        OldImage=$RestoreArgs.OldImage;BrokerImage=$RestoreArgs.BrokerImage;CaSha256=$RestoreArgs.CaSha256;
        DockerSha256=$RestoreArgs.DockerSha256}
    $snapshot=Get-H454OriginalRestoreState @s
    Assert-H454OriginalLiveRoute $snapshot $s.AgentId $s.DockerSha256
    $base=Get-H454CandidateImage $s.AgentImage $s.DockerSha256
    $image=Get-H454CandidateImage $CandidateImage $s.DockerSha256
    Assert-H454CandidateImage $base $image $s.AgentImage $CandidateImage
    $name='hermes-h454-broker-candidate';$label=$s.MarkerSha256.Substring(0,32).ToLowerInvariant()
    $scope=[string]$snapshot.Agent.Config.Labels.'com.hermes.scope'
    Require-H454 ($scope -cmatch '^[A-Za-z0-9_.-]{1,100}$' -and
        $null -eq $snapshot.Agent.Config.Labels.PSObject.Properties['com.hermes.h454.candidate']) 'H454_CANDIDATE_LABELS'
    $candidate=Find-H454RecoveryObject 'container' $name $s.DockerSha256
    if($null -ne $candidate){Assert-H454PreparedCandidate $candidate $snapshot.Agent $image $name $CandidateImage $s.AgentId $label $snapshot.Bridge.Id}
    if(-not $Apply){return [pscustomobject]@{Status='PREFLIGHT';Present=($null -ne $candidate)}}
    if($null -eq $candidate){
        $snapshot=Get-H454OriginalRestoreState @s
        Assert-H454OriginalLiveRoute $snapshot $s.AgentId $s.DockerSha256
        Require-H454 ($null -eq (Find-H454RecoveryObject 'container' $name $s.DockerSha256)) 'H454_CANDIDATE_COLLISION'
        $created=Invoke-H454RecoveryDocker -Arguments @('create','--pull=never','--name',$name,'--network','bridge',
            '--volumes-from',$s.AgentId,'--label',('com.hermes.scope='+$scope),'--label',('com.hermes.h454.candidate='+$label),
            '--read-only','--init','--user','65534:65534','--cap-drop','ALL','--security-opt','no-new-privileges',
            '--pids-limit','128','--memory','512m','--cpus','1','--workdir','/workspace',
            '--tmpfs','/run/brc:rw,nosuid,nodev,noexec,uid=65534,gid=65534,mode=0700,size=8m',
            '--tmpfs','/tmp:rw,nosuid,nodev,noexec,uid=65534,gid=65534,mode=0700,size=64m',$CandidateImage) -DockerSha256 $s.DockerSha256
        Require-H454 ($created.Code -eq 0 -and $created.Output.Trim() -cmatch '^[a-f0-9]{64}$') 'H454_CANDIDATE_CREATE'
        $candidate=Find-H454RecoveryObject 'container' $name $s.DockerSha256
        Require-H454 ($null -ne $candidate -and $candidate.Id -ceq $created.Output.Trim()) 'H454_CANDIDATE_CREATE'
    }
    Assert-H454PreparedCandidate $candidate $snapshot.Agent $image $name $CandidateImage $s.AgentId $label $snapshot.Bridge.Id
    $snapshot=Get-H454OriginalRestoreState @s
    Assert-H454OriginalLiveRoute $snapshot $s.AgentId $s.DockerSha256
    return [pscustomobject]@{Status='CANDIDATE_CREATED_STOPPED';CandidateId=$candidate.Id}
}
