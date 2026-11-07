#requires -Version 5.1
# The monitor can restage a running original but cannot start, stop or reroute it.
function New-H454BrokerMonitorDefinition([string]$GuardPath,[hashtable]$Pins,[string]$TaskUser,[datetime]$StartTime) {
    Require-H454 (-not [string]::IsNullOrWhiteSpace($GuardPath) -and [IO.Path]::IsPathRooted($GuardPath) -and
        -not $GuardPath.Contains('"') -and -not $GuardPath.Contains("`r") -and -not $GuardPath.Contains("`n") -and
        [IO.Path]::GetFileName($GuardPath) -ceq 'h454_windows_guard_operator.ps1') 'H454_MONITOR_INPUT'
    $path=[IO.Path]::GetFullPath($GuardPath);$state=[IO.Path]::GetDirectoryName($path)
    Require-H454 ([IO.Path]::GetDirectoryName($state) -ieq [Environment]::GetFolderPath('LocalApplicationData') -and
        $StartTime.Kind -ne [DateTimeKind]::Utc -and $StartTime -ge (Get-Date).AddMinutes(1) -and
        $StartTime -le (Get-Date).AddDays(1)) 'H454_MONITOR_INPUT'
    $keys=@('OriginalLauncherSha256','GuardedLauncherSha256','BackupName','TaskBackupName','TaskBackupSha256',
        'TaskSourceSha256','RecoverySourceSha256','OriginalProfileSourceSha256','RecoveryDockerSourceSha256',
        'DockerSha256','RecoveryRouteSourceSha256','NetworkGuardSourceSha256','ProxyImageId','BrokerImageId',
        'WssConfigSha256','SupervisorSha256','CaSha256','CurlSha256','RestoreSourceSha256',
        'SecureCredentialSourceSha256','BrokerCredentialSourceSha256','VerifierSourceSha256','GuardOperatorSourceSha256')
    Require-H454 ($null -ne $Pins -and $Pins.Count -eq $keys.Count) 'H454_MONITOR_PINS'
    $arguments='-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+$path+'"'
    foreach($key in $keys){
        Require-H454 ($Pins.ContainsKey($key) -and $Pins[$key] -is [string]) 'H454_MONITOR_PINS'
        $value=[string]$Pins[$key]
        if($key -ceq 'BackupName'){Require-H454 ($value -cmatch '^h454-original-launcher-[a-f0-9]{32}\.txt$') 'H454_MONITOR_PINS'}
        elseif($key -ceq 'TaskBackupName'){Require-H454 ($value -cmatch '^h454-legacy-task-[a-f0-9]{32}\.xml$') 'H454_MONITOR_PINS'}
        elseif($key -cin @('ProxyImageId','BrokerImageId')){Require-H454 ($value -cmatch '^sha256:[a-f0-9]{64}$') 'H454_MONITOR_PINS'}
        else{Require-H454 ($value -cmatch '^[A-F0-9]{64}$') 'H454_MONITOR_PINS'}
        $arguments+=' -'+$key+' '+$value
    }
    Require-H454 ($Pins.ProxyImageId -cne $Pins.BrokerImageId) 'H454_MONITOR_PINS'
    $arguments+=' -RestoreOriginal -RestageOnly -Apply -OwnerApproved'
    $sid=Get-H454WssTaskSid $TaskUser
    Require-H454 ($sid -ceq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value) 'H454_MONITOR_PRINCIPAL'
    $exe=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    $action=New-ScheduledTaskAction -Execute $exe -Argument $arguments
    $principal=New-ScheduledTaskPrincipal -UserId $TaskUser -LogonType Interactive -RunLevel Limited
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $settings.Enabled=$false
    $trigger=New-ScheduledTaskTrigger -Once -At $StartTime -RepetitionInterval (New-TimeSpan -Minutes 1)
    return [pscustomobject]@{Action=$action;Principal=$principal;Settings=$settings;Trigger=$trigger}
}

function Install-H454BrokerMonitor(
    [string]$StateDir,[IO.FileStream]$Lock,[string]$MarkerSha256,[scriptblock]$SafetyCheck,
    [hashtable]$Pins,[object[]]$SourceFiles,[switch]$Apply,[switch]$OwnerApproved
) {
    Require-H454 (-not $Apply -or $OwnerApproved) 'H454_MONITOR_APPROVAL'
    Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
    $context=Get-H454WssDisabledLegacy
    Require-H454 ($context.StateDir -ceq $StateDir) 'H454_MONITOR_STATE'
    Assert-H454PrivateAcl $StateDir
    $spec=[ordered]@{
        'h454_windows_guard_operator.ps1'='GuardOperatorSourceSha256';
        'h454_windows_wss_task.ps1'='TaskSourceSha256';
        'h454_windows_offline_recovery.ps1'='RecoverySourceSha256';
        'h454_windows_original_profile.ps1'='OriginalProfileSourceSha256';
        'h454_windows_recovery_docker.ps1'='RecoveryDockerSourceSha256';
        'h454_windows_recovery_route.ps1'='RecoveryRouteSourceSha256';
        'h454_windows_network_guard.ps1'='NetworkGuardSourceSha256';
        'h454_windows_original_restore.ps1'='RestoreSourceSha256';
        'h454_windows_secure_credential.ps1'='SecureCredentialSourceSha256';
        'h454_windows_broker_credential.ps1'='BrokerCredentialSourceSha256';
        'h454_verify_staged.cjs'='VerifierSourceSha256'
    }
    Require-H454 ($null -ne $SourceFiles -and $SourceFiles.Count -eq $spec.Count) 'H454_MONITOR_FILES'
    $expected=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($name in $spec.Keys){$null=$expected.Add([string]$name)}
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    foreach($entry in $SourceFiles){
        Require-H454 ($null -ne $entry -and $entry.Name -is [string] -and $expected.Contains($entry.Name) -and
            $seen.Add($entry.Name) -and $entry.Bytes -is [byte[]] -and $entry.Bytes.Length -gt 0 -and
            $entry.Bytes.Length -le 500000 -and $entry.Hash -ceq $Pins[$spec[$entry.Name]] -and
            (Hash-H454Bytes $entry.Bytes) -ceq $entry.Hash) 'H454_MONITOR_FILES'
        $target=Join-Path $StateDir $entry.Name
        if(Test-H454WssStateEntry $StateDir $entry.Name){Assert-H454WssTaskFile $target $entry.Hash 500000}
    }
    $guardPath=Join-Path $StateDir 'h454_windows_guard_operator.ps1'
    $definition=New-H454BrokerMonitorDefinition $guardPath $Pins ([string]$context.Task.Principal.UserId) ((Get-Date).AddMinutes(5))
    $name='HermesH454BrokerRestage'
    $existing=@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop|Where-Object {$_.TaskName -ieq $name})
    Require-H454 ($existing.Count -le 1) 'H454_MONITOR_TASK'
    if($existing.Count -eq 1){
        Require-H454 ((Test-H454WssTaskMatch $existing[0] $definition $context.Sid) -or
            (Test-H454WssTaskMatch $existing[0] $definition $context.Sid -Enabled)) 'H454_MONITOR_TASK'
    }
    if(-not $Apply){return [pscustomobject]@{Status='PREFLIGHT';TaskPresent=($existing.Count -eq 1)}}
    foreach($entry in $SourceFiles){
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $target=Join-Path $StateDir $entry.Name
        if(-not (Test-H454WssStateEntry $StateDir $entry.Name)){
            $temp=Join-Path $StateDir ('h454-monitor-'+[Guid]::NewGuid().ToString('N')+'.tmp')
            $created=$false
            try{
                $stream=[IO.File]::Open($temp,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None);$created=$true
                try{$stream.Write($entry.Bytes,0,$entry.Bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
                Assert-H454WssTaskFile $temp $entry.Hash 500000
                [IO.File]::Move($temp,$target);$created=$false
            }finally{if($created -and [IO.File]::Exists($temp)){[IO.File]::Delete($temp)}}
        }
        Assert-H454WssTaskFile $target $entry.Hash 500000
    }
    Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
    $existing=@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop|Where-Object {$_.TaskName -ieq $name})
    Require-H454 ($existing.Count -le 1) 'H454_MONITOR_TASK'
    if($existing.Count -eq 0){
        Register-ScheduledTask -TaskName $name -TaskPath '\' -Action $definition.Action -Principal $definition.Principal `
            -Settings $definition.Settings -Trigger $definition.Trigger -ErrorAction Stop|Out-Null
        $existing=@(Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop)
        if($existing.Count -eq 1 -and -not (Test-H454WssTaskMatch $existing[0] $definition $context.Sid)){
            $actions=@($existing[0].Actions|Where-Object {$null -ne $_})
            $owned=($actions.Count -eq 1 -and [string]$actions[0].Execute -ceq [string]$definition.Action.Execute -and
                [string]$actions[0].Arguments -ceq [string]$definition.Action.Arguments -and
                (Get-H454WssTaskSid ([string]$existing[0].Principal.UserId)) -ceq $context.Sid)
            if($owned -and [string]$existing[0].State -cne 'Disabled'){
                $wasRunning=([string]$existing[0].State -ceq 'Running')
                Disable-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop|Out-Null
                if($wasRunning){Stop-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop}
            }
            throw 'H454_MONITOR_TASK'
        }
    }
    Require-H454 ($existing.Count -eq 1) 'H454_MONITOR_TASK'
    if(Test-H454WssTaskMatch $existing[0] $definition $context.Sid){
        Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
        $existing=@(Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop)
        Require-H454 ($existing.Count -eq 1 -and (Test-H454WssTaskMatch $existing[0] $definition $context.Sid)) 'H454_MONITOR_TASK'
        Enable-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop|Out-Null
        $existing=@(Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop)
    }
    Require-H454 ($existing.Count -eq 1 -and (Test-H454WssTaskMatch $existing[0] $definition $context.Sid -Enabled)) 'H454_MONITOR_TASK'
    foreach($entry in $SourceFiles){Assert-H454WssTaskFile (Join-Path $StateDir $entry.Name) $entry.Hash 500000}
    Assert-H454RecoveryRouteSafety $StateDir $Lock $MarkerSha256 $SafetyCheck
    return [pscustomobject]@{Status='MONITOR_READY'}
}
