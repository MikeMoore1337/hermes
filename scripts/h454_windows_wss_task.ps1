#requires -Version 5.1
# The operator must verify protected files and the existing task before registration.
function Get-H454WssTaskSid([string]$User) {
    try{
        if($User -cmatch '^S-1-[0-9-]+$'){return ([Security.Principal.SecurityIdentifier]::new($User)).Value}
        return ([Security.Principal.NTAccount]$User).Translate([Security.Principal.SecurityIdentifier]).Value
    }catch{throw 'H454_WSS_TASK_PRINCIPAL'}
}

function New-H454WssTaskDefinition([string]$ScriptPath,[string]$ConfigSha256,[string]$TaskUser,[datetime]$StartTime) {
    if([string]::IsNullOrWhiteSpace($ScriptPath) -or -not [IO.Path]::IsPathRooted($ScriptPath) -or
        $ScriptPath.Contains('"') -or $ScriptPath.Contains("`r") -or $ScriptPath.Contains("`n") -or
        $ConfigSha256 -cnotmatch '^[A-F0-9]{64}$' -or [string]::IsNullOrWhiteSpace($TaskUser)) {
        throw 'H454_WSS_TASK_INPUT'
    }
    $path=[IO.Path]::GetFullPath($ScriptPath)
    $state=[IO.Path]::GetDirectoryName($path)
    if([IO.Path]::GetFileName($path) -cne 'h454-wss-tunnel.ps1' -or
        [IO.Path]::GetDirectoryName($state) -ine [Environment]::GetFolderPath('LocalApplicationData') -or
        $StartTime.Kind -eq [DateTimeKind]::Utc -or $StartTime -lt (Get-Date).AddMinutes(1) -or
        $StartTime -gt (Get-Date).AddDays(1)) { throw 'H454_WSS_TASK_INPUT' }
    $sid=Get-H454WssTaskSid $TaskUser
    if($sid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value){throw 'H454_WSS_TASK_PRINCIPAL'}
    $exe=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    $actionArguments='-WindowStyle Hidden -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$path+'" -ConfigSha256 '+$ConfigSha256
    $action=New-ScheduledTaskAction -Execute $exe -Argument $actionArguments
    $principal=New-ScheduledTaskPrincipal -UserId $TaskUser -LogonType Interactive -RunLevel Limited
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit ([TimeSpan]::Zero) -MultipleInstances IgnoreNew `
        -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    $settings.Enabled=$false
    $trigger=New-ScheduledTaskTrigger -Once -At $StartTime -RepetitionInterval (New-TimeSpan -Minutes 1)
    return [pscustomobject]@{Action=$action;Principal=$principal;Settings=$settings;Trigger=$trigger}
}

function Assert-H454WssTaskFile([string]$Path,[string]$Sha256,[int]$MaxBytes) {
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if($item.PSIsContainer -or $item.Length -le 0 -or $item.Length -gt $MaxBytes){throw 'H454_WSS_TASK_FILE'}
    $parent=$item
    while($null -ne $parent){
        if($parent.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'H454_WSS_TASK_REPARSE'}
        if($parent -is [IO.FileInfo]){$parent=$parent.Directory}else{$parent=$parent.Parent}
    }
    $directory=$item.Directory
    if(-not (Get-Acl -LiteralPath $directory.FullName).AreAccessRulesProtected){throw 'H454_WSS_TASK_ACL'}
    $allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
    foreach($target in @($item.FullName,$directory.FullName)){
        $acl=Get-Acl -LiteralPath $target
        if($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -notin $allowed){throw 'H454_WSS_TASK_OWNER'}
        $owner=$false
        foreach($rule in $acl.Access){
            $sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            if($sid -notin $allowed){throw 'H454_WSS_TASK_ACL'}
            if($sid -ceq $allowed[0] -and $rule.AccessControlType -eq 'Allow'){$owner=$true}
        }
        if(-not $owner){throw 'H454_WSS_TASK_ACL'}
    }
    if((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -cne $Sha256){throw 'H454_WSS_TASK_FILE'}
}

function Get-H454WssTaskGuardParts {
    $anchor=@'
    $runtimeLock = [IO.File]::Open($lockPath, [IO.FileMode]::OpenOrCreate,
        [IO.FileAccess]::ReadWrite, [IO.FileShare]::None)
    try {
'@+"`n"
    $guard=@'
    $h454PendingExists = $false; $h454Entries = 0
    foreach ($h454Entry in [IO.Directory]::EnumerateFileSystemEntries([IO.Path]::GetDirectoryName($STATE_PATH))) {
        $h454Entries++
        Require ($h454Entries -le 512) 'H454_STATE_DIRECTORY_OVERSIZE'
        if ([IO.Path]::GetFileName($h454Entry).Equals('h454-wss-transition.pending', [StringComparison]::OrdinalIgnoreCase)) {
            $h454PendingExists = $true; break
        }
    }
    Require (-not $h454PendingExists) 'H454_RECOVERY_REQUIRED'
'@+"`n"
    $anchor=$anchor.Replace("`r`n","`n")
    $guard=$guard.Replace("`r`n","`n")
    return [pscustomobject]@{Anchor=$anchor;Guard=$guard}
}

function New-H454WssGuardBytes([byte[]]$Original) {
    $encoding=[Text.UTF8Encoding]::new($false,$true)
    try{$before=$encoding.GetString($Original)}
    catch{throw 'H454_WSS_TASK_GUARD'}
    if($before.Contains([char]0) -or $before.IndexOf('h454-wss-transition.pending',[StringComparison]::OrdinalIgnoreCase) -ge 0){
        throw 'H454_WSS_TASK_GUARD'
    }
    $parts=Get-H454WssTaskGuardParts;$matches=0
    foreach($newline in @("`n","`r`n")){
        $anchor=$parts.Anchor.Replace("`n",$newline);$guard=$parts.Guard.Replace("`n",$newline)
        $first=$before.IndexOf($anchor,[StringComparison]::Ordinal)
        if($first -ge 0){
            if($before.LastIndexOf($anchor,[StringComparison]::Ordinal) -ne $first){throw 'H454_WSS_TASK_GUARD'}
            $matches++
            $expected=$before.Substring(0,$first)+$anchor+$guard+$before.Substring($first+$anchor.Length)
        }
    }
    if($matches -ne 1){throw 'H454_WSS_TASK_GUARD'}
    return ,$encoding.GetBytes($expected)
}

function Assert-H454WssTaskGuardBytes([byte[]]$Original,[byte[]]$Guarded) {
    $expected=New-H454WssGuardBytes $Original
    try{$actual64=[Convert]::ToBase64String($Guarded)}catch{throw 'H454_WSS_TASK_GUARD'}
    if([Convert]::ToBase64String($expected) -cne $actual64){throw 'H454_WSS_TASK_GUARD'}
}

function Get-H454WssMarkerText([string]$OldHash,[string]$GuardHash,[string]$BackupName) {
    if($OldHash -cnotmatch '^[A-F0-9]{64}$' -or $GuardHash -cnotmatch '^[A-F0-9]{64}$' -or
        $OldHash -ceq $GuardHash -or $BackupName -cnotmatch '^h454-original-launcher-[a-f0-9]{32}\.txt$'){
        throw 'H454_WSS_TASK_PINS'
    }
    return "H454_WSS_TRANSITION_V1`noriginal=1fbf00d9b711be215ab35eaea1f6ef549cc4a0930495e3d0776a965f8c75abb6`nold=$OldHash`nguard=$GuardHash`nbackup=$BackupName`n"
}

function Assert-H454WssLegacyUnchanged([object]$Expected,[string]$ExpectedSid) {
    $current=Get-ScheduledTask -TaskName 'HermesH15BRCWindows' -TaskPath '\' -ErrorAction Stop
    $actions=@($current.Actions | Where-Object {$null -ne $_})
    if([string]$current.State -cne 'Disabled' -or [string]$current.Principal.LogonType -cne 'Interactive' -or
        (Get-H454WssTaskSid ([string]$current.Principal.UserId)) -cne $ExpectedSid -or $actions.Count -ne 1 -or
        [string]$actions[0].Execute -cne [string]$Expected.Actions[0].Execute -or
        [string]$actions[0].Arguments -cne [string]$Expected.Actions[0].Arguments){throw 'H454_WSS_TASK_LEGACY'}
}

function Get-H454WssDisabledLegacy {
    $legacy=Get-ScheduledTask -TaskName 'HermesH15BRCWindows' -TaskPath '\' -ErrorAction Stop
    if([string]$legacy.State -cne 'Disabled' -or [string]$legacy.Principal.LogonType -cne 'Interactive' -or
        @($legacy.Actions).Count -ne 1){throw 'H454_WSS_TASK_LEGACY'}
    $sid=Get-H454WssTaskSid ([string]$legacy.Principal.UserId)
    if($sid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value){throw 'H454_WSS_TASK_PRINCIPAL'}
    $powershell=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    $action=$legacy.Actions[0]
    if([IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables([string]$action.Execute)) -ine
        [IO.Path]::GetFullPath($powershell)){throw 'H454_WSS_TASK_LEGACY'}
    $match=[regex]::Match([string]$action.Arguments,'(?i)^\s*-NoProfile\s+-ExecutionPolicy\s+\S+\s+-File\s+(?:"([^"]+)"|(\S+))\s+-Mode\s+Run\s*$')
    if(-not $match.Success){throw 'H454_WSS_TASK_LEGACY'}
    $launcher=if($match.Groups[1].Success){$match.Groups[1].Value}else{$match.Groups[2].Value}
    $launcher=[IO.Path]::GetFullPath($launcher);$state=[IO.Path]::GetDirectoryName($launcher)
    if([IO.Path]::GetDirectoryName($state) -ine [Environment]::GetFolderPath('LocalApplicationData')){throw 'H454_WSS_TASK_STATE'}
    return [pscustomobject]@{Task=$legacy;Sid=$sid;PowerShell=$powershell;Launcher=$launcher;StateDir=$state}
}

function Assert-H454WssOriginalStopped {
    $id='1fbf00d9b711be215ab35eaea1f6ef549cc4a0930495e3d0776a965f8c75abb6'
    $image='sha256:0c95960c02e0dbe00a6a11ee6253d4055e4a7abf7671404b3f876dfdb95bd5d8'
    $container=Get-H454Container $id
    if($container.Id -cne $id -or $container.Image -cne $image -or $container.Name -cne '/hermes-h15-windows-permanent' -or
        $container.State.Running -isnot [bool] -or $container.State.Running -or $container.State.Status -cne 'exited' -or
        $container.State.Paused -isnot [bool] -or $container.State.Paused -or
        $container.State.Restarting -isnot [bool] -or $container.State.Restarting -or
        $container.State.Dead -isnot [bool] -or $container.State.Dead -or
        $container.HostConfig.RestartPolicy.Name -cne 'no'){throw 'H454_WSS_GUARD_ORIGINAL'}
    foreach($port in @(38180,38184)){
        if(@(Get-NetTCPConnection -LocalPort $port -State Listen -ErrorAction SilentlyContinue).Count -ne 0){throw 'H454_WSS_GUARD_LISTENER'}
    }
}

function Test-H454WssStateEntry([string]$State,[string]$Name) {
    $entries=0;$found=$false
    foreach($entry in [IO.Directory]::EnumerateFileSystemEntries($State)){
        $entries++;if($entries -gt 512){throw 'H454_WSS_GUARD_STATE_SIZE'}
        if([IO.Path]::GetFileName($entry).Equals($Name,[StringComparison]::OrdinalIgnoreCase)){$found=$true}
    }
    return $found
}

function Install-H454WssGuard(
    [string]$OriginalLauncherSha256,[string]$GuardedLauncherSha256,[string]$BackupName,
    [IO.FileStream]$Lock,[switch]$Apply,[switch]$OwnerApproved
) {
    if($Apply -and -not $OwnerApproved){throw 'H454_WSS_TASK_APPROVAL'}
    $markerText=Get-H454WssMarkerText $OriginalLauncherSha256 $GuardedLauncherSha256 $BackupName
    $utf8=[Text.UTF8Encoding]::new($false)
    $markerBytes=$utf8.GetBytes($markerText);$markerHash=Hash-H454Bytes $markerBytes
    $context=Get-H454WssDisabledLegacy
    $state=$context.StateDir;$launcher=$context.Launcher;$backup=Join-Path $state $BackupName
    $marker=Join-Path $state 'h454-wss-transition.pending'
    Assert-H454RecoveryLock $state $Lock
    Assert-H454WssOriginalStopped
    $markerFound=Test-H454WssStateEntry $state 'h454-wss-transition.pending'
    $backupFound=Test-H454WssStateEntry $state $BackupName
    if($markerFound){
        Assert-H454WssTaskFile $marker $markerHash 4096
        if([IO.File]::ReadAllText($marker) -cne $markerText){throw 'H454_WSS_TASK_MARKER'}
    }
    $current=(Get-FileHash -LiteralPath $launcher -Algorithm SHA256 -ErrorAction Stop).Hash
    if($current -ceq $GuardedLauncherSha256){
        if(-not $markerFound){throw 'H454_WSS_GUARD_MARKER'}
        Assert-H454WssTaskFile $launcher $GuardedLauncherSha256 200000
        Assert-H454WssTaskFile $backup $OriginalLauncherSha256 200000
        Assert-H454WssTaskGuardBytes ([IO.File]::ReadAllBytes($backup)) ([IO.File]::ReadAllBytes($launcher))
        return [pscustomobject]@{Status='ALREADY_INSTALLED';BackupName=$BackupName;MarkerSha256=$markerHash}
    }
    if($current -cne $OriginalLauncherSha256 -or ($backupFound -and -not $markerFound)){throw 'H454_WSS_GUARD_DRIFT'}
    Assert-H454WssTaskFile $launcher $OriginalLauncherSha256 200000
    $original=[IO.File]::ReadAllBytes($launcher)
    $guarded=New-H454WssGuardBytes $original
    if((Hash-H454Bytes $guarded) -cne $GuardedLauncherSha256){throw 'H454_WSS_GUARD_DRIFT'}
    if($backupFound){Assert-H454WssTaskFile $backup $OriginalLauncherSha256 200000}
    if(-not $Apply){return [pscustomobject]@{Status='PREFLIGHT';BackupName=$BackupName;MarkerSha256=$markerHash}}
    Assert-H454RecoveryLock $state $Lock
    Assert-H454WssLegacyUnchanged $context.Task $context.Sid
    Assert-H454WssOriginalStopped
    $pending=Join-Path $state ('h454-guard-'+[Guid]::NewGuid().ToString('N')+'.new')
    $stream=[IO.File]::Open($pending,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($guarded,0,$guarded.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    Assert-H454WssTaskFile $pending $GuardedLauncherSha256 200000
    if(-not $markerFound){$null=New-H454TransitionMarker $state $markerBytes $Lock}
    if(-not $backupFound){
        $stream=[IO.File]::Open($backup,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
        try{$stream.Write($original,0,$original.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    }
    Assert-H454RecoveryLock $state $Lock
    Assert-H454WssLegacyUnchanged $context.Task $context.Sid
    Assert-H454WssOriginalStopped
    Assert-H454WssTaskFile $marker $markerHash 4096
    Assert-H454WssTaskFile $launcher $OriginalLauncherSha256 200000
    Assert-H454WssTaskFile $backup $OriginalLauncherSha256 200000
    [IO.File]::Replace($pending,$launcher,[System.Management.Automation.Language.NullString]::Value)
    Assert-H454RecoveryLock $state $Lock
    Assert-H454WssLegacyUnchanged $context.Task $context.Sid
    Assert-H454WssOriginalStopped
    Assert-H454WssTaskFile $launcher $GuardedLauncherSha256 200000
    Assert-H454WssTaskFile $backup $OriginalLauncherSha256 200000
    Assert-H454WssTaskFile $marker $markerHash 4096
    Assert-H454WssTaskGuardBytes ([IO.File]::ReadAllBytes($backup)) ([IO.File]::ReadAllBytes($launcher))
    return [pscustomobject]@{Status='INSTALLED_PENDING';BackupName=$BackupName;MarkerSha256=$markerHash}
}

function Test-H454WssTaskMatch([object]$Task,[object]$Definition,[string]$ExpectedSid,[switch]$Enabled) {
    if($null -eq $Task){return $false}
    $actions=@($Task.Actions | Where-Object {$null -ne $_})
    $triggers=@($Task.Triggers | Where-Object {$null -ne $_})
    try{$sid=Get-H454WssTaskSid ([string]$Task.Principal.UserId)}catch{return $false}
    $stateOk=if($Enabled){$Task.Settings.Enabled -eq $true -and [string]$Task.State -cin @('Ready','Queued','Running')}
        else{$Task.Settings.Enabled -eq $false -and [string]$Task.State -ceq 'Disabled'}
    if(-not $stateOk -or $sid -cne $ExpectedSid -or
        [string]$Task.Principal.LogonType -cne 'Interactive' -or [string]$Task.Principal.RunLevel -cne 'Limited' -or
        $actions.Count -ne 1 -or [string]$actions[0].Execute -cne [string]$Definition.Action.Execute -or
        [string]$actions[0].Arguments -cne [string]$Definition.Action.Arguments -or
        [string]$Task.Settings.ExecutionTimeLimit -cne 'PT0S' -or [string]$Task.Settings.MultipleInstances -cne 'IgnoreNew' -or
        $triggers.Count -ne 1 -or $triggers[0].Enabled -ne $true -or $triggers[0].Repetition.Interval -cne 'PT1M' -or
        -not [string]::IsNullOrEmpty([string]$triggers[0].Repetition.Duration) -or
        -not [string]::IsNullOrEmpty([string]$triggers[0].EndBoundary)){return $false}
    try{$start=[datetime]::Parse([string]$triggers[0].StartBoundary,[Globalization.CultureInfo]::InvariantCulture)}catch{return $false}
    return ($start -le (Get-Date).AddMinutes(10))
}

function Register-H454WssTaskDisabled(
    [string]$OriginalLauncherSha256,[string]$GuardedLauncherSha256,[string]$MarkerSha256,
    [string]$SupervisorSha256,[string]$ConfigSha256,[string]$BackupName,[IO.FileStream]$Lock,[switch]$OwnerApproved
) {
    if(-not $OwnerApproved){throw 'H454_WSS_TASK_APPROVAL'}
    foreach($hash in @($OriginalLauncherSha256,$GuardedLauncherSha256,$MarkerSha256,$SupervisorSha256,$ConfigSha256)){
        if($hash -cnotmatch '^[A-F0-9]{64}$'){throw 'H454_WSS_TASK_PINS'}
    }
    if($OriginalLauncherSha256 -ceq $GuardedLauncherSha256 -or
        $BackupName -cnotmatch '^h454-original-launcher-[a-f0-9]{32}\.txt$'){throw 'H454_WSS_TASK_PINS'}
    $context=Get-H454WssDisabledLegacy
    $legacy=$context.Task;$legacySid=$context.Sid;$powershell=$context.PowerShell;$launcher=$context.Launcher;$state=$context.StateDir
    Assert-H454RecoveryLock $state $Lock
    $backup=Join-Path $state $BackupName
    $marker=Join-Path $state 'h454-wss-transition.pending'
    $supervisor=Join-Path $state 'h454-wss-tunnel.ps1'
    $config=Join-Path $state 'h454-wss-tunnel-config.json'
    Assert-H454WssTaskFile $launcher $GuardedLauncherSha256 200000
    Assert-H454WssTaskFile $backup $OriginalLauncherSha256 200000
    Assert-H454WssTaskFile $marker $MarkerSha256 4096
    Assert-H454WssTaskFile $supervisor $SupervisorSha256 65536
    Assert-H454WssTaskFile $config $ConfigSha256 8192
    $expectedMarker=Get-H454WssMarkerText $OriginalLauncherSha256 $GuardedLauncherSha256 $BackupName
    if([IO.File]::ReadAllText($marker) -cne $expectedMarker){throw 'H454_WSS_TASK_MARKER'}
    Assert-H454WssTaskGuardBytes ([IO.File]::ReadAllBytes($backup)) ([IO.File]::ReadAllBytes($launcher))
    $settings=[Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($config)) | ConvertFrom-Json -ErrorAction Stop
    if($settings.launcherSha256 -cne $GuardedLauncherSha256){throw 'H454_WSS_TASK_CONFIG'}
    $prior=$ErrorActionPreference;$ErrorActionPreference='SilentlyContinue';$global:LASTEXITCODE=-1
    try{$output=@(& $powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $supervisor -ConfigSha256 $ConfigSha256 -Preflight 2>$null);$code=$LASTEXITCODE}
    catch{$output=@();$code=-1}finally{$ErrorActionPreference=$prior}
    if($code -ne 0 -or $output.Count -ne 1 -or $output[0] -cne 'H454_WSS_TUNNEL_PREFLIGHT=PASS'){throw 'H454_WSS_TASK_PREFLIGHT'}
    foreach($pair in @(@($launcher,$GuardedLauncherSha256,200000),@($backup,$OriginalLauncherSha256,200000),
        @($marker,$MarkerSha256,4096),@($supervisor,$SupervisorSha256,65536),@($config,$ConfigSha256,8192))){
        Assert-H454WssTaskFile $pair[0] $pair[1] $pair[2]
    }
    Assert-H454RecoveryLock $state $Lock
    Assert-H454WssLegacyUnchanged $legacy $legacySid
    $name='HermesH454WssTunnel'
    $existing=@(Get-ScheduledTask -TaskPath '\' -ErrorAction Stop | Where-Object {$_.TaskName -ieq $name})
    $definition=New-H454WssTaskDefinition $supervisor $ConfigSha256 ([string]$legacy.Principal.UserId) ((Get-Date).AddMinutes(5))
    if($existing.Count -gt 0){
        if($existing.Count -ne 1 -or -not (Test-H454WssTaskMatch $existing[0] $definition $legacySid)){throw 'H454_WSS_TASK_EXISTS'}
        Assert-H454RecoveryLock $state $Lock
        Assert-H454WssLegacyUnchanged $legacy $legacySid
        return 'H454_WSS_TASK=ALREADY_REGISTERED_DISABLED'
    }
    Register-ScheduledTask -TaskName $name -TaskPath '\' -Action $definition.Action -Principal $definition.Principal `
        -Settings $definition.Settings -Trigger $definition.Trigger -ErrorAction Stop | Out-Null
    $created=Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop
    $actions=@($created.Actions | Where-Object {$null -ne $_})
    $owned=($actions.Count -eq 1 -and [string]$actions[0].Execute -ceq [string]$definition.Action.Execute -and
        [string]$actions[0].Arguments -ceq [string]$definition.Action.Arguments)
    if(-not (Test-H454WssTaskMatch $created $definition $legacySid)){
        if($owned -and [string]$created.State -cne 'Disabled'){Disable-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop | Out-Null}
        throw 'H454_WSS_TASK_REGISTER_DRIFT'
    }
    Assert-H454RecoveryLock $state $Lock
    Assert-H454WssLegacyUnchanged $legacy $legacySid
    'H454_WSS_TASK=REGISTERED_DISABLED'
}

function Start-H454WssTask(
    [string]$OriginalLauncherSha256,[string]$GuardedLauncherSha256,[string]$MarkerSha256,
    [string]$SupervisorSha256,[string]$ConfigSha256,[string]$BackupName,[IO.FileStream]$Lock,[switch]$OwnerApproved
) {
    if(-not $OwnerApproved){throw 'H454_WSS_TASK_APPROVAL'}
    $context=Get-H454WssDisabledLegacy
    $state=$context.StateDir;$name='HermesH454WssTunnel'
    Assert-H454RecoveryLock $state $Lock
    Assert-H454WssOriginalStopped
    $supervisor=Join-Path $state 'h454-wss-tunnel.ps1'
    $definition=New-H454WssTaskDefinition $supervisor $ConfigSha256 ([string]$context.Task.Principal.UserId) ((Get-Date).AddMinutes(5))
    $existing=@(Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop)
    if($existing.Count -ne 1 -or -not (Test-H454WssTaskMatch $existing[0] $definition $context.Sid)){throw 'H454_WSS_TASK_EXISTS'}
    $verified=@(Register-H454WssTaskDisabled $OriginalLauncherSha256 $GuardedLauncherSha256 $MarkerSha256 `
        $SupervisorSha256 $ConfigSha256 $BackupName $Lock -OwnerApproved)
    if($verified.Count -ne 1 -or $verified[0] -cne 'H454_WSS_TASK=ALREADY_REGISTERED_DISABLED'){throw 'H454_WSS_TASK_EXISTS'}
    Assert-H454RecoveryLock $state $Lock
    Assert-H454WssLegacyUnchanged $context.Task $context.Sid
    Assert-H454WssOriginalStopped
    try {
        Enable-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop | Out-Null
        $current=Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop
        if(-not (Test-H454WssTaskMatch $current $definition $context.Sid -Enabled)){throw 'H454_WSS_TASK_ACTIVATION'}
        Start-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop
        $current=Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop
        if(-not (Test-H454WssTaskMatch $current $definition $context.Sid -Enabled)){throw 'H454_WSS_TASK_ACTIVATION'}
        Assert-H454RecoveryLock $state $Lock
        Assert-H454WssLegacyUnchanged $context.Task $context.Sid
        return 'H454_WSS_TASK=START_REQUESTED'
    }catch{
        $current=Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop
        if(Test-H454WssTaskMatch $current $definition $context.Sid -Enabled){
            Disable-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop | Out-Null
            Stop-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop
        }elseif(-not (Test-H454WssTaskMatch $current $definition $context.Sid)){
            throw 'H454_WSS_TASK_ACTIVATION_AMBIGUOUS'
        }
        throw 'H454_WSS_TASK_ACTIVATION'
    }
}
