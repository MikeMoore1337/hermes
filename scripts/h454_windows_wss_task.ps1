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
    $actionArguments='-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$path+'" -ConfigSha256 '+$ConfigSha256
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

function Assert-H454WssTaskGuardBytes([byte[]]$Original,[byte[]]$Guarded) {
    $encoding=[Text.UTF8Encoding]::new($false,$true)
    try{$before=$encoding.GetString($Original);$after=$encoding.GetString($Guarded)}
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
            if($after -cne $expected){throw 'H454_WSS_TASK_GUARD'}
        }
    }
    if($matches -ne 1){throw 'H454_WSS_TASK_GUARD'}
}

function Assert-H454WssLegacyUnchanged([object]$Expected,[string]$ExpectedSid) {
    $current=Get-ScheduledTask -TaskName 'HermesH15BRCWindows' -TaskPath '\' -ErrorAction Stop
    $actions=@($current.Actions | Where-Object {$null -ne $_})
    if([string]$current.State -cne 'Disabled' -or [string]$current.Principal.LogonType -cne 'Interactive' -or
        (Get-H454WssTaskSid ([string]$current.Principal.UserId)) -cne $ExpectedSid -or $actions.Count -ne 1 -or
        [string]$actions[0].Execute -cne [string]$Expected.Actions[0].Execute -or
        [string]$actions[0].Arguments -cne [string]$Expected.Actions[0].Arguments){throw 'H454_WSS_TASK_LEGACY'}
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
    $legacy=Get-ScheduledTask -TaskName 'HermesH15BRCWindows' -TaskPath '\' -ErrorAction Stop
    if([string]$legacy.State -cne 'Disabled' -or [string]$legacy.Principal.LogonType -cne 'Interactive' -or
        @($legacy.Actions).Count -ne 1){throw 'H454_WSS_TASK_LEGACY'}
    $legacySid=Get-H454WssTaskSid ([string]$legacy.Principal.UserId)
    if($legacySid -cne [Security.Principal.WindowsIdentity]::GetCurrent().User.Value){throw 'H454_WSS_TASK_PRINCIPAL'}
    $powershell=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
    $legacyAction=$legacy.Actions[0]
    if([IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables([string]$legacyAction.Execute)) -ine
        [IO.Path]::GetFullPath($powershell)){throw 'H454_WSS_TASK_LEGACY'}
    $match=[regex]::Match([string]$legacyAction.Arguments,'(?i)^\s*-NoProfile\s+-ExecutionPolicy\s+\S+\s+-File\s+(?:"([^"]+)"|(\S+))\s+-Mode\s+Run\s*$')
    if(-not $match.Success){throw 'H454_WSS_TASK_LEGACY'}
    $launcher=if($match.Groups[1].Success){$match.Groups[1].Value}else{$match.Groups[2].Value}
    $launcher=[IO.Path]::GetFullPath($launcher);$state=[IO.Path]::GetDirectoryName($launcher)
    if([IO.Path]::GetDirectoryName($state) -ine [Environment]::GetFolderPath('LocalApplicationData')){throw 'H454_WSS_TASK_STATE'}
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
    $expectedMarker="H454_WSS_TRANSITION_V1`noriginal=1fbf00d9b711be215ab35eaea1f6ef549cc4a0930495e3d0776a965f8c75abb6`nold=$OriginalLauncherSha256`nguard=$GuardedLauncherSha256`nbackup=$BackupName`n"
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
    if($existing.Count -ne 0){throw 'H454_WSS_TASK_EXISTS'}
    $definition=New-H454WssTaskDefinition $supervisor $ConfigSha256 ([string]$legacy.Principal.UserId) ((Get-Date).AddMinutes(5))
    Register-ScheduledTask -TaskName $name -TaskPath '\' -Action $definition.Action -Principal $definition.Principal `
        -Settings $definition.Settings -Trigger $definition.Trigger -ErrorAction Stop | Out-Null
    $created=Get-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop
    $triggers=@($created.Triggers | Where-Object {$null -ne $_})
    $actions=@($created.Actions | Where-Object {$null -ne $_})
    $owned=($actions.Count -eq 1 -and [string]$actions[0].Execute -ceq [string]$definition.Action.Execute -and
        [string]$actions[0].Arguments -ceq [string]$definition.Action.Arguments)
    try{$createdSid=Get-H454WssTaskSid ([string]$created.Principal.UserId)}catch{$createdSid=''}
    if(-not $owned -or [string]$created.State -cne 'Disabled' -or $created.Settings.Enabled -ne $false -or $createdSid -cne $legacySid -or
        [string]$created.Principal.LogonType -cne 'Interactive' -or [string]$created.Principal.RunLevel -cne 'Limited' -or
        [string]$created.Settings.ExecutionTimeLimit -cne 'PT0S' -or
        [string]$created.Settings.MultipleInstances -cne 'IgnoreNew' -or $triggers.Count -ne 1 -or
        $triggers[0].Enabled -ne $true -or $triggers[0].Repetition.Interval -cne 'PT1M' -or
        -not [string]::IsNullOrEmpty([string]$triggers[0].Repetition.Duration) -or
        -not [string]::IsNullOrEmpty([string]$triggers[0].EndBoundary)){
        if($owned -and [string]$created.State -cne 'Disabled'){Disable-ScheduledTask -TaskName $name -TaskPath '\' -ErrorAction Stop | Out-Null}
        throw 'H454_WSS_TASK_REGISTER_DRIFT'
    }
    Assert-H454RecoveryLock $state $Lock
    Assert-H454WssLegacyUnchanged $legacy $legacySid
    'H454_WSS_TASK=REGISTERED_DISABLED'
}
