#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$Source,[Parameter(Mandatory=$true)][string]$RecoverySource,
      [Parameter(Mandatory=$true)][string]$FilesSource,[Parameter(Mandatory=$true)][string]$SupervisorSource,
      [string]$FixtureTaskName='HermesH454WssTunnel',[switch]$RealScheduler)
$ErrorActionPreference='Stop'
. $Source
. $RecoverySource
. $FilesSource
Import-Module ScheduledTasks -ErrorAction Stop
Import-Module NetTCPIP -ErrorAction Stop
function Require-H454([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
Require-H454 (@(ScheduledTasks\Get-ScheduledTask -TaskName 'HermesH454WssTunnel' -TaskPath '\' -ErrorAction SilentlyContinue).Count -eq 0) 'FIXTURE_REAL_TASK_EXISTS'
Require-H454 ((-not $RealScheduler -and $FixtureTaskName -ceq 'HermesH454WssTunnel') -or
    ($RealScheduler -and $FixtureTaskName -cmatch '^H454TaskRegistrationFixture-[a-f0-9]{32}$')) 'FIXTURE_TASK_NAME'
function Hash-H454Bytes([byte[]]$Bytes){
    $hash=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-','')}finally{$hash.Dispose()}
}
$local=[Environment]::GetFolderPath('LocalApplicationData')
$state=Join-Path $local ('H454TaskFixture-'+[Guid]::NewGuid().ToString('N'))
Require-H454 ([IO.Path]::GetDirectoryName($state) -ceq $local -and -not (Test-Path -LiteralPath $state)) 'FIXTURE_PATH'
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetOwner($owner);$acl.SetAccessRuleProtection($true,$false)
foreach($sid in @($owner,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))){
    $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($rule)
}
[IO.Directory]::CreateDirectory($state,$acl)|Out-Null
function Assert-H454PrivateAcl([string]$Path){
    $item=Get-Item -LiteralPath $Path -Force
    Require-H454 ($item.FullName -ceq $state -or [IO.Path]::GetDirectoryName($item.FullName) -ceq $state) 'FIXTURE_SCOPE'
    Require-H454 (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'FIXTURE_REPARSE'
}
$files=[Collections.Generic.List[string]]::new();$lock=$null
function New-FixtureFile([string]$Name,[byte[]]$Bytes){
    $path=Join-Path $state $Name
    Require-H454 (-not (Test-Path -LiteralPath $path)) 'FIXTURE_FILE'
    $stream=[IO.File]::Open($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    $files.Add($path);return $path
}
$utf8=[Text.UTF8Encoding]::new($false)
$user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$powershell=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
$script:createdTask=$null;$script:registrations=0;$script:drift=$false;$script:disables=0;$script:legacyDrift=$false;$script:legacyReads=0
function Get-NetTCPConnection {[CmdletBinding()]param([int]$LocalPort,[string]$State)}
function Get-H454Container([string]$Id){
    return [pscustomobject]@{Id=$Id;Image='sha256:0c95960c02e0dbe00a6a11ee6253d4055e4a7abf7671404b3f876dfdb95bd5d8';
        Name='/hermes-h15-windows-permanent';State=[pscustomobject]@{Running=$false;Status='exited';Paused=$false;Restarting=$false;Dead=$false};
        HostConfig=[pscustomobject]@{RestartPolicy=[pscustomobject]@{Name='no'}}}
}
function Assert-H454WssNode([string]$ExpectedSha256){Require-H454 ($ExpectedSha256 -ceq ('D'*64)) 'FIXTURE_NODE'}
function Get-ScheduledTask {
    [CmdletBinding()]param([string]$TaskName,[string]$TaskPath)
    if($TaskName -ceq 'HermesH15BRCWindows'){
        $script:legacyReads++
        if($script:legacyDrift -and $script:legacyReads -gt 1){
            return [pscustomobject]@{TaskName='HermesH15BRCWindows';State='Disabled';Principal=$script:legacy.Principal;
                Actions=@([pscustomobject]@{Execute=$script:legacy.Actions[0].Execute;Arguments='changed'})}
        }
        return $script:legacy
    }
    if($TaskName -ceq $FixtureTaskName){
        if($RealScheduler){return ScheduledTasks\Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction SilentlyContinue}
        return $script:createdTask
    }
    if([string]::IsNullOrEmpty($TaskName)){
        if($RealScheduler){return ScheduledTasks\Get-ScheduledTask -TaskPath $TaskPath -ErrorAction Stop}
        return @($script:legacy,$script:createdTask) | Where-Object {$null -ne $_}
    }
    throw 'FIXTURE_UNEXPECTED_TASK'
}
function Register-ScheduledTask {
    [CmdletBinding()]param([string]$TaskName,[string]$TaskPath,$Action,$Principal,$Settings,$Trigger)
    Require-H454 ($TaskName -ceq $FixtureTaskName -and -not $Settings.Enabled -and $null -eq $script:createdTask) 'FIXTURE_REGISTER'
    $script:registrations++
    $script:registeredAction=$Action
    if($RealScheduler){
        ScheduledTasks\Register-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -Action $Action -Principal $Principal -Settings $Settings -Trigger $Trigger -ErrorAction Stop | Out-Null
        $script:createdTask=ScheduledTasks\Get-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop
        return $script:createdTask
    }
    $normalizedPrincipal=[pscustomobject]@{UserId=$owner.Value;LogonType=[string]$Principal.LogonType;RunLevel=[string]$Principal.RunLevel}
    $stateValue=if($script:drift){'Ready'}else{'Disabled'}
    $script:createdTask=[pscustomobject]@{TaskName=$TaskName;State=$stateValue;Actions=@($Action);
        Principal=$normalizedPrincipal;Settings=$Settings;Triggers=@($Trigger)}
    return $script:createdTask
}
function Disable-ScheduledTask {
    [CmdletBinding()]param([string]$TaskName,[string]$TaskPath)
    Require-H454 ($TaskName -ceq $FixtureTaskName -and $null -ne $script:createdTask) 'FIXTURE_DISABLE'
    if($RealScheduler){ScheduledTasks\Disable-ScheduledTask -TaskName $TaskName -TaskPath $TaskPath -ErrorAction Stop | Out-Null;return}
    $script:disables++;$script:createdTask.State='Disabled'
}
try{
    $parts=Get-H454WssTaskGuardParts
    $oldText=@'
$HOST_ADDR = 'relay.example.test'
$RELAY = '172.29.1.2:3000'
$SSH_PORT = 2222
$TUNNEL_TARGET = "fixture@$HOST_ADDR"
'@+"`n"+$parts.Anchor+"    # fixture`n"
    $guardedText=$oldText.Replace($parts.Anchor,$parts.Anchor+$parts.Guard)
    $backupName='h454-original-launcher-'+[Guid]::NewGuid().ToString('N')+'.txt'
    $backup=New-FixtureFile $backupName ($utf8.GetBytes($oldText))
    $launcher=New-FixtureFile 'Hermes-H15-Windows-Permanent.ps1' ($utf8.GetBytes($guardedText))
    $oldHash=(Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash
    $guardHash=(Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash
    $moduleBytes=$utf8.GetBytes('fixture-module');$moduleHash=Hash-H454Bytes $moduleBytes
    $identityBytes=$utf8.GetBytes(('$script:h454ModuleHash = '''+$moduleHash+"'`n"));$identityHash=Hash-H454Bytes $identityBytes
    $caBytes=$utf8.GetBytes("-----BEGIN CERTIFICATE-----`nZmFrZQ==`n-----END CERTIFICATE-----`n");$caHash=Hash-H454Bytes $caBytes
    $publicBytes=$utf8.GetBytes(('ssh-ed25519 '+('A'*68)+" hermes-h454-wss`n"))
    $public=New-FixtureFile 'wss-ssh-identity.pub' $publicBytes;$publicHash=Hash-H454Bytes $publicBytes
    $supervisorBytes=[IO.File]::ReadAllBytes($SupervisorSource);$supervisorHash=Hash-H454Bytes $supervisorBytes
    $supervisor=Join-Path $state 'h454-wss-tunnel.ps1'
    $configPath=Join-Path $state 'h454-wss-tunnel-config.json'
    foreach($name in @('h454-wss-identity.ps1','h454_windows_wss_identity.mjs','wss-relay-ca.pem','h454-wss-tunnel.ps1','h454-wss-tunnel-config.json')){
        $files.Add((Join-Path $state $name))
    }
    $markerText=Get-H454WssMarkerText $oldHash $guardHash $backupName
    $marker=New-FixtureFile 'h454-wss-transition.pending' ($utf8.GetBytes($markerText))
    $markerHash=(Get-FileHash $marker).Hash
    $action=[pscustomobject]@{Execute=$powershell;Arguments=('-NoProfile -ExecutionPolicy Bypass -File "'+$launcher+'" -Mode Run')}
    $script:legacy=[pscustomobject]@{TaskName='HermesH15BRCWindows';State='Disabled';Actions=@($action);
        Principal=[pscustomobject]@{UserId=$user;LogonType='Interactive'}}
    $lock=Open-H454RecoveryLock $state;$files.Add((Join-Path $state 'runtime.lock'))
    Require-H454 ((Get-Command Register-ScheduledTask).ScriptBlock.ToString().Contains('FIXTURE_REGISTER') -and
        (Get-Command Get-ScheduledTask).ScriptBlock.ToString().Contains('FIXTURE_UNEXPECTED_TASK') -and
        (Get-Command Assert-H454WssNode).ScriptBlock.ToString().Contains('FIXTURE_NODE')) 'FIXTURE_MOCK_SCOPE'
    $nodeHash='D'*64
    foreach($bom in @($false,$true)){
        $sourceBytes=$utf8.GetBytes($oldText)
        if($bom){$sourceBytes=[byte[]](@(0xef,0xbb,0xbf)+@($sourceBytes))}
        $sourceGuard=New-H454WssGuardBytes $sourceBytes
        $generated=New-H454WssConfigBytes $sourceBytes $sourceGuard $caHash $identityHash $nodeHash $publicHash
        $parsed=[Text.Encoding]::UTF8.GetString($generated) | ConvertFrom-Json
        Require-H454 ($parsed.sshHost -ceq 'relay.example.test' -and $parsed.sshUser -ceq 'fixture' -and
            $parsed.sshPort -eq 2222 -and $parsed.relayAddress -ceq '172.29.1.2') 'FIXTURE_CONFIG'
    }
    $badSource=$utf8.GetBytes($oldText.Replace('172.29.1.2:3000','8.8.8.8:3000'))
    $badSourceGuard=New-H454WssGuardBytes $badSource;$refused=$false
    try{$null=New-H454WssConfigBytes $badSource $badSourceGuard $caHash $identityHash $nodeHash $publicHash}catch{$refused=$_.Exception.Message -ceq 'H454_WSS_FILES_SOURCE'}
    Require-H454 $refused 'FIXTURE_CONFIG_ADDRESS'
    $script:legacyReads=0;$refused=$false
    try{$null=Install-H454WssFiles $supervisorBytes $identityBytes $moduleBytes $caBytes $supervisorHash $identityHash $moduleHash $caHash `
        $nodeHash $publicHash $oldHash $guardHash $markerHash '..\outside.txt' $lock -Apply -OwnerApproved}catch{$refused=$_.Exception.Message -ceq 'H454_WSS_TASK_PINS'}
    Require-H454 ($refused -and $script:legacyReads -eq 0 -and -not (Test-Path -LiteralPath $supervisor)) 'FIXTURE_BACKUP_PATH'
    $plan=Install-H454WssFiles $supervisorBytes $identityBytes $moduleBytes $caBytes $supervisorHash $identityHash $moduleHash $caHash `
        $nodeHash $publicHash $oldHash $guardHash $markerHash $backupName $lock
    Require-H454 ($plan.Status -ceq 'PREFLIGHT' -and -not (Test-Path -LiteralPath $supervisor)) 'FIXTURE_FILES_PREFLIGHT'
    $refused=$false
    try{$null=Install-H454WssFiles $supervisorBytes $identityBytes $moduleBytes $caBytes $supervisorHash $identityHash $moduleHash $caHash `
        $nodeHash $publicHash $oldHash $guardHash $markerHash $backupName $lock -Apply}catch{$refused=$_.Exception.Message -ceq 'H454_WSS_TASK_APPROVAL'}
    Require-H454 ($refused -and -not (Test-Path -LiteralPath $supervisor)) 'FIXTURE_FILES_APPROVAL'
    $collision=Join-Path $state 'wss-relay-ca.pem';[IO.File]::WriteAllText($collision,'occupied',$utf8)
    $refused=$false
    try{$null=Install-H454WssFiles $supervisorBytes $identityBytes $moduleBytes $caBytes $supervisorHash $identityHash $moduleHash $caHash `
        $nodeHash $publicHash $oldHash $guardHash $markerHash $backupName $lock -Apply -OwnerApproved}catch{$refused=$_.Exception.Message -ceq 'H454_WSS_TASK_FILE'}
    Require-H454 ($refused -and [IO.File]::ReadAllText($collision) -ceq 'occupied' -and -not (Test-Path -LiteralPath $supervisor)) 'FIXTURE_FILES_COLLISION'
    [IO.File]::Delete($collision)
    $junctionTarget=Join-Path $state 'junction-target'
    [IO.Directory]::CreateDirectory($junctionTarget)|Out-Null
    try{
        $null=New-Item -ItemType Junction -Path $collision -Target $junctionTarget
        $refused=$false
        try{$null=Install-H454WssFiles $supervisorBytes $identityBytes $moduleBytes $caBytes $supervisorHash $identityHash $moduleHash $caHash `
            $nodeHash $publicHash $oldHash $guardHash $markerHash $backupName $lock -Apply -OwnerApproved}catch{$refused=$_.Exception.Message -ceq 'H454_WSS_TASK_FILE'}
        Require-H454 ($refused -and -not (Test-Path -LiteralPath $supervisor)) 'FIXTURE_FILES_JUNCTION'
    }finally{
        if(Test-Path -LiteralPath $collision){
            $junction=Get-Item -LiteralPath $collision -Force
            Require-H454 ($junction.Attributes -band [IO.FileAttributes]::ReparsePoint) 'FIXTURE_JUNCTION_CLEANUP'
            [IO.Directory]::Delete($collision,$false)
        }
        if(Test-Path -LiteralPath $junctionTarget){[IO.Directory]::Delete($junctionTarget,$false)}
    }
    $ready=Install-H454WssFiles $supervisorBytes $identityBytes $moduleBytes $caBytes $supervisorHash $identityHash $moduleHash $caHash `
        $nodeHash $publicHash $oldHash $guardHash $markerHash $backupName $lock -Apply -OwnerApproved
    Require-H454 ($ready.Status -ceq 'FILES_READY' -and $ready.ConfigSha256 -ceq $plan.ConfigSha256) 'FIXTURE_FILES_INSTALL'
    $againFiles=Install-H454WssFiles $supervisorBytes $identityBytes $moduleBytes $caBytes $supervisorHash $identityHash $moduleHash $caHash `
        $nodeHash $publicHash $oldHash $guardHash $markerHash $backupName $lock -Apply -OwnerApproved
    Require-H454 ($againFiles.Status -ceq 'FILES_READY' -and $againFiles.ConfigSha256 -ceq $ready.ConfigSha256) 'FIXTURE_FILES_REPEAT'
    [IO.File]::Delete((Join-Path $state 'h454_windows_wss_identity.mjs'))
    $resumedFiles=Install-H454WssFiles $supervisorBytes $identityBytes $moduleBytes $caBytes $supervisorHash $identityHash $moduleHash $caHash `
        $nodeHash $publicHash $oldHash $guardHash $markerHash $backupName $lock -Apply -OwnerApproved
    Require-H454 ($resumedFiles.Status -ceq 'FILES_READY' -and $resumedFiles.ConfigSha256 -ceq $ready.ConfigSha256) 'FIXTURE_FILES_RESUME'
    $configHash=$ready.ConfigSha256
    try{$result=@(Register-H454WssTaskDisabled $oldHash $guardHash $markerHash $supervisorHash $configHash $backupName $lock -OwnerApproved)}
    catch{
        if($null -ne $script:createdTask){
            $created=$script:createdTask;$triggers=@($created.Triggers | Where-Object {$null -ne $_});$actions=@($created.Actions | Where-Object {$null -ne $_})
            'FIXTURE_ACTION_COUNT='+$actions.Count;'FIXTURE_TRIGGER_COUNT='+$triggers.Count
            if($actions.Count -eq 1){'FIXTURE_ACTION_EXEC_MATCH='+[string]([string]$actions[0].Execute -ceq [string]$script:registeredAction.Execute);
                'FIXTURE_ACTION_ARGS_MATCH='+[string]([string]$actions[0].Arguments -ceq [string]$script:registeredAction.Arguments)}
            'FIXTURE_STATE='+[string]$created.State;'FIXTURE_PRINCIPAL_MATCH='+[string]([string]$created.Principal.UserId -ceq $user)
            'FIXTURE_LOGON='+[string]$created.Principal.LogonType;'FIXTURE_LIMIT='+[string]$created.Settings.ExecutionTimeLimit
            'FIXTURE_MULTIPLE='+[string]$created.Settings.MultipleInstances
            if($triggers.Count -eq 1){'FIXTURE_INTERVAL='+[string]$triggers[0].Repetition.Interval;
                'FIXTURE_DURATION_EMPTY='+[string]([string]::IsNullOrEmpty([string]$triggers[0].Repetition.Duration));
                'FIXTURE_END_EMPTY='+[string]([string]::IsNullOrEmpty([string]$triggers[0].EndBoundary))}
        }
        throw
    }
    Require-H454 ($result.Count -eq 1 -and $result[0] -ceq 'H454_WSS_TASK=REGISTERED_DISABLED' -and $script:registrations -eq 1) 'FIXTURE_SUCCESS'
    $again=@(Register-H454WssTaskDisabled $oldHash $guardHash $markerHash $supervisorHash $configHash $backupName $lock -OwnerApproved)
    Require-H454 ($again.Count -eq 1 -and $again[0] -ceq 'H454_WSS_TASK=ALREADY_REGISTERED_DISABLED' -and
        $script:registrations -eq 1) 'FIXTURE_IDEMPOTENT'
    if(-not $RealScheduler){
    $script:createdTask.Actions=@([pscustomobject]@{Execute=$script:registeredAction.Execute;Arguments='unknown'})
    $refused=$false
    try{$null=Register-H454WssTaskDisabled $oldHash $guardHash $markerHash $supervisorHash $configHash $backupName $lock -OwnerApproved}
    catch{$refused=$_.Exception.Message -ceq 'H454_WSS_TASK_EXISTS'}
    Require-H454 ($refused -and $script:registrations -eq 1) 'FIXTURE_COLLISION'
    $script:createdTask=$null
    [IO.File]::WriteAllText($marker,'wrong-marker',$utf8);$wrongMarker=(Get-FileHash $marker).Hash
    $refused=$false
    try{$null=Register-H454WssTaskDisabled $oldHash $guardHash $wrongMarker $supervisorHash $configHash $backupName $lock -OwnerApproved}
    catch{$refused=$_.Exception.Message -ceq 'H454_WSS_TASK_MARKER'}
    Require-H454 ($refused -and $script:registrations -eq 1) 'FIXTURE_MARKER'
    $badGuard=$guardedText+"`n# unexpected`n";[IO.File]::WriteAllText($launcher,$badGuard,$utf8)
    $badGuardHash=(Get-FileHash $launcher).Hash
    $badMarker="H454_WSS_TRANSITION_V1`noriginal=1fbf00d9b711be215ab35eaea1f6ef549cc4a0930495e3d0776a965f8c75abb6`nold=$oldHash`nguard=$badGuardHash`nbackup=$backupName`n"
    [IO.File]::WriteAllText($marker,$badMarker,$utf8);$badMarkerHash=(Get-FileHash $marker).Hash
    $refused=$false
    try{$null=Register-H454WssTaskDisabled $oldHash $badGuardHash $badMarkerHash $supervisorHash $configHash $backupName $lock -OwnerApproved}
    catch{$refused=$_.Exception.Message -ceq 'H454_WSS_TASK_GUARD'}
    Require-H454 ($refused -and $script:registrations -eq 1) 'FIXTURE_GUARD'
    [IO.File]::WriteAllText($launcher,$guardedText,$utf8);[IO.File]::WriteAllText($marker,$markerText,$utf8)
    $script:legacyDrift=$true;$script:legacyReads=0;$script:createdTask=$null;$refused=$false
    try{$null=Register-H454WssTaskDisabled $oldHash $guardHash $markerHash $supervisorHash $configHash $backupName $lock -OwnerApproved}
    catch{$refused=$_.Exception.Message -ceq 'H454_WSS_TASK_LEGACY'}
    Require-H454 ($refused -and $script:registrations -eq 1) 'FIXTURE_LEGACY_DRIFT'
    $script:legacyDrift=$false;$script:legacyReads=0
    $script:drift=$true;$script:createdTask=$null;$refused=$false
    try{$null=Register-H454WssTaskDisabled $oldHash $guardHash $markerHash $supervisorHash $configHash $backupName $lock -OwnerApproved}
    catch{$refused=$_.Exception.Message -ceq 'H454_WSS_TASK_REGISTER_DRIFT'}
    Require-H454 ($refused -and $script:registrations -eq 2 -and $script:disables -eq 1 -and
        $script:createdTask.State -ceq 'Disabled') 'FIXTURE_REGISTER_DRIFT'
    }
    'H454_WSS_TASK_REGISTRATION_FIXTURE=PASS'
}finally{
    if($RealScheduler){
        $owned=@(ScheduledTasks\Get-ScheduledTask -TaskName $FixtureTaskName -TaskPath '\' -ErrorAction SilentlyContinue)
        if($owned.Count -gt 0){
            Require-H454 ($owned.Count -eq 1 -and [string]$owned[0].State -ceq 'Disabled' -and @($owned[0].Actions).Count -eq 1 -and
                $null -ne $supervisor -and [string]$owned[0].Actions[0].Arguments -like ('*"'+$supervisor+'"*')) 'FIXTURE_REAL_CLEANUP'
            ScheduledTasks\Unregister-ScheduledTask -TaskName $FixtureTaskName -TaskPath '\' -Confirm:$false
        }
    }
    $real=@(ScheduledTasks\Get-ScheduledTask -TaskName 'HermesH454WssTunnel' -TaskPath '\' -ErrorAction SilentlyContinue)
    $realLeak=($real.Count -gt 0)
    if($realLeak -and $real.Count -eq 1 -and [string]$real[0].State -ceq 'Disabled' -and @($real[0].Actions).Count -eq 1 -and
        $null -ne $supervisor -and [string]$real[0].Actions[0].Arguments -like ('*"'+$supervisor+'"*')){
        ScheduledTasks\Unregister-ScheduledTask -TaskName 'HermesH454WssTunnel' -TaskPath '\' -Confirm:$false
    }
    if($null -ne $lock){Close-H454RecoveryLock $lock}
    foreach($path in $files){
        if(Test-Path -LiteralPath $path){
            $item=Get-Item -LiteralPath $path -Force
            Require-H454 ([IO.Path]::GetDirectoryName($item.FullName) -ceq $state -and
                -not $item.PSIsContainer -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'FIXTURE_CLEANUP'
            Remove-Item -LiteralPath $item.FullName -Force
        }
    }
    [IO.Directory]::Delete($state,$false)
    if($realLeak){throw 'FIXTURE_REAL_TASK_CREATED'}
}
