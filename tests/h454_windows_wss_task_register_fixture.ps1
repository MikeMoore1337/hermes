#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$Source,[Parameter(Mandatory=$true)][string]$RecoverySource,
      [string]$PythonExe='python',[string]$FixtureTaskName='HermesH454WssTunnel',[switch]$RealScheduler)
$ErrorActionPreference='Stop'
. $Source
. $RecoverySource
Import-Module ScheduledTasks -ErrorAction Stop
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
    $identity=New-FixtureFile 'h454-wss-identity.ps1' ($utf8.GetBytes('fixture-identity'))
    $public=New-FixtureFile 'wss-ssh-identity.pub' ($utf8.GetBytes('fixture-public'))
    $ca=New-FixtureFile 'wss-relay-ca.pem' ($utf8.GetBytes('fixture-ca'))
    $supervisor=Join-Path $state 'h454-wss-tunnel.ps1'
    $env:H454_SUPERVISOR_FIXTURE=$supervisor
    & $PythonExe -B -c "import os; from pathlib import Path; from scripts.h454_windows_wss_tunnel import build; Path(os.environ['H454_SUPERVISOR_FIXTURE']).write_bytes(build())"
    Require-H454 ($LASTEXITCODE -eq 0 -and (Test-Path -LiteralPath $supervisor)) 'FIXTURE_SUPERVISOR'
    $files.Add($supervisor)
    $config=@{version=1;sshHost='relay.example.test';sshUser='fixture';sshPort=2222;relayAddress='172.29.1.2';
        caSha256=(Get-FileHash $ca).Hash;identitySha256=(Get-FileHash $identity).Hash;launcherSha256=$guardHash;
        nodeSha256=('D'*64);publicKeySha256=(Get-FileHash $public).Hash} | ConvertTo-Json -Compress
    $configPath=New-FixtureFile 'h454-wss-tunnel-config.json' ($utf8.GetBytes($config))
    $markerText="H454_WSS_TRANSITION_V1`noriginal=1fbf00d9b711be215ab35eaea1f6ef549cc4a0930495e3d0776a965f8c75abb6`nold=$oldHash`nguard=$guardHash`nbackup=$backupName`n"
    $marker=New-FixtureFile 'h454-wss-transition.pending' ($utf8.GetBytes($markerText))
    $markerHash=(Get-FileHash $marker).Hash;$supervisorHash=(Get-FileHash $supervisor).Hash;$configHash=(Get-FileHash $configPath).Hash
    $action=[pscustomobject]@{Execute=$powershell;Arguments=('-NoProfile -ExecutionPolicy Bypass -File "'+$launcher+'" -Mode Run')}
    $script:legacy=[pscustomobject]@{TaskName='HermesH15BRCWindows';State='Disabled';Actions=@($action);
        Principal=[pscustomobject]@{UserId=$user;LogonType='Interactive'}}
    $lock=Open-H454RecoveryLock $state;$files.Add((Join-Path $state 'runtime.lock'))
    Require-H454 ((Get-Command Register-ScheduledTask).ScriptBlock.ToString().Contains('FIXTURE_REGISTER') -and
        (Get-Command Get-ScheduledTask).ScriptBlock.ToString().Contains('FIXTURE_UNEXPECTED_TASK')) 'FIXTURE_MOCK_SCOPE'
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
    $refused=$false
    try{$null=Register-H454WssTaskDisabled $oldHash $guardHash $markerHash $supervisorHash $configHash $backupName $lock -OwnerApproved}
    catch{$refused=$_.Exception.Message -ceq 'H454_WSS_TASK_EXISTS'}
    Require-H454 ($refused -and $script:registrations -eq 1) 'FIXTURE_COLLISION'
    if(-not $RealScheduler){
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
