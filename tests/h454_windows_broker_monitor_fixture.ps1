#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$TaskSource,[Parameter(Mandatory=$true)][string]$MonitorSource)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Import-Module ScheduledTasks -ErrorAction Stop
. $TaskSource
. $MonitorSource
function Require-H454([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
function Hash-H454Bytes([byte[]]$Bytes){$h=[Security.Cryptography.SHA256]::Create();try{return [BitConverter]::ToString($h.ComputeHash($Bytes)).Replace('-','')}finally{$h.Dispose()}}
Require-H454 (@(ScheduledTasks\Get-ScheduledTask -TaskName 'HermesH454BrokerRestage' -TaskPath '\' -ErrorAction SilentlyContinue).Count -eq 0) 'FIXTURE_REAL_TASK_EXISTS'
$local=[Environment]::GetFolderPath('LocalApplicationData');$state=Join-Path $local ('H454BrokerFixture-'+[Guid]::NewGuid().ToString('N'))
Require-H454 ([IO.Path]::GetDirectoryName($state) -ceq $local -and -not (Test-Path -LiteralPath $state)) 'FIXTURE_PATH'
$owner=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetOwner($owner);$acl.SetAccessRuleProtection($true,$false)
foreach($sid in @($owner,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'))){
    $rule=[Security.AccessControl.FileSystemAccessRule]::new($sid,'FullControl','ContainerInherit,ObjectInherit','None','Allow');$acl.AddAccessRule($rule)
}
[IO.Directory]::CreateDirectory($state,$acl)|Out-Null
$lockPath=Join-Path $state 'runtime.lock';$lock=[IO.File]::Open($lockPath,[IO.FileMode]::CreateNew,[IO.FileAccess]::ReadWrite,[IO.FileShare]::None)
$user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$script:fakeTask=$null;$script:registrations=0;$script:enables=0;$script:disables=0;$script:drift=$false;$script:checks=0;$script:failAt=0
function Assert-H454PrivateAcl([string]$Path){
    $item=Get-Item -LiteralPath $Path -Force
    Require-H454 ($item.FullName -ceq $state -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
        (Get-Acl -LiteralPath $state).AreAccessRulesProtected) 'FIXTURE_ACL'
}
function Assert-H454RecoveryRouteSafety([string]$StateDir,[IO.FileStream]$Lock,[string]$MarkerSha256,[scriptblock]$SafetyCheck){
    Require-H454 ($StateDir -ceq $state -and [object]::ReferenceEquals($Lock,$lock) -and $Lock.CanWrite -and
        $MarkerSha256 -ceq ('A'*64) -and (& $SafetyCheck)) 'FIXTURE_LOCK'
    $script:checks++;if($script:checks -eq $script:failAt){throw 'H454_ROUTE_SAFETY'}
}
function Get-H454WssDisabledLegacy {
    return [pscustomobject]@{StateDir=$state;Sid=$owner.Value;Task=[pscustomobject]@{Principal=[pscustomobject]@{UserId=$user}}}
}
function Get-ScheduledTask {
    [CmdletBinding()]param([string]$TaskName,[string]$TaskPath)
    if([string]::IsNullOrEmpty($TaskName) -or $TaskName -ceq 'HermesH454BrokerRestage'){
        if($null -ne $script:fakeTask){return $script:fakeTask};return
    }
    throw 'FIXTURE_UNEXPECTED_TASK'
}
function Register-ScheduledTask {
    [CmdletBinding()]param([string]$TaskName,[string]$TaskPath,$Action,$Principal,$Settings,$Trigger)
    Require-H454 ($TaskName -ceq 'HermesH454BrokerRestage' -and -not $Settings.Enabled -and $null -eq $script:fakeTask) 'FIXTURE_REGISTER'
    $script:registrations++
    $principalValue=[pscustomobject]@{UserId=$owner.Value;LogonType=[string]$Principal.LogonType;RunLevel=[string]$Principal.RunLevel}
    $taskState='Disabled';if($script:drift){$Settings.Enabled=$true;$taskState='Ready'}
    $script:fakeTask=[pscustomobject]@{TaskName=$TaskName;State=$taskState;Actions=@($Action);Principal=$principalValue;Settings=$Settings;Triggers=@($Trigger)}
    return $script:fakeTask
}
function Disable-ScheduledTask {
    [CmdletBinding()]param([string]$TaskName,[string]$TaskPath)
    Require-H454 ($TaskName -ceq 'HermesH454BrokerRestage' -and $null -ne $script:fakeTask) 'FIXTURE_DISABLE'
    $script:disables++;$script:fakeTask.State='Disabled';$script:fakeTask.Settings.Enabled=$false
}
function Enable-ScheduledTask {
    [CmdletBinding()]param([string]$TaskName,[string]$TaskPath)
    Require-H454 ($TaskName -ceq 'HermesH454BrokerRestage' -and $null -ne $script:fakeTask) 'FIXTURE_ENABLE'
    $script:enables++;$script:fakeTask.State='Ready';$script:fakeTask.Settings.Enabled=$true
}
Require-H454 ((Get-Command Register-ScheduledTask).CommandType -ceq 'Function' -and
    (Get-Command Enable-ScheduledTask).CommandType -ceq 'Function' -and
    (Get-Command Disable-ScheduledTask).CommandType -ceq 'Function') 'FIXTURE_MOCKS'
$files=@();$pins=@{
    OriginalLauncherSha256=('A'*64);GuardedLauncherSha256=('B'*64);BackupName=('h454-original-launcher-'+('a'*32)+'.txt');
    TaskBackupName=('h454-legacy-task-'+('b'*32)+'.xml');TaskBackupSha256=('C'*64);DockerSha256=('D'*64);
    ProxyImageId=('sha256:'+('a'*64));BrokerImageId=('sha256:'+('b'*64));WssConfigSha256=('E'*64);
    SupervisorSha256=('F'*64);CaSha256=('1'*64);CurlSha256=('2'*64)
}
$spec=[ordered]@{'h454_windows_guard_operator.ps1'='GuardOperatorSourceSha256';'h454_windows_wss_task.ps1'='TaskSourceSha256';
    'h454_windows_offline_recovery.ps1'='RecoverySourceSha256';'h454_windows_original_profile.ps1'='OriginalProfileSourceSha256';
    'h454_windows_recovery_docker.ps1'='RecoveryDockerSourceSha256';'h454_windows_recovery_route.ps1'='RecoveryRouteSourceSha256';
    'h454_windows_network_guard.ps1'='NetworkGuardSourceSha256';'h454_windows_original_restore.ps1'='RestoreSourceSha256';
    'h454_windows_secure_credential.ps1'='SecureCredentialSourceSha256';'h454_windows_broker_credential.ps1'='BrokerCredentialSourceSha256';
    'h454_verify_staged.cjs'='VerifierSourceSha256'}
foreach($name in $spec.Keys){$bytes=[Text.Encoding]::UTF8.GetBytes('synthetic-'+$name);$hash=Hash-H454Bytes $bytes
    $pins[$spec[$name]]=$hash;$files+=@([pscustomobject]@{Name=$name;Bytes=$bytes;Hash=$hash})}
$safety={return $true};$failed=$false;$clean=$true
try{
    $definition=New-H454BrokerMonitorDefinition (Join-Path $state 'h454_windows_guard_operator.ps1') $pins $user ((Get-Date).AddMinutes(5))
    Require-H454 ($definition.Action.Arguments.Contains('-RestoreOriginal -RestageOnly -Apply -OwnerApproved') -and
        $definition.Action.Arguments.Contains('-WindowStyle Hidden') -and -not $definition.Action.Arguments.Contains('brc_dev_') -and
        -not $definition.Settings.Enabled) 'FIXTURE_DEFINITION'
    $badPins=$pins.Clone();$badPins.BackupName='" -Command dangerous';$refused=$false
    try{$null=New-H454BrokerMonitorDefinition (Join-Path $state 'h454_windows_guard_operator.ps1') $badPins $user ((Get-Date).AddMinutes(5))}catch{$refused=$true}
    Require-H454 $refused 'FIXTURE_ARGUMENT_INJECTION'
    $badFiles=@($files);$badFiles[0]=[pscustomobject]@{Name=$files[0].Name.ToUpperInvariant();Bytes=$files[0].Bytes;Hash=$files[0].Hash}
    $refused=$false;try{$null=Install-H454BrokerMonitor $state $lock ('A'*64) $safety $pins $badFiles}catch{$refused=$true}
    Require-H454 $refused 'FIXTURE_FILE_CASE_COLLISION'
    $badPrincipal=[pscustomobject]@{UserId=$owner.Value;LogonType='Interactive';RunLevel='Limited'}
    $badAction=[pscustomobject]@{Execute=$definition.Action.Execute;Arguments='unexpected'}
    $script:fakeTask=[pscustomobject]@{TaskName='HermesH454BrokerRestage';State='Disabled';Actions=@($badAction);
        Principal=$badPrincipal;Settings=$definition.Settings;Triggers=@($definition.Trigger)}
    $refused=$false;try{$null=Install-H454BrokerMonitor $state $lock ('A'*64) $safety $pins $files -Apply -OwnerApproved}catch{$refused=$true}
    Require-H454 ($refused -and $script:registrations -eq 0 -and $script:fakeTask.Actions[0].Arguments -ceq 'unexpected') 'FIXTURE_TASK_COLLISION'
    $script:fakeTask=$null
    $refused=$false;try{$null=Install-H454BrokerMonitor $state $lock ('A'*64) $safety $pins $files -Apply}catch{$refused=$true}
    Require-H454 ($refused -and $script:registrations -eq 0) 'FIXTURE_APPROVAL'
    $collision=Join-Path $state $files[0].Name;[IO.File]::WriteAllText($collision,'foreign')
    $refused=$false;try{$null=Install-H454BrokerMonitor $state $lock ('A'*64) $safety $pins $files -Apply -OwnerApproved}catch{$refused=$true}
    Require-H454 ($refused -and [IO.File]::ReadAllText($collision) -ceq 'foreign' -and $script:registrations -eq 0) 'FIXTURE_COLLISION'
    [IO.File]::Delete($collision)
    $script:checks=0;$script:failAt=4;$refused=$false
    try{$null=Install-H454BrokerMonitor $state $lock ('A'*64) $safety $pins $files -Apply -OwnerApproved}catch{
        $refused=$_.Exception.Message -ceq 'H454_ROUTE_SAFETY';if(-not $refused){throw}
    }
    Require-H454 ($refused -and $script:registrations -eq 0) 'FIXTURE_INTERRUPTION'
    $script:checks=0;$script:failAt=0
    $script:drift=$true;$refused=$false
    try{$null=Install-H454BrokerMonitor $state $lock ('A'*64) $safety $pins $files -Apply -OwnerApproved}catch{$refused=$true}
    Require-H454 ($refused -and $script:disables -eq 1 -and $script:fakeTask.State -ceq 'Disabled') 'FIXTURE_DRIFT_DISABLED'
    $script:fakeTask=$null;$script:drift=$false
    $ready=Install-H454BrokerMonitor $state $lock ('A'*64) $safety $pins $files -Apply -OwnerApproved
    Require-H454 ($ready.Status -ceq 'MONITOR_READY' -and $script:registrations -eq 2 -and $script:enables -eq 1) 'FIXTURE_INSTALL'
    $again=Install-H454BrokerMonitor $state $lock ('A'*64) $safety $pins $files -Apply -OwnerApproved
    Require-H454 ($again.Status -ceq 'MONITOR_READY' -and $script:registrations -eq 2 -and $script:enables -eq 1) 'FIXTURE_IDEMPOTENT'
    'PS51_BROKER_MONITOR_INSTALL_RESUME=PASS'
}catch{$failed=$true;throw}finally{
    $lock.Dispose()
    try{
        Require-H454 ((Resolve-Path -LiteralPath $state).ProviderPath -ceq $state -and [IO.Path]::GetDirectoryName($state) -ceq $local) 'FIXTURE_CLEANUP'
        foreach($entry in $files){$p=Join-Path $state $entry.Name;if(Test-Path -LiteralPath $p){[IO.File]::Delete($p)}}
        if(Test-Path -LiteralPath $lockPath){[IO.File]::Delete($lockPath)}
        [IO.Directory]::Delete($state,$false)
    }catch{$clean=$false}
    if(-not $clean){throw 'FIXTURE_CLEANUP_FAILED'}
}
