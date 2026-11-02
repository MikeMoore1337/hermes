#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$Source,[Parameter(Mandatory=$true)][string]$RecoverySource)
$ErrorActionPreference='Stop'
. $Source
. $RecoverySource
Import-Module ScheduledTasks -ErrorAction Stop
Import-Module NetTCPIP -ErrorAction Stop
function Require-H454([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
function Hash-H454Bytes([byte[]]$Bytes){
    $hash=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-','')}finally{$hash.Dispose()}
}
$local=[Environment]::GetFolderPath('LocalApplicationData')
$state=Join-Path $local ('H454GuardFixture-'+[Guid]::NewGuid().ToString('N'))
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
$launcher=Join-Path $state 'Hermes-H15-Windows-Permanent.ps1'
$marker=Join-Path $state 'h454-wss-transition.pending'
$backupName='h454-original-launcher-'+[Guid]::NewGuid().ToString('N')+'.txt'
$backup=Join-Path $state $backupName
$user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$powershell=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
$script:legacy=[pscustomobject]@{State='Disabled';Actions=@([pscustomobject]@{Execute=$powershell;
    Arguments=('-NoProfile -ExecutionPolicy Bypass -File "'+$launcher+'" -Mode Run')});
    Principal=[pscustomobject]@{UserId=$user;LogonType='Interactive'}}
$script:running=$false;$script:listener=$false;$script:containerChecks=0;$script:failAtCheck=0
function Get-ScheduledTask {[CmdletBinding()]param([string]$TaskName,[string]$TaskPath) Require-H454 ($TaskName -ceq 'HermesH15BRCWindows') 'FIXTURE_TASK';return $script:legacy}
function Get-NetTCPConnection {[CmdletBinding()]param([int]$LocalPort,[string]$State) if($script:listener){return [pscustomobject]@{LocalPort=$LocalPort}}}
function Get-H454Container([string]$Id){
    $script:containerChecks++
    $running=$script:running -or ($script:failAtCheck -gt 0 -and $script:containerChecks -eq $script:failAtCheck)
    return [pscustomobject]@{Id=$Id;Image='sha256:0c95960c02e0dbe00a6a11ee6253d4055e4a7abf7671404b3f876dfdb95bd5d8';
        Name='/hermes-h15-windows-permanent';State=[pscustomobject]@{Running=$running;Status='exited';Paused=$false;Restarting=$false;Dead=$false};
        HostConfig=[pscustomobject]@{RestartPolicy=[pscustomobject]@{Name='no'}}}
}
$parts=Get-H454WssTaskGuardParts
$original=[Text.UTF8Encoding]::new($false).GetBytes(('before'+"`r`n"+$parts.Anchor.Replace("`n","`r`n")+'after'+"`r`n"))
$guarded=New-H454WssGuardBytes $original
$oldHash=Hash-H454Bytes $original;$guardHash=Hash-H454Bytes $guarded
$lock=$null
try{
    Require-H454 ((Get-Command Get-ScheduledTask).ScriptBlock.ToString().Contains('FIXTURE_TASK') -and
        (Get-Command Get-NetTCPConnection).ScriptBlock.ToString().Contains('script:listener')) 'FIXTURE_MOCK_SCOPE'
    [IO.File]::WriteAllBytes($launcher,$original)
    $lock=Open-H454RecoveryLock $state
    $plan=Install-H454WssGuard $oldHash $guardHash $backupName $lock
    Require-H454 ($plan.Status -ceq 'PREFLIGHT' -and -not (Test-Path -LiteralPath $marker) -and
        -not (Test-Path -LiteralPath $backup) -and (Get-FileHash $launcher).Hash -ceq $oldHash) 'FIXTURE_PREFLIGHT'
    $refused=$false
    try{$null=Install-H454WssGuard $oldHash $guardHash $backupName $lock -Apply}catch{$refused=$_.Exception.Message -ceq 'H454_WSS_TASK_APPROVAL'}
    Require-H454 ($refused -and -not (Test-Path -LiteralPath $marker)) 'FIXTURE_APPROVAL'
    $script:running=$true;$refused=$false
    try{$null=Install-H454WssGuard $oldHash $guardHash $backupName $lock -Apply -OwnerApproved}catch{$refused=$_.Exception.Message -ceq 'H454_WSS_GUARD_ORIGINAL'}
    Require-H454 ($refused -and -not (Test-Path -LiteralPath $marker)) 'FIXTURE_RUNNING';$script:running=$false
    $script:listener=$true;$refused=$false
    try{$null=Install-H454WssGuard $oldHash $guardHash $backupName $lock -Apply -OwnerApproved}catch{$refused=$_.Exception.Message -ceq 'H454_WSS_GUARD_LISTENER'}
    Require-H454 ($refused -and -not (Test-Path -LiteralPath $marker)) 'FIXTURE_LISTENER';$script:listener=$false
    [IO.File]::WriteAllText($marker,'unknown')
    $refused=$false
    try{$null=Install-H454WssGuard $oldHash $guardHash $backupName $lock -Apply -OwnerApproved}catch{$refused=$_.Exception.Message -ceq 'H454_WSS_TASK_FILE'}
    Require-H454 ($refused -and [IO.File]::ReadAllText($marker) -ceq 'unknown' -and (Get-FileHash $launcher).Hash -ceq $oldHash) 'FIXTURE_UNKNOWN_MARKER'
    [IO.File]::Delete($marker)
    [IO.File]::WriteAllText($backup,'existing')
    $refused=$false
    try{$null=Install-H454WssGuard $oldHash $guardHash $backupName $lock -Apply -OwnerApproved}catch{$refused=$_.Exception.Message -ceq 'H454_WSS_GUARD_DRIFT'}
    Require-H454 ($refused -and [IO.File]::ReadAllText($backup) -ceq 'existing') 'FIXTURE_BACKUP_COLLISION'
    [IO.File]::Delete($backup)
    $script:containerChecks=0;$script:failAtCheck=3;$refused=$false
    try{$null=Install-H454WssGuard $oldHash $guardHash $backupName $lock -Apply -OwnerApproved}catch{$refused=$_.Exception.Message -ceq 'H454_WSS_GUARD_ORIGINAL'}
    Require-H454 ($refused -and (Test-Path -LiteralPath $marker) -and (Get-FileHash $backup).Hash -ceq $oldHash -and
        (Get-FileHash $launcher).Hash -ceq $oldHash) 'FIXTURE_INTERRUPTED_BEFORE_REPLACE'
    Close-H454RecoveryLock $lock;$lock=Open-H454RecoveryLock $state;$script:failAtCheck=0
    $result=Install-H454WssGuard $oldHash $guardHash $backupName $lock -Apply -OwnerApproved
    Require-H454 ($result.Status -ceq 'INSTALLED_PENDING' -and (Get-FileHash $launcher).Hash -ceq $guardHash -and
        (Get-FileHash $backup).Hash -ceq $oldHash -and (Get-FileHash $marker).Hash -ceq $result.MarkerSha256) 'FIXTURE_INSTALL'
    $again=Install-H454WssGuard $oldHash $guardHash $backupName $lock -Apply -OwnerApproved
    Require-H454 ($again.Status -ceq 'ALREADY_INSTALLED' -and $again.MarkerSha256 -ceq $result.MarkerSha256) 'FIXTURE_REPEAT'
    [IO.File]::WriteAllBytes($launcher,$original)
    $script:containerChecks=0;$script:failAtCheck=4;$refused=$false
    try{$null=Install-H454WssGuard $oldHash $guardHash $backupName $lock -Apply -OwnerApproved}catch{$refused=$_.Exception.Message -ceq 'H454_WSS_GUARD_ORIGINAL'}
    Require-H454 ($refused -and (Get-FileHash $launcher).Hash -ceq $guardHash -and
        (Get-FileHash $backup).Hash -ceq $oldHash -and (Get-FileHash $marker).Hash -ceq $result.MarkerSha256) 'FIXTURE_INTERRUPTED_AFTER_REPLACE'
    Close-H454RecoveryLock $lock;$lock=Open-H454RecoveryLock $state;$script:failAtCheck=0
    $resume=Install-H454WssGuard $oldHash $guardHash $backupName $lock -Apply -OwnerApproved
    Require-H454 ($resume.Status -ceq 'ALREADY_INSTALLED') 'FIXTURE_RESUME'
    'H454_WSS_GUARD_INSTALL_FIXTURE=PASS'
}finally{
    if($null -ne $lock){Close-H454RecoveryLock $lock}
    foreach($item in Get-ChildItem -LiteralPath $state -Force){
        Require-H454 (-not $item.PSIsContainer -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
            [IO.Path]::GetDirectoryName($item.FullName) -ceq $state -and
            ($item.Name -cin @('runtime.lock','Hermes-H15-Windows-Permanent.ps1','h454-wss-transition.pending',$backupName) -or
             $item.Name -cmatch '^h454-(guard|journal)-[a-f0-9]{32}\.new$')) 'FIXTURE_CLEANUP'
        Remove-Item -LiteralPath $item.FullName -Force
    }
    [IO.Directory]::Delete($state,$false)
}
