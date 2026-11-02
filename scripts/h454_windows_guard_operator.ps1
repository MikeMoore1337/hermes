#requires -Version 5.1
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-F0-9]{64}$')][string]$OriginalLauncherSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-F0-9]{64}$')][string]$GuardedLauncherSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^h454-original-launcher-[a-f0-9]{32}\.txt$')][string]$BackupName,
    [Parameter(Mandatory=$true)][ValidatePattern('^h454-legacy-task-[a-f0-9]{32}\.xml$')][string]$TaskBackupName,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-F0-9]{64}$')][string]$TaskBackupSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-F0-9]{64}$')][string]$TaskSourceSha256,
    [Parameter(Mandatory=$true)][ValidatePattern('^[A-F0-9]{64}$')][string]$RecoverySourceSha256,
    [switch]$Apply,[switch]$OwnerApproved
)
$ErrorActionPreference='Stop'
function Require-H454([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
function Hash-H454Bytes([byte[]]$Bytes){
    $hash=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-','')}finally{$hash.Dispose()}
}
function Read-H454PinnedSource([string]$Path,[string]$Sha256){
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Require-H454 (-not $item.PSIsContainer -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
        $item.Length -gt 0 -and $item.Length -le 500000) 'H454_GUARD_OPERATOR_SOURCE'
    $bytes=[IO.File]::ReadAllBytes($Path)
    Require-H454 ($bytes.Length -gt 0 -and $bytes.Length -le 500000 -and (Hash-H454Bytes $bytes) -ceq $Sha256) 'H454_GUARD_OPERATOR_SOURCE'
    $stream=[IO.MemoryStream]::new($bytes)
    $reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false,$true),$true)
    try{return $reader.ReadToEnd()}finally{$reader.Dispose();$stream.Dispose()}
}
function Assert-H454PrivateAcl([string]$Path){
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $cursor=$item
    while($null -ne $cursor){
        Require-H454 (-not ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'H454_GUARD_OPERATOR_REPARSE'
        if($cursor -is [IO.FileInfo]){$cursor=$cursor.Directory}else{$cursor=$cursor.Parent}
    }
    $directory=if($item.PSIsContainer){$item}else{$item.Directory}
    Require-H454 ((Get-Acl -LiteralPath $directory.FullName).AreAccessRulesProtected) 'H454_GUARD_OPERATOR_ACL'
    $allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
    foreach($target in @($item.FullName,$directory.FullName)){
        $acl=Get-Acl -LiteralPath $target
        Require-H454 ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -in $allowed) 'H454_GUARD_OPERATOR_OWNER'
        $owner=$false
        foreach($rule in $acl.Access){
            $sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            Require-H454 ($sid -in $allowed) 'H454_GUARD_OPERATOR_ACL'
            if($sid -ceq $allowed[0] -and $rule.AccessControlType -eq 'Allow'){$owner=$true}
        }
        Require-H454 $owner 'H454_GUARD_OPERATOR_ACL'
    }
}
function Get-H454Container([string]$Id){
    Require-H454 ($Id -ceq '1fbf00d9b711be215ab35eaea1f6ef549cc4a0930495e3d0776a965f8c75abb6') 'H454_GUARD_OPERATOR_CONTAINER'
    foreach($name in @('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH','DOCKER_CONFIG')){
        Require-H454 ([string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name,'Process'))) 'H454_GUARD_OPERATOR_DOCKER_ENV'
    }
    $docker=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Docker\Docker\resources\bin\docker.exe'
    $item=Get-Item -LiteralPath $docker -Force -ErrorAction Stop
    while($null -ne $item){
        Require-H454 (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'H454_GUARD_OPERATOR_DOCKER'
        if($item -is [IO.FileInfo]){$item=$item.Directory}else{$item=$item.Parent}
    }
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$docker
    $info.Arguments='--host npipe:////./pipe/dockerDesktopLinuxEngine container inspect '+$Id
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $process=[Diagnostics.Process]::new();$process.StartInfo=$info
    try{
        Require-H454 $process.Start() 'H454_GUARD_OPERATOR_DOCKER'
        $output=$process.StandardOutput.ReadToEndAsync();$errors=$process.StandardError.ReadToEndAsync();$process.StandardInput.Close()
        if(-not $process.WaitForExit(20000)){try{$process.Kill()}catch{};throw 'H454_GUARD_OPERATOR_DOCKER_TIMEOUT'}
        $raw=$output.GetAwaiter().GetResult();$null=$errors.GetAwaiter().GetResult()
        Require-H454 ($process.ExitCode -eq 0 -and $raw.Length -gt 0 -and $raw.Length -le 2097152) 'H454_GUARD_OPERATOR_DOCKER'
        $containers=@($raw | ConvertFrom-Json -ErrorAction Stop)
        Require-H454 ($containers.Count -eq 1) 'H454_GUARD_OPERATOR_DOCKER'
        return $containers[0]
    }finally{$process.Dispose()}
}
$lock=$null
try{
    Require-H454 (-not $Apply -or $OwnerApproved) 'H454_GUARD_OPERATOR_APPROVAL'
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
    $taskSource=Join-Path $PSScriptRoot 'h454_windows_wss_task.ps1'
    $recoverySource=Join-Path $PSScriptRoot 'h454_windows_offline_recovery.ps1'
    $taskText=Read-H454PinnedSource $taskSource $TaskSourceSha256
    $recoveryText=Read-H454PinnedSource $recoverySource $RecoverySourceSha256
    $modules=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\Modules'
    Import-Module (Join-Path $modules 'ScheduledTasks\ScheduledTasks.psd1') -ErrorAction Stop
    Import-Module (Join-Path $modules 'NetTCPIP\NetTCPIP.psd1') -ErrorAction Stop
    . ([scriptblock]::Create($taskText))
    . ([scriptblock]::Create($recoveryText))
    $context=Get-H454WssDisabledLegacy
    $state=$context.StateDir
    $taskBackup=Join-Path $state $TaskBackupName
    Assert-H454WssTaskFile $taskBackup $TaskBackupSha256 65536
    [xml]$backupXml=[IO.File]::ReadAllText($taskBackup)
    Require-H454 ([string]$backupXml.Task.Actions.Exec.Command -ieq [string]$context.Task.Actions[0].Execute -and
        [string]$backupXml.Task.Actions.Exec.Arguments -ceq [string]$context.Task.Actions[0].Arguments -and
        (Get-H454WssTaskSid ([string]$backupXml.Task.Principals.Principal.UserId)) -ceq $context.Sid) 'H454_GUARD_OPERATOR_TASK_BACKUP'
    $lockPath=Join-Path $state 'runtime.lock'
    Require-H454 (Test-Path -LiteralPath $lockPath -PathType Leaf) 'H454_GUARD_OPERATOR_LOCK'
    $lock=Open-H454RecoveryLock $state
    $result=Install-H454WssGuard $OriginalLauncherSha256 $GuardedLauncherSha256 $BackupName $lock -Apply:$Apply -OwnerApproved:$OwnerApproved
    foreach($pair in @(@($taskSource,$TaskSourceSha256),@($recoverySource,$RecoverySourceSha256),@($taskBackup,$TaskBackupSha256))){
        Require-H454 ((Get-FileHash -LiteralPath $pair[0] -Algorithm SHA256).Hash -ceq $pair[1]) 'H454_GUARD_OPERATOR_SOURCE_DRIFT'
    }
    'H454_GUARD_OPERATOR='+$result.Status
    'H454_GUARD_BACKUP_NAME='+$result.BackupName
    'H454_GUARD_MARKER_SHA256='+$result.MarkerSha256
}catch{
    $reason=$_.Exception.Message
    if($reason -cnotmatch '^H454_[A-Z0-9_]{1,80}$' -and $reason -cnotmatch '^RECOVERY_[A-Z0-9_]{1,80}$'){$reason='H454_GUARD_OPERATOR_INTERNAL'}
    'H454_GUARD_OPERATOR=HOLD';'H454_GUARD_OPERATOR_REASON='+$reason
    exit 2
}finally{if($null -ne $lock){Close-H454RecoveryLock $lock}}
