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
    [switch]$PrepareWss,[switch]$StartWss,[switch]$CheckOriginal,[switch]$PrepareRecoveryRoute,[switch]$PrepareRecoveryBroker,
    [switch]$RestoreOriginal,[switch]$RestageOnly,[switch]$InstallBrokerMonitor,[switch]$PrepareBrokerCandidate,
    [switch]$BeginBrokerTrial,[switch]$RecoverBrokerTrial,[switch]$CompleteBrokerTrial,[switch]$OriginalMcpObserved,
    [string]$FilesSourceSha256,[string]$SupervisorSha256,[string]$IdentitySha256,
    [string]$ModuleSha256,[string]$CaSha256,[string]$NodeSha256,[string]$PublicKeySha256,
    [string]$PublicCaPath,[string]$OriginalProfileSourceSha256,[string]$RecoveryDockerSourceSha256,[string]$DockerSha256,
    [string]$RecoveryRouteSourceSha256,[string]$NetworkGuardSourceSha256,[string]$ProxyImageId,[string]$WssConfigSha256,[string]$CurlSha256,
    [string]$BrokerRouteSourceSha256,[string]$BrokerImageId,[string]$RestoreSourceSha256,
    [string]$SecureCredentialSourceSha256,[string]$BrokerCredentialSourceSha256,[string]$VerifierSourceSha256,
    [string]$GuardOperatorSourceSha256,[string]$MonitorSourceSha256,[string]$CandidateSourceSha256,[string]$CandidateImageId,
    [string]$TrialSourceSha256,[string]$CandidateId,[datetime]$WindowStartUtc,[datetime]$WindowEndUtc,
    [switch]$Apply,[switch]$OwnerApproved
)
$ErrorActionPreference='Stop'
function Require-H454([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
function Hash-H454Bytes([byte[]]$Bytes){
    $hash=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($hash.ComputeHash($Bytes)).Replace('-','')}finally{$hash.Dispose()}
}
function Read-H454PinnedBytes([string]$Path,[string]$Sha256){
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Require-H454 (-not $item.PSIsContainer -and -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
        $item.Length -gt 0 -and $item.Length -le 500000) 'H454_GUARD_OPERATOR_SOURCE'
    $parent=$item.Directory
    while($null -ne $parent){
        Require-H454 (-not ($parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'H454_GUARD_OPERATOR_SOURCE'
        $parent=$parent.Parent
    }
    $bytes=[IO.File]::ReadAllBytes($Path)
    Require-H454 ($bytes.Length -gt 0 -and $bytes.Length -le 500000 -and (Hash-H454Bytes $bytes) -ceq $Sha256) 'H454_GUARD_OPERATOR_SOURCE'
    return ,$bytes
}
function Read-H454PinnedSource([string]$Path,[string]$Sha256){
    $bytes=Read-H454PinnedBytes $Path $Sha256
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
function Get-H454LauncherLeaf([string]$Text,[string]$Variable){
    $tokens=$null;$errors=$null;$ast=[Management.Automation.Language.Parser]::ParseInput($Text,[ref]$tokens,[ref]$errors)
    $items=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.AssignmentStatementAst] -and
        $node.Left -is [Management.Automation.Language.VariableExpressionAst] -and $node.Left.VariablePath.UserPath -ceq $Variable},$true))
    Require-H454 (@($errors).Count -eq 0 -and $items.Count -eq 1 -and
        $items[0].Right -is [Management.Automation.Language.PipelineAst] -and @($items[0].Right.PipelineElements).Count -eq 1) 'H454_RESTORE_PATH_SOURCE'
    $command=$items[0].Right.PipelineElements[0]
    Require-H454 ($command -is [Management.Automation.Language.CommandAst] -and @($command.CommandElements).Count -eq 3 -and
        $command.CommandElements[0] -is [Management.Automation.Language.StringConstantExpressionAst] -and
        $command.CommandElements[0].Value -ceq 'Join-Path' -and
        $command.CommandElements[1] -is [Management.Automation.Language.VariableExpressionAst] -and
        $command.CommandElements[1].VariablePath.UserPath -ceq 'STATE_DIR' -and
        $command.CommandElements[2] -is [Management.Automation.Language.StringConstantExpressionAst]) 'H454_RESTORE_PATH_SOURCE'
    $leaf=[string]$command.CommandElements[2].Value
    Require-H454 ($leaf -cmatch '^[A-Za-z0-9_.-]{1,128}$' -and $leaf -cnotin @('.','..') -and
        [IO.Path]::GetFileName($leaf) -ceq $leaf) 'H454_RESTORE_PATH_SOURCE'
    return $leaf
}
function Read-H454ProtectedText([string]$Path,[int]$MaxBytes){
    Assert-H454PrivateAcl $Path
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    Require-H454 (-not $item.PSIsContainer -and $item.Length -gt 0 -and $item.Length -le $MaxBytes) 'H454_RESTORE_PRIVATE_FILE'
    $stream=[IO.File]::Open($Path,[IO.FileMode]::Open,[IO.FileAccess]::Read,[IO.FileShare]::Read)
    $reader=[IO.StreamReader]::new($stream,[Text.UTF8Encoding]::new($false,$true),$true)
    try{return $reader.ReadToEnd()}finally{$reader.Dispose();$stream.Dispose()}
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
    Require-H454 (-not $StartWss -or ($PrepareWss -and $Apply -and $OwnerApproved)) 'H454_GUARD_OPERATOR_WSS_MODE'
    Require-H454 (-not $RestageOnly -or ($RestoreOriginal -and $Apply -and $OwnerApproved)) 'H454_GUARD_OPERATOR_MONITOR_MODE'
    Require-H454 (-not $InstallBrokerMonitor -or ($RestoreOriginal -and -not $RestageOnly)) 'H454_GUARD_OPERATOR_MONITOR_MODE'
    Require-H454 (-not $PrepareBrokerCandidate -or ($RestoreOriginal -and -not $RestageOnly -and -not $InstallBrokerMonitor)) 'H454_GUARD_OPERATOR_CANDIDATE_MODE'
    $trial=($BeginBrokerTrial -or $RecoverBrokerTrial -or $CompleteBrokerTrial)
    Require-H454 (-not $trial -or ($RestoreOriginal -and -not $RestageOnly -and -not $InstallBrokerMonitor -and
        -not $PrepareBrokerCandidate -and @(@($BeginBrokerTrial,$RecoverBrokerTrial,$CompleteBrokerTrial)|Where-Object {$_}).Count -eq 1)) 'H454_GUARD_OPERATOR_TRIAL_MODE'
    Require-H454 (-not $OriginalMcpObserved -or ($CompleteBrokerTrial -and $Apply)) 'H454_GUARD_OPERATOR_TRIAL_MODE'
    Require-H454 (-not ($CompleteBrokerTrial -and $Apply) -or $OriginalMcpObserved) 'H454_TRIAL_MCP_ACKNOWLEDGMENT'
    if($PrepareBrokerCandidate -or $trial){
        Require-H454 ($CandidateSourceSha256 -cmatch '^[A-F0-9]{64}$' -and
            $CandidateImageId -cmatch '^sha256:[a-f0-9]{64}$') 'H454_GUARD_OPERATOR_CANDIDATE_PINS'
    }
    if($trial){Require-H454 ($TrialSourceSha256 -cmatch '^[A-F0-9]{64}$' -and $CandidateId -cmatch '^[a-f0-9]{64}$') 'H454_GUARD_OPERATOR_TRIAL_PINS'}
    if($RestageOnly -or $InstallBrokerMonitor -or $PrepareBrokerCandidate -or $trial){
        Require-H454 ($GuardOperatorSourceSha256 -cmatch '^[A-F0-9]{64}$') 'H454_GUARD_OPERATOR_MONITOR_PINS'
        $null=Read-H454PinnedBytes $PSCommandPath $GuardOperatorSourceSha256
    }
    if($InstallBrokerMonitor){Require-H454 ($MonitorSourceSha256 -cmatch '^[A-F0-9]{64}$') 'H454_GUARD_OPERATOR_MONITOR_PINS'}
    if($CheckOriginal -or $PrepareRecoveryRoute -or $PrepareRecoveryBroker -or $RestoreOriginal){
        Require-H454 (@(@($CheckOriginal,$PrepareRecoveryRoute,$PrepareRecoveryBroker,$RestoreOriginal)|Where-Object {$_}).Count -eq 1 -and
            (-not $CheckOriginal -or -not $Apply) -and
            -not $PrepareWss -and -not $StartWss -and
            $OriginalProfileSourceSha256 -cmatch '^[A-F0-9]{64}$' -and
            $RecoveryDockerSourceSha256 -cmatch '^[A-F0-9]{64}$' -and $DockerSha256 -cmatch '^[A-F0-9]{64}$') 'H454_GUARD_OPERATOR_ORIGINAL_MODE'
    }
    if($PrepareRecoveryRoute -or $PrepareRecoveryBroker -or $RestoreOriginal){
        foreach($pin in @($RecoveryRouteSourceSha256,$NetworkGuardSourceSha256,$WssConfigSha256,$SupervisorSha256,$CaSha256,$CurlSha256)){
            Require-H454 ($pin -cmatch '^[A-F0-9]{64}$') 'H454_GUARD_OPERATOR_ROUTE_PINS'
        }
        Require-H454 ($ProxyImageId -cmatch '^sha256:[a-f0-9]{64}$') 'H454_GUARD_OPERATOR_ROUTE_PINS'
    }
    if($PrepareRecoveryBroker -or $RestoreOriginal){
        Require-H454 ($BrokerImageId -cmatch '^sha256:[a-f0-9]{64}$' -and $BrokerImageId -cne $ProxyImageId) 'H454_GUARD_OPERATOR_BROKER_PINS'
        if($PrepareRecoveryBroker){Require-H454 ($BrokerRouteSourceSha256 -cmatch '^[A-F0-9]{64}$') 'H454_GUARD_OPERATOR_BROKER_PINS'}
    }
    if($RestoreOriginal){
        foreach($pin in @($RestoreSourceSha256,$SecureCredentialSourceSha256,$BrokerCredentialSourceSha256,$VerifierSourceSha256)){
            Require-H454 ($pin -cmatch '^[A-F0-9]{64}$') 'H454_GUARD_OPERATOR_RESTORE_PINS'
        }
    }
    if($PrepareWss){
        foreach($pin in @($FilesSourceSha256,$SupervisorSha256,$IdentitySha256,$ModuleSha256,$CaSha256,$NodeSha256,$PublicKeySha256)){
            Require-H454 ($pin -cmatch '^[A-F0-9]{64}$') 'H454_GUARD_OPERATOR_WSS_PINS'
        }
        Require-H454 (-not [string]::IsNullOrWhiteSpace($PublicCaPath) -and [IO.Path]::IsPathRooted($PublicCaPath)) 'H454_GUARD_OPERATOR_WSS_PINS'
    }
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
    if($RestageOnly){Assert-H454PrivateAcl $PSCommandPath}
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
    if($CheckOriginal -or $PrepareRecoveryRoute -or $PrepareRecoveryBroker -or $RestoreOriginal){
        $profileSource=Join-Path $PSScriptRoot 'h454_windows_original_profile.ps1'
        $dockerSource=Join-Path $PSScriptRoot 'h454_windows_recovery_docker.ps1'
        $profileText=Read-H454PinnedSource $profileSource $OriginalProfileSourceSha256
        $dockerText=Read-H454PinnedSource $dockerSource $RecoveryDockerSourceSha256
        . ([scriptblock]::Create($profileText))
        . ([scriptblock]::Create($dockerText))
        $backup=Join-Path $state $BackupName;$marker=Join-Path $state 'h454-wss-transition.pending'
        $markerText=Get-H454WssMarkerText $OriginalLauncherSha256 $GuardedLauncherSha256 $BackupName
        $markerHash=Hash-H454Bytes ([Text.UTF8Encoding]::new($false).GetBytes($markerText))
        Assert-H454WssTaskFile $backup $OriginalLauncherSha256 200000
        Assert-H454WssTaskFile $context.Launcher $GuardedLauncherSha256 200000
        Assert-H454WssTaskFile $marker $markerHash 4096
        Require-H454 ([IO.File]::ReadAllText($marker) -ceq $markerText) 'H454_WSS_TASK_MARKER'
        Assert-H454WssTaskGuardBytes ([IO.File]::ReadAllBytes($backup)) ([IO.File]::ReadAllBytes($context.Launcher))
        $inspect=Invoke-H454RecoveryDocker -Arguments @('container','inspect','1fbf00d9b711be215ab35eaea1f6ef549cc4a0930495e3d0776a965f8c75abb6') -DockerSha256 $DockerSha256
        Require-H454 ($inspect.Code -eq 0 -and $inspect.Output.Length -gt 0) 'H454_ORIGINAL_PROFILE_INSPECT'
        $originals=@($inspect.Output | ConvertFrom-Json -ErrorAction Stop)
        Require-H454 ($originals.Count -eq 1) 'H454_ORIGINAL_PROFILE_INSPECT'
        $original=$originals[0]
        if(-not $RestoreOriginal){
            Require-H454 ($original.State.Running -is [bool] -and -not $original.State.Running -and
                [string]$original.State.Status -ceq 'exited' -and [string]$original.HostConfig.RestartPolicy.Name -ceq 'no') 'H454_ORIGINAL_PROFILE_STATE'
            Assert-H454OriginalProfile $original $backup $OriginalLauncherSha256 `
                '1fbf00d9b711be215ab35eaea1f6ef549cc4a0930495e3d0776a965f8c75abb6' `
                'sha256:0c95960c02e0dbe00a6a11ee6253d4055e4a7abf7671404b3f876dfdb95bd5d8' 'hermes-h15-windows-permanent' 'bridge'
        }
        Assert-H454RecoveryLock $state $lock
        Assert-H454WssLegacyUnchanged $context.Task $context.Sid
        foreach($pair in @(@($profileSource,$OriginalProfileSourceSha256),@($dockerSource,$RecoveryDockerSourceSha256))){
            Require-H454 ((Get-FileHash -LiteralPath $pair[0] -Algorithm SHA256).Hash -ceq $pair[1]) 'H454_GUARD_OPERATOR_SOURCE_DRIFT'
        }
        if($PrepareRecoveryRoute -or $PrepareRecoveryBroker -or $RestoreOriginal){
            $routeSource=Join-Path $PSScriptRoot 'h454_windows_recovery_route.ps1'
            $networkSource=Join-Path $PSScriptRoot 'h454_windows_network_guard.ps1'
            $routeText=Read-H454PinnedSource $routeSource $RecoveryRouteSourceSha256
            $networkText=Read-H454PinnedSource $networkSource $NetworkGuardSourceSha256
            . ([scriptblock]::Create($networkText))
            . ([scriptblock]::Create($routeText))
            $supervisor=Join-Path $state 'h454-wss-tunnel.ps1';$config=Join-Path $state 'h454-wss-tunnel-config.json'
            $ca=Join-Path $state 'wss-relay-ca.pem';$curl=Join-Path ([Environment]::GetFolderPath('System')) 'curl.exe'
            $safetyCheck={
                Assert-H454RecoveryLock $state $lock
                Assert-H454WssLegacyUnchanged $context.Task $context.Sid
                Assert-H454WssTaskFile $backup $OriginalLauncherSha256 200000
                Assert-H454WssTaskFile $context.Launcher $GuardedLauncherSha256 200000
                Assert-H454WssTaskFile $supervisor $SupervisorSha256 65536
                Assert-H454WssTaskFile $config $WssConfigSha256 8192
                Assert-H454WssTaskFile $ca $CaSha256 65536
                $task=Get-ScheduledTask -TaskName 'HermesH454WssTunnel' -TaskPath '\' -ErrorAction Stop
                $definition=New-H454WssTaskDefinition $supervisor $WssConfigSha256 ([string]$context.Task.Principal.UserId) ((Get-Date).AddMinutes(5))
                Require-H454 ([string]$task.State -ceq 'Running' -and (Test-H454WssTaskMatch $task $definition $context.Sid -Enabled)) 'H454_ROUTE_WSS_TASK'
                $listenerErrors=@()
                $plaintext=@(Get-NetTCPConnection -LocalPort 38180 -State Listen -ErrorAction SilentlyContinue -ErrorVariable +listenerErrors)
                foreach($listenerError in $listenerErrors){Require-H454 ($listenerError.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) 'H454_ROUTE_LISTENER'}
                Require-H454 ($plaintext.Count -eq 0 -and (Get-FileHash -LiteralPath $curl -Algorithm SHA256).Hash -ceq $CurlSha256 -and
                    (Get-AuthenticodeSignature -LiteralPath $curl).Status -eq 'Valid') 'H454_ROUTE_LISTENER'
                $health=@(& $curl -q --proto '=https' --noproxy '*' --ssl-revoke-best-effort --silent --connect-timeout 2 --max-time 4 `
                    --cacert $ca --resolve 'brc-agent.internal:38184:127.0.0.1' --output NUL --write-out '%{http_code}' 'https://brc-agent.internal:38184/' 2>$null)
                Require-H454 ($LASTEXITCODE -eq 0 -and $health.Count -eq 1 -and $health[0] -ceq '404') 'H454_ROUTE_WSS_TLS'
                if(-not $RestoreOriginal){
                    $fresh=Invoke-H454RecoveryDocker -Arguments @('container','inspect','1fbf00d9b711be215ab35eaea1f6ef549cc4a0930495e3d0776a965f8c75abb6') -DockerSha256 $DockerSha256
                    Require-H454 ($fresh.Code -eq 0 -and $fresh.Output.Length -gt 0) 'H454_ORIGINAL_PROFILE_INSPECT'
                    $items=@($fresh.Output | ConvertFrom-Json -ErrorAction Stop)
                    Require-H454 ($items.Count -eq 1 -and $items[0].State.Running -is [bool] -and -not $items[0].State.Running -and
                        [string]$items[0].State.Status -ceq 'exited' -and [string]$items[0].HostConfig.RestartPolicy.Name -ceq 'no') 'H454_ORIGINAL_PROFILE_STATE'
                    Assert-H454OriginalProfile $items[0] $backup $OriginalLauncherSha256 `
                        '1fbf00d9b711be215ab35eaea1f6ef549cc4a0930495e3d0776a965f8c75abb6' `
                        'sha256:0c95960c02e0dbe00a6a11ee6253d4055e4a7abf7671404b3f876dfdb95bd5d8' 'hermes-h15-windows-permanent' 'bridge'
                }
                return $true
            }
            if($RestoreOriginal){
                $restoreSource=Join-Path $PSScriptRoot 'h454_windows_original_restore.ps1'
                $secureSource=Join-Path $PSScriptRoot 'h454_windows_secure_credential.ps1'
                $brokerCredentialSource=Join-Path $PSScriptRoot 'h454_windows_broker_credential.ps1'
                $verifierSource=Join-Path $PSScriptRoot 'h454_verify_staged.cjs'
                . ([scriptblock]::Create((Read-H454PinnedSource $restoreSource $RestoreSourceSha256)))
                . ([scriptblock]::Create((Read-H454PinnedSource $secureSource $SecureCredentialSourceSha256)))
                . ([scriptblock]::Create((Read-H454PinnedSource $brokerCredentialSource $BrokerCredentialSourceSha256)))
                $null=Read-H454PinnedBytes $verifierSource $VerifierSourceSha256
                $restoreArgs=@{StateDir=$state;Lock=$lock;MarkerSha256=$markerHash;SafetyCheck=$safetyCheck;
                    Launcher=$backup;LauncherSha256=$OriginalLauncherSha256;
                    AgentId='1fbf00d9b711be215ab35eaea1f6ef549cc4a0930495e3d0776a965f8c75abb6';
                    AgentImage='sha256:0c95960c02e0dbe00a6a11ee6253d4055e4a7abf7671404b3f876dfdb95bd5d8';
                    AgentName='hermes-h15-windows-permanent';DeviceId='h15-win-05be75515428';
                    OldImage=$ProxyImageId;BrokerImage=$BrokerImageId;CaSha256=$CaSha256;DockerSha256=$DockerSha256;
                    VerifierPath=$verifierSource;VerifierSha256=$VerifierSourceSha256}
                if(-not $RecoverBrokerTrial){$result=Restore-H454Original @restoreArgs}
                if($trial){
                    $candidateSource=Join-Path $PSScriptRoot 'h454_windows_candidate_prepare.ps1'
                    $trialSource=Join-Path $PSScriptRoot 'h454_windows_broker_trial.ps1'
                    . ([scriptblock]::Create((Read-H454PinnedSource $candidateSource $CandidateSourceSha256)))
                    . ([scriptblock]::Create((Read-H454PinnedSource $trialSource $TrialSourceSha256)))
                }
                if($PrepareBrokerCandidate){
                    $candidateSource=Join-Path $PSScriptRoot 'h454_windows_candidate_prepare.ps1'
                    . ([scriptblock]::Create((Read-H454PinnedSource $candidateSource $CandidateSourceSha256)))
                    $result=Prepare-H454BrokerCandidate $restoreArgs $CandidateImageId -Apply:$Apply -OwnerApproved:$OwnerApproved
                    Require-H454 ((Get-FileHash -LiteralPath $candidateSource -Algorithm SHA256).Hash -ceq $CandidateSourceSha256 -and
                        (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash -ceq $GuardOperatorSourceSha256) 'H454_GUARD_OPERATOR_SOURCE_DRIFT'
                }elseif($InstallBrokerMonitor){
                    $monitorSource=Join-Path $PSScriptRoot 'h454_windows_broker_monitor.ps1'
                    . ([scriptblock]::Create((Read-H454PinnedSource $monitorSource $MonitorSourceSha256)))
                    $pins=@{OriginalLauncherSha256=$OriginalLauncherSha256;GuardedLauncherSha256=$GuardedLauncherSha256;
                        BackupName=$BackupName;TaskBackupName=$TaskBackupName;TaskBackupSha256=$TaskBackupSha256;
                        TaskSourceSha256=$TaskSourceSha256;RecoverySourceSha256=$RecoverySourceSha256;
                        OriginalProfileSourceSha256=$OriginalProfileSourceSha256;RecoveryDockerSourceSha256=$RecoveryDockerSourceSha256;
                        DockerSha256=$DockerSha256;RecoveryRouteSourceSha256=$RecoveryRouteSourceSha256;NetworkGuardSourceSha256=$NetworkGuardSourceSha256;
                        ProxyImageId=$ProxyImageId;BrokerImageId=$BrokerImageId;WssConfigSha256=$WssConfigSha256;
                        SupervisorSha256=$SupervisorSha256;CaSha256=$CaSha256;CurlSha256=$CurlSha256;
                        RestoreSourceSha256=$RestoreSourceSha256;SecureCredentialSourceSha256=$SecureCredentialSourceSha256;
                        BrokerCredentialSourceSha256=$BrokerCredentialSourceSha256;VerifierSourceSha256=$VerifierSourceSha256;
                        GuardOperatorSourceSha256=$GuardOperatorSourceSha256}
                    $sourceSpec=[ordered]@{'h454_windows_guard_operator.ps1'=$GuardOperatorSourceSha256;
                        'h454_windows_wss_task.ps1'=$TaskSourceSha256;'h454_windows_offline_recovery.ps1'=$RecoverySourceSha256;
                        'h454_windows_original_profile.ps1'=$OriginalProfileSourceSha256;'h454_windows_recovery_docker.ps1'=$RecoveryDockerSourceSha256;
                        'h454_windows_recovery_route.ps1'=$RecoveryRouteSourceSha256;'h454_windows_network_guard.ps1'=$NetworkGuardSourceSha256;
                        'h454_windows_original_restore.ps1'=$RestoreSourceSha256;'h454_windows_secure_credential.ps1'=$SecureCredentialSourceSha256;
                        'h454_windows_broker_credential.ps1'=$BrokerCredentialSourceSha256;'h454_verify_staged.cjs'=$VerifierSourceSha256}
                    $sourceFiles=@(foreach($name in $sourceSpec.Keys){$path=Join-Path $PSScriptRoot $name
                        [pscustomobject]@{Name=$name;Hash=$sourceSpec[$name];Bytes=(Read-H454PinnedBytes $path $sourceSpec[$name])}})
                    $result=Install-H454BrokerMonitor $state $lock $markerHash $safetyCheck $pins $sourceFiles -Apply:$Apply -OwnerApproved:$OwnerApproved
                    Require-H454 ((Get-FileHash -LiteralPath $monitorSource -Algorithm SHA256).Hash -ceq $MonitorSourceSha256) 'H454_GUARD_OPERATOR_SOURCE_DRIFT'
                }elseif($trial -and -not $Apply){
                    if($BeginBrokerTrial){$result=Start-H454BrokerTrial $restoreArgs $CandidateId $CandidateImageId}
                    elseif($RecoverBrokerTrial){$result=Restore-H454BrokerTrial $restoreArgs $CandidateId $CandidateImageId}
                    else{$result=Complete-H454BrokerTrial $restoreArgs $CandidateId $CandidateImageId}
                }elseif($Apply -and ($trial -or -not $RestageOnly -or $result.Running)){
                    $launcherText=Read-H454PinnedSource $backup $OriginalLauncherSha256
                    $credentialPath=Join-Path $state (Get-H454LauncherLeaf $launcherText 'CRED_PATH')
                    $statePath=Join-Path $state (Get-H454LauncherLeaf $launcherText 'STATE_PATH')
                    $record=ConvertFrom-Json -InputObject (Read-H454ProtectedText $statePath 65536) -ErrorAction Stop
                    Require-H454 ($record.deviceId -ceq $restoreArgs.DeviceId -and $record.imageId -ceq $restoreArgs.AgentImage) 'H454_RESTORE_SAVED_IDENTITY'
                    $encrypted=(Read-H454ProtectedText $credentialPath 65536).Trim()
                    $secure=ConvertTo-SecureString -String $encrypted -ErrorAction Stop
                    $pointer=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
                    try{$plaintext=[Runtime.InteropServices.Marshal]::PtrToStringBSTR($pointer)}
                    finally{[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($pointer);$secure.Dispose()}
                    $credential=Convert-H454BrokerCredential $plaintext $restoreArgs.DeviceId
                    try {
                        if($BeginBrokerTrial){
                            $result=Start-H454BrokerTrial $restoreArgs $CandidateId $CandidateImageId $credential.TokenBytes $credential.AgentBytes `
                                $WindowStartUtc $WindowEndUtc -Apply -OwnerApproved:$OwnerApproved
                        }elseif($RecoverBrokerTrial){
                            $result=Restore-H454BrokerTrial $restoreArgs $CandidateId $CandidateImageId $credential.TokenBytes $credential.AgentBytes `
                                -Apply -OwnerApproved:$OwnerApproved
                        }elseif($CompleteBrokerTrial){
                            $result=Complete-H454BrokerTrial $restoreArgs $CandidateId $CandidateImageId $credential.TokenBytes $credential.AgentBytes `
                                -Apply -OwnerApproved:$OwnerApproved -OriginalMcpObserved:$OriginalMcpObserved
                        }else{
                            $result=Restore-H454Original @restoreArgs -TokenBytes $credential.TokenBytes -AgentBytes $credential.AgentBytes `
                                -Apply -OwnerApproved:$OwnerApproved -RestageOnly:$RestageOnly
                        }
                    } finally {
                        [Array]::Clear($credential.TokenBytes,0,$credential.TokenBytes.Length)
                        [Array]::Clear($credential.AgentBytes,0,$credential.AgentBytes.Length)
                    }
                }elseif($RestageOnly){$result=[pscustomobject]@{Status='MONITOR_WAITING'}}
                if($trial){
                    foreach($pair in @(@($candidateSource,$CandidateSourceSha256),@($trialSource,$TrialSourceSha256),@($PSCommandPath,$GuardOperatorSourceSha256))){
                        Require-H454 ((Get-FileHash -LiteralPath $pair[0] -Algorithm SHA256).Hash -ceq $pair[1]) 'H454_GUARD_OPERATOR_SOURCE_DRIFT'
                    }
                }
                foreach($pair in @(@($restoreSource,$RestoreSourceSha256),@($secureSource,$SecureCredentialSourceSha256),
                    @($brokerCredentialSource,$BrokerCredentialSourceSha256),@($verifierSource,$VerifierSourceSha256))){
                    Require-H454 ((Get-FileHash -LiteralPath $pair[0] -Algorithm SHA256).Hash -ceq $pair[1]) 'H454_GUARD_OPERATOR_SOURCE_DRIFT'
                }
            }elseif($PrepareRecoveryBroker){
                $brokerSource=Join-Path $PSScriptRoot 'h454_windows_broker_route.ps1'
                $brokerText=Read-H454PinnedSource $brokerSource $BrokerRouteSourceSha256
                . ([scriptblock]::Create($brokerText))
                $result=Prepare-H454RecoveryBroker $state $lock $markerHash $ProxyImageId $BrokerImageId $CaSha256 $DockerSha256 $safetyCheck -Apply:$Apply -OwnerApproved:$OwnerApproved
                Require-H454 ((Get-FileHash -LiteralPath $brokerSource -Algorithm SHA256).Hash -ceq $BrokerRouteSourceSha256) 'H454_GUARD_OPERATOR_SOURCE_DRIFT'
            }else{
                $result=Prepare-H454RecoveryRoute $state $lock $markerHash $ProxyImageId $CaSha256 $DockerSha256 $safetyCheck -Apply:$Apply -OwnerApproved:$OwnerApproved
            }
            foreach($pair in @(@($routeSource,$RecoveryRouteSourceSha256),@($networkSource,$NetworkGuardSourceSha256))){
                Require-H454 ((Get-FileHash -LiteralPath $pair[0] -Algorithm SHA256).Hash -ceq $pair[1]) 'H454_GUARD_OPERATOR_SOURCE_DRIFT'
            }
        }
    }elseif($PrepareWss){
        $filesSource=Join-Path $PSScriptRoot 'h454_windows_wss_files.ps1'
        $supervisorSource=Join-Path $PSScriptRoot 'h454_windows_wss_tunnel.ps1'
        $identitySource=Join-Path $PSScriptRoot 'h454_windows_wss_identity.ps1'
        $moduleSource=Join-Path $PSScriptRoot 'h454_windows_wss_identity.mjs'
        $filesText=Read-H454PinnedSource $filesSource $FilesSourceSha256
        $supervisor=Read-H454PinnedBytes $supervisorSource $SupervisorSha256
        $identity=Read-H454PinnedBytes $identitySource $IdentitySha256
        $module=Read-H454PinnedBytes $moduleSource $ModuleSha256
        $ca=Read-H454PinnedBytes $PublicCaPath $CaSha256
        . ([scriptblock]::Create($filesText))
        $markerText=Get-H454WssMarkerText $OriginalLauncherSha256 $GuardedLauncherSha256 $BackupName
        $markerHash=Hash-H454Bytes ([Text.UTF8Encoding]::new($false).GetBytes($markerText))
        $result=Install-H454WssFiles $supervisor $identity $module $ca $SupervisorSha256 $IdentitySha256 $ModuleSha256 $CaSha256 `
            $NodeSha256 $PublicKeySha256 $OriginalLauncherSha256 $GuardedLauncherSha256 $markerHash $BackupName $lock -Apply:$Apply -OwnerApproved:$OwnerApproved
        if($Apply){
            if($StartWss){
                $taskStatus=Start-H454WssTask $OriginalLauncherSha256 $GuardedLauncherSha256 $markerHash `
                    $SupervisorSha256 $result.ConfigSha256 $BackupName $lock -OwnerApproved
            }else{
                $taskStatus=Register-H454WssTaskDisabled $OriginalLauncherSha256 $GuardedLauncherSha256 $markerHash `
                    $SupervisorSha256 $result.ConfigSha256 $BackupName $lock -OwnerApproved
            }
        }
    }else{
        $result=Install-H454WssGuard $OriginalLauncherSha256 $GuardedLauncherSha256 $BackupName $lock -Apply:$Apply -OwnerApproved:$OwnerApproved
    }
    foreach($pair in @(@($taskSource,$TaskSourceSha256),@($recoverySource,$RecoverySourceSha256),@($taskBackup,$TaskBackupSha256))){
        Require-H454 ((Get-FileHash -LiteralPath $pair[0] -Algorithm SHA256).Hash -ceq $pair[1]) 'H454_GUARD_OPERATOR_SOURCE_DRIFT'
    }
    if($trial){
        'H454_BROKER_TRIAL_OPERATOR='+$result.Status
    }elseif($PrepareBrokerCandidate){
        'H454_BROKER_CANDIDATE_OPERATOR='+$result.Status
        if($Apply){'H454_BROKER_CANDIDATE_ID='+$result.CandidateId}
    }elseif($InstallBrokerMonitor){
        'H454_BROKER_MONITOR_OPERATOR='+$result.Status
    }elseif($RestoreOriginal){
        'H454_ORIGINAL_RESTORE_OPERATOR='+$result.Status
    }elseif($PrepareRecoveryBroker){
        'H454_RECOVERY_BROKER_OPERATOR='+$result.Status
    }elseif($PrepareRecoveryRoute){
        'H454_RECOVERY_ROUTE_OPERATOR='+$result.Status
    }elseif($CheckOriginal){
        'H454_ORIGINAL_PROFILE_PREFLIGHT=PASS'
    }elseif($PrepareWss){
        'H454_WSS_FILES_OPERATOR='+$result.Status
        'H454_WSS_CONFIG_SHA256='+$result.ConfigSha256
        if($Apply){$taskStatus}
    }else{
        'H454_GUARD_OPERATOR='+$result.Status
        'H454_GUARD_BACKUP_NAME='+$result.BackupName
        'H454_GUARD_MARKER_SHA256='+$result.MarkerSha256
    }
}catch{
    $reason=$_.Exception.Message
    if($reason -cnotmatch '^H454_[A-Z0-9_]{1,80}$' -and $reason -cnotmatch '^RECOVERY_[A-Z0-9_]{1,80}$'){$reason='H454_GUARD_OPERATOR_INTERNAL'}
    'H454_GUARD_OPERATOR=HOLD';'H454_GUARD_OPERATOR_REASON='+$reason
    exit 2
}finally{if($null -ne $lock){Close-H454RecoveryLock $lock}}
