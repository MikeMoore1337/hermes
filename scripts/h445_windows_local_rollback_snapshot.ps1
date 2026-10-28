#requires -Version 5.1
<#
H445 owner-local, single-container evidence snapshot.
Preflight only reads. Backup requires owner approval and writes ONLY
new ACL-restricted files under the user's LocalAppData; no container
or Task Scheduler changes. Snapshot contains confidential Docker
inspect/task XML, NEVER upload or paste it into chat or GitHub.
This is NOT a proven executable rollback plan.
#>
[CmdletBinding()]
param(
    [ValidateSet('Preflight','Backup')][string]$Mode='Preflight',
    [switch]$OwnerApproved
)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'

$taskName='HermesH15BRCWindows'
$cid='571a1e2bede31a07638b896e3ef2de677dafa1c000e4a7975e7996257f8ea162'
$image='sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3'
$originalLauncherHash='55EA1245671C8B656A3BBA944945198350668B2920CD46E36ED7CBA56637317E'

function Deny([string]$Reason) {
    Write-Output 'H445_BACKUP=HOLD'
    Write-Output ('H445_REASON=' + $Reason)
    Write-Output 'H445_ROLLBACK_VERIFIED=FALSE'
    exit 2
}

function Get-LauncherPath([string]$Arguments) {
    if ($Arguments -match '(?i)(?:^|\s)-(?:Command|EncodedCommand|enc)\s') {
        return $null
    }
    $m=[regex]::Match($Arguments,
        '(?i)(?:^|\s)-File\s+(?:"(?<q>[^"]{1,512})"|(?<b>[^\s"]{1,512}))')
    if (-not $m.Success) { return $null }
    if ($m.Groups['q'].Success) { return $m.Groups['q'].Value }
    return $m.Groups['b'].Value
}

function Read-Docker([string[]]$Arguments,[int]$MaxChars=4096) {
    $lines=@(& $script:docker @Arguments 2>$null)
    if ($LASTEXITCODE -ne 0 -or $lines.Count -lt 1 -or
        (($lines -join [Environment]::NewLine).Length -gt $MaxChars)) {
        throw 'DOCKER_READ_FAILED'
    }
    return @($lines)
}

function Protected-Directory([string]$Location) {
    # ACL is installed atomically when the directory is created. No
    # inherited broad read access to private task XML or Docker Env.
    if ([IO.Directory]::Exists($Location) -or [IO.File]::Exists($Location)) {
        throw 'BACKUP_PATH_ALREADY_EXISTS'
    }
    $identity=[Security.Principal.WindowsIdentity]::GetCurrent()
    $acl=New-Object System.Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true,$false)
    $acl.SetOwner($identity.User)
    $sidList=@(
        $identity.User,
        (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')),
        (New-Object Security.Principal.SecurityIdentifier('S-1-5-32-544'))
    )
    foreach ($sid in $sidList) {
        $rule=[Security.AccessControl.FileSystemAccessRule]::new(
            $sid,
            [Security.AccessControl.FileSystemRights]::FullControl,
            ([Security.AccessControl.InheritanceFlags]::ContainerInherit -bor
             [Security.AccessControl.InheritanceFlags]::ObjectInherit),
            [Security.AccessControl.PropagationFlags]::None,
            [Security.AccessControl.AccessControlType]::Allow)
        $acl.AddAccessRule($rule)
    }
    if ([Environment]::Version.Major -lt 5) {
        # Windows PowerShell 5.1 on .NET Framework.
        [IO.Directory]::CreateDirectory($Location,$acl) | Out-Null
    } else {
        # PowerShell 7+ on modern .NET uses the ACL extension.
        [IO.FileSystemAclExtensions]::CreateDirectory($acl,$Location) | Out-Null
    }
    $actual=Get-Acl -LiteralPath $Location -ErrorAction Stop
    if (-not $actual.AreAccessRulesProtected) { throw 'BACKUP_ACL_NOT_PROTECTED' }
    foreach ($ace in $actual.Access) {
        $sid=$ace.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]).Value
        if ($sid -notin @(
            $identity.User.Value,'S-1-5-18','S-1-5-32-544')) {
            throw 'BACKUP_ACL_EXTRA_IDENTITY'
        }
    }
}

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        Deny 'WINDOWS_REQUIRED'
    }
    $docker=Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'
    $dockerFile=Get-Item -LiteralPath $docker -Force -ErrorAction Stop
    if ($dockerFile.PSIsContainer -or
        ($dockerFile.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Deny 'UNTRUSTED_DOCKER_BINARY'
    }
    $task=Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    $actions=@($task.Actions)
    if ($actions.Count -ne 1 -or
        $task.Principal.LogonType -ne 'Interactive' -or
        $task.State -notin @('Ready','Running') -or
        [IO.Path]::GetFileName(([string]$actions[0].Execute).Trim('"')) -notin
            @('powershell.exe','pwsh.exe')) {
        Deny 'TASK_CONTRACT_DRIFT'
    }
    $source=Get-LauncherPath ([string]$actions[0].Arguments)
    if ([string]::IsNullOrWhiteSpace($source) -or
        -not [IO.Path]::IsPathRooted($source) -or
        $source.StartsWith('\\') -or
        [IO.Path]::GetExtension($source) -cne '.ps1') {
        Deny 'LAUNCHER_SOURCE_NOT_VERIFIED'
    }
    $launcher=Get-Item -LiteralPath $source -Force -ErrorAction Stop
    if ($launcher.PSIsContainer -or
        ($launcher.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $launcher.Length -ne 26893) {
        Deny 'LAUNCHER_FILE_DRIFT'
    }
    $launchHash=(Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    if ($launchHash -cne $originalLauncherHash) {
        Deny 'LAUNCHER_HASH_DRIFT'
    }
    $fmt='{{.Id}}|{{.Name}}|{{.Image}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.Memory}}|{{.Config.User}}|{{.State.Running}}|{{.HostConfig.RestartPolicy.Name}}|{{len .Mounts}}'
    $snapshot=@(Read-Docker @('container','inspect','--format',$fmt,$cid))
    $expected="$cid|/hermes-h15-windows-permanent|$image|96|536870912|65534:65534|true|no|1"
    if ($snapshot.Count -ne 1 -or $snapshot[0] -cne $expected) {
        Deny 'CONTAINER_IDENTITY_DRIFT'
    }
    $installed=@(Read-Docker @('image','inspect','--format','{{.Id}}',$image))
    if ($installed.Count -ne 1 -or $installed[0] -cne $image) {
        Deny 'ORIGINAL_IMAGE_MISSING'
    }
    $root=[Environment]::GetFolderPath('LocalApplicationData')
    $rootItem=Get-Item -LiteralPath $root -Force -ErrorAction Stop
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Deny 'LOCAL_APPDATA_UNTRUSTED'
    }
    $dest=Join-Path $root 'HermesH445Rollback-20261028'
    if ([IO.Directory]::Exists($dest) -or [IO.File]::Exists($dest)) {
        Deny 'BACKUP_ALREADY_EXISTS'
    }
    if ($Mode -eq 'Preflight') {
        if ($OwnerApproved) { Deny 'APPROVAL_FLAG_NOT_FOR_PREFLIGHT' }
        Write-Output 'H445_BACKUP=PREFLIGHT_PASS'
        Write-Output 'H445_ORIGINAL_IMAGE=PASS'
        Write-Output 'H445_LAUNCHER_HASH=PASS'
        Write-Output 'H445_BACKUP_FILES_CREATED=FALSE'
        Write-Output 'H445_ROLLBACK_VERIFIED=FALSE'
        exit 0
    }
    if (-not $OwnerApproved) { Deny 'EXPLICIT_OWNER_BACKUP_APPROVAL_REQUIRED' }
    # All sensitive output remains inside the fresh, restricted directory.
    # Never pass task XML, original Docker inspect, or host volume paths to
    # the model, source control, logs, clipboard or remote endpoints.
    Protected-Directory $dest
    $launcherCopy=Join-Path $dest 'launcher.ps1'
    $taskCopy=Join-Path $dest 'scheduled-task.xml'
    $inspectCopy=Join-Path $dest 'container-inspect.json'
    [IO.File]::Copy($launcher.FullName,$launcherCopy,$false)
    $taskXml=Export-ScheduledTask -TaskName $taskName -ErrorAction Stop
    if ($taskXml.Length -lt 100 -or $taskXml.Length -gt 524288) {
        throw 'TASK_XML_SIZE_UNSAFE'
    }
    [IO.File]::WriteAllText($taskCopy,$taskXml,
        ([Text.UTF8Encoding]::new($false)))
    $all=@(Read-Docker @('container','inspect',$cid) 1048576)
    $allText=$all -join [Environment]::NewLine
    [IO.File]::WriteAllText($inspectCopy,$allText,
        ([Text.UTF8Encoding]::new($false)))
    $documents=@($launcherCopy,$taskCopy,$inspectCopy)
    $checks=@{}
    foreach ($path in $documents) {
        $checks[[IO.Path]::GetFileName($path)]=
            (Get-FileHash -LiteralPath $path -Algorithm SHA256).Hash
    }
    if ($checks['launcher.ps1'] -cne $originalLauncherHash) {
        throw 'BACKUP_LAUNCHER_CHECKSUM_MISMATCH'
    }
    $manifest=@{
        schema='h445-owner-local-backup-v1'
        original_container_id=$cid
        original_image_id=$image
        task_name=$taskName
        document_sha256=$checks
        owner_approved_local_backup=$true
        rollback_verified=$false
        original_container_changed=$false
    } | ConvertTo-Json -Depth 5
    [IO.File]::WriteAllText((Join-Path $dest 'manifest.json'),$manifest,
        ([Text.UTF8Encoding]::new($false)))
    $after=@(Read-Docker @('container','inspect','--format',$fmt,$cid))
    if ($after.Count -ne 1 -or $after[0] -cne $expected) {
        throw 'BACKUP_COMPLETED_BUT_CONTAINER_STATE_CHANGED'
    }
    Write-Output 'H445_BACKUP=PASS'
    Write-Output 'H445_ACL=PROTECTED'
    Write-Output 'H445_BACKUP_FILE_COUNT=4'
    Write-Output 'H445_LAUNCHER_HASH=PASS'
    Write-Output 'H445_ORIGINAL_CONTAINER_UNCHANGED=PASS'
    Write-Output 'H445_ROLLBACK_VERIFIED=FALSE'
    exit 0
} catch {
    # Do not print filesystem paths, action arguments or Docker secrets.
    Deny 'BACKUP_PREFLIGHT_OR_CAPTURE_FAILED'
}
