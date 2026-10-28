#requires -Version 5.1
<#
Hermes H445 restore-readiness inspection on OWNER Windows ONLY.
READ-ONLY: no Docker container mutations, task changes, backups or restore.
Sensitive full container inspect and task XML are read LOCAL ONLY. Never output
their content, mount sources, environment, task action args or private paths.
Result is evidence of snapshot consistency, NOT an executable rollback.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'

$cid='571a1e2bede31a07638b896e3ef2de677dafa1c000e4a7975e7996257f8ea162'
$image='sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3'
$launcherSha='55EA1245671C8B656A3BBA944945198350668B2920CD46E36ED7CBA56637317E'
$taskName='HermesH15BRCWindows'

function Deny([string]$Code) {
    Write-Output 'H445_RESTORE_READINESS=HOLD'
    Write-Output ('H445_REASON='+$Code)
    Write-Output 'H445_ROLLBACK_EXECUTION=NOT_TESTED'
    exit 2
}
function Private-File([string]$Path) {
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -lt 1 -or $item.Length -gt 2097152) {
        throw 'PRIVATE_FILE_INVALID'
    }
    return $item
}
function Parse-Json-Array([string]$Data) {
    if ($Data.Length -lt 2 -or $Data.Length -gt 2097152) { throw 'JSON_SIZE' }
    $v=@(ConvertFrom-Json -InputObject $Data -ErrorAction Stop)
    if ($v.Count -ne 1) { throw 'JSON_CARDINALITY' }
    return $v[0]
}
function Compare-Section($A,$B,[string]$Section) {
    $left=ConvertTo-Json -InputObject $A.$Section -Depth 80 -Compress
    $right=ConvertTo-Json -InputObject $B.$Section -Depth 80 -Compress
    if ($left -cne $right) { throw 'SECTION_CHANGED' }
}
try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        Deny 'WINDOWS_REQUIRED'
    }
    $root=[Environment]::GetFolderPath('LocalApplicationData')
    $dir=Join-Path $root 'HermesH445Rollback-20261028'
    $folder=Get-Item -LiteralPath $dir -Force -ErrorAction Stop
    if (-not $folder.PSIsContainer -or
        ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Deny 'BACKUP_DIRECTORY_INVALID'
    }
    $acl=Get-Acl -LiteralPath $dir -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected) { Deny 'BACKUP_DIRECTORY_ACL_WEAK' }
    $me=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach ($rule in $acl.Access) {
        $sid=$rule.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]).Value
        if ($sid -notin @($me,'S-1-5-18','S-1-5-32-544')) {
            Deny 'BACKUP_DIRECTORY_ACL_UNEXPECTED'
        }
    }
    $names=@('launcher.ps1','scheduled-task.xml','container-inspect.json','manifest.json')
    $entries=@(Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop)
    if ($entries.Count -ne 4) { Deny 'BACKUP_CARDINALITY' }
    foreach ($name in $names) {
        $path=Join-Path $dir $name
        Private-File $path | Out-Null
    }
    $manifest=ConvertFrom-Json -InputObject (
        [IO.File]::ReadAllText((Join-Path $dir 'manifest.json')))
    if ($manifest.schema -cne 'h445-owner-local-backup-v1' -or
        $manifest.original_container_id -cne $cid -or
        $manifest.original_image_id -cne $image -or
        $manifest.task_name -cne $taskName -or
        $manifest.rollback_verified -ne $false) {
        Deny 'BACKUP_MANIFEST_IDENTITY'
    }
    foreach ($name in @('launcher.ps1','scheduled-task.xml','container-inspect.json')) {
        $expected=[string]$manifest.document_sha256.PSObject.Properties[$name].Value
        $actual=(Get-FileHash -LiteralPath (Join-Path $dir $name) -Algorithm SHA256).Hash
        if ($actual -cne $expected -or $expected -cnotmatch '^[0-9A-F]{64}$') {
            Deny 'BACKUP_HASH_MISMATCH'
        }
    }
    if ((Get-FileHash -LiteralPath (Join-Path $dir 'launcher.ps1') -Algorithm SHA256).Hash -cne $launcherSha) {
        Deny 'BACKUP_LAUNCHER_DRIFT'
    }
    $saved=Parse-Json-Array ([IO.File]::ReadAllText(
        (Join-Path $dir 'container-inspect.json')))
    if ($saved.Id -cne $cid -or $saved.Image -cne $image -or
        @($saved.Mounts).Count -ne 1) { Deny 'BACKUP_DOCKER_IDENTITY' }
    $docker=Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'
    $binary=Get-Item -LiteralPath $docker -Force -ErrorAction Stop
    if ($binary.PSIsContainer -or ($binary.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Deny 'DOCKER_BINARY_UNTRUSTED'
    }
    $raw=@(& $docker container inspect $cid 2>$null)
    if ($LASTEXITCODE -ne 0) { Deny 'DOCKER_OBSERVATION_FAILED' }
    $live=Parse-Json-Array ($raw -join [Environment]::NewLine)
    if ($live.Id -cne $cid -or $live.Image -cne $image -or
        $live.State.Running -ne $true) { Deny 'LIVE_DOCKER_IDENTITY' }
    Compare-Section $saved $live 'Config'
    Compare-Section $saved $live 'HostConfig'
    Compare-Section $saved $live 'Mounts'
    $savedTask=[IO.File]::ReadAllText((Join-Path $dir 'scheduled-task.xml'))
    $liveTask=Export-ScheduledTask -TaskName $taskName -ErrorAction Stop
    if ($savedTask -cne $liveTask) { Deny 'TASK_CHANGED' }
    # Preservation is not the same as a usable reconstruction recipe.
    # Static evidence of a mount source cannot establish its future accessibility.
    if ([string]::IsNullOrWhiteSpace([string]$saved.Mounts[0].Source) -or
        [string]::IsNullOrWhiteSpace([string]$saved.Mounts[0].Destination)) {
        Deny 'MOUNT_METADATA_MISSING'
    }
    if ($saved.HostConfig.Privileged -ne $false -or
        $saved.Config.User -cne '65534:65534' -or
        [long]$saved.HostConfig.PidsLimit -ne 96 -or
        [long]$saved.HostConfig.Memory -ne 536870912 -or
        $saved.HostConfig.RestartPolicy.Name -cne 'no') {
        Deny 'SECURITY_AND_RESOURCE_CONTRACT'
    }
    if (@($saved.Config.Env).Count -lt 1) { Deny 'ENVIRONMENT_METADATA_MISSING' }
    if (@($saved.Config.Entrypoint).Count -eq 0 -and
        @($saved.Config.Cmd).Count -eq 0) {
        Deny 'ENTRYPOINT_METADATA_MISSING'
    }
    # No current task/container commands or arguments or private data emitted.
    Write-Output 'H445_RESTORE_READINESS=SNAPSHOT_CONSISTENT'
    Write-Output 'H445_BACKUP_HASHES=PASS'
    Write-Output 'H445_SECURITY_RESOURCE_CONTRACT=PASS'
    Write-Output 'H445_TASK_LIVE_MATCH=PASS'
    Write-Output 'H445_CONTAINER_LIVE_MATCH=PASS'
    Write-Output 'H445_MOUNT_REATTACH=NOT_VERIFIED'
    Write-Output 'H445_DEVICE_IDENTITY_REATTACH=NOT_VERIFIED'
    Write-Output 'H445_ROLLBACK_EXECUTION=NOT_TESTED'
    Write-Output 'H445_ORIGINAL_CONTAINER_CHANGED=FALSE'
    exit 0
} catch {
    # NEVER print raw exception; it could contain a local path or secrets.
    Deny 'EVIDENCE_READ_OR_COMPARE_FAILED'
}
