#requires -Version 5.1
<#
.SYNOPSIS
  #445 read-only inventory of BRC candidates on the actual Windows Docker host.
.DESCRIPTION
  Discover lists only candidate container names and IDs; Inspect reads strictly
  selected Docker metadata. No docker start/stop/restart/exec/cp, no arbitrary
  shell, environment values, host mount paths, credentials, or changes.
  Inspect does not prove container-to-Hermes-device attribution and cannot
  authorize a Docker cutover. Run in owner's own Windows PowerShell.
#>
[CmdletBinding()]
param(
    [ValidateSet('Discover', 'Inspect')]
    [string]$Mode = 'Discover',
    [string]$ContainerId = ''
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

function Deny([string]$Code) {
    Write-Output ('H445_HOST_INVENTORY=HOLD')
    Write-Output ('H445_REASON=' + $Code)
    exit 2
}

function Invoke-DockerReadOnly([string[]]$Arguments) {
    $docker = Get-Command 'docker.exe' -CommandType Application -ErrorAction Stop
    $output = @(& $docker.Source @Arguments 2>$null)
    if ($LASTEXITCODE -ne 0 -or $output.Count -gt 150 -or
        (($output -join [Environment]::NewLine).Length -gt 32768)) {
        throw 'H445_DOCKER_UNAVAILABLE_OR_OUTPUT_INVALID'
    }
    return @($output)
}

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        Deny 'H445_WINDOWS_REQUIRED'
    }
    if ($Mode -eq 'Discover') {
        if ($ContainerId) { Deny 'H445_DISCOVER_ARGUMENTS_DENIED' }
        $records = @(Invoke-DockerReadOnly @('ps', '-a', '--no-trunc', '--format', '{{.ID}}|{{.Names}}'))
        $candidates = @()
        foreach ($line in $records) {
            $parts = $line -split '\|'
            if ($parts.Count -ne 2 -or
                $parts[0] -cnotmatch '^[a-f0-9]{64}$' -or
                $parts[1] -notmatch '^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$') {
                Deny 'H445_UNTRUSTED_CONTAINER_ROW'
            }
            if ($parts[1] -match '(?i:hermes|brc|h15)') {
                $candidates += @{
                    container_id = $parts[0]
                    container_name = $parts[1]
                    identity_verified = $false
                }
            }
        }
        if ($candidates.Count -gt 16) { Deny 'H445_TOO_MANY_CANDIDATES' }
        $payload = @{
            schema = 'h445-host-docker-inventory-v1'
            status = 'CANDIDATES_NOT_VERIFIED'
            candidates = @($candidates)
            actions_executed = 0
            changes_applied = $false
        }
        Write-Output ($payload | ConvertTo-Json -Depth 5 -Compress)
        exit 0
    }

    # Enforce exact immutable Docker ID. Never accept image refs, names,
    # arguments, wildcards, paths, pipes, or shortened ambiguous IDs.
    if ($ContainerId -cnotmatch '^[a-f0-9]{64}$') {
        Deny 'H445_FULL_CONTAINER_ID_REQUIRED'
    }
    $fmt = '{{.Id}}|{{.Image}}|{{.Name}}|{{.State.Running}}|{{.HostConfig.Init}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.Memory}}|{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.Privileged}}|{{.Config.User}}|{{len .Mounts}}'
    $lines = @(Invoke-DockerReadOnly @('container', 'inspect', '--format', $fmt, $ContainerId))
    if ($lines.Count -ne 1) { Deny 'H445_CONTAINER_INSPECT_FAILED' }
    $part = $lines[0] -split '\|'
    if ($part.Count -ne 11) { Deny 'H445_INSPECT_SCHEMA_DRIFT' }
    $id, $image, $name, $running, $init, $pids, $memory, $readonly, $privileged, $uid, $mounts = $part
    if ($id -cne $ContainerId -or
        $image -cnotmatch '^sha256:[a-f0-9]{64}$' -or
        $name -notmatch '^/[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$' -or
        $running -cnotin @('true', 'false') -or
        $init -cnotin @('true', 'false', '<nil>') -or
        $readonly -cnotin @('true', 'false') -or
        $privileged -cnotin @('true', 'false') -or
        $pids -cnotmatch '^-?[0-9]{1,7}$' -or
        $memory -cnotmatch '^[0-9]{1,15}$' -or
        $mounts -cnotmatch '^[0-9]{1,3}$' -or
        $uid -notmatch '^(65534|nobody|65534:65534|nobody:nogroup)$') {
        Deny 'H445_INSPECT_FIELD_INVALID'
    }
    $pidsNum = [long]::Parse($pids)
    $memoryNum = [long]::Parse($memory)
    $mountsNum = [int]::Parse($mounts)
    if ($mountsNum -gt 20 -or $pidsNum -gt 16384 -or
        $memoryNum -gt 8589934592) {
        Deny 'H445_INSPECT_RESOURCE_OUT_OF_BOUNDS'
    }
    # No environment, binds, actual mount paths, entrypoint, shell args,
    # authorizations, or file contents are ever requested from Docker.
    $payload = @{
        schema = 'h445-host-docker-inventory-v1'
        status = 'HOST_INSPECTED_IDENTITY_NOT_ATTESTED'
        container_id = $id
        container_name = $name.Substring(1)
        image_id = $image
        running = [bool]::Parse($running)
        init = if ($init -eq '<nil>') { 'UNSPECIFIED' } else { $init }
        pids_limit = $pidsNum
        memory_limit_bytes = $memoryNum
        uid = $uid
        read_only_rootfs = [bool]::Parse($readonly)
        privileged = [bool]::Parse($privileged)
        mount_count = $mountsNum
        suspected_process_reaping_risk = ($init -ne 'true')
        target_device_verified = $false
        rollback_verified = $false
        host_change_authorized = $false
        actions_executed = 0
        changes_applied = $false
    }
    Write-Output ($payload | ConvertTo-Json -Depth 5 -Compress)
    exit 0
} catch {
    # Deliberately no raw exception: docker CLI error may include host paths.
    Deny 'H445_DOCKER_INSPECTION_UNAVAILABLE'
}
