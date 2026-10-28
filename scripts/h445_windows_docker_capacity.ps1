#requires -Version 5.1
<#
H445 read-only Windows Docker container PID-pressure diagnostic.
No Docker exec, host ps, file/environment reads, restarts, writes, or
session termination. An unavailable top result never masks Docker stats.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidatePattern('^[a-f0-9]{64}$')]
    [string]$ContainerId
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Top-Summary([string[]]$Lines) {
    $no = @{
        process_state_status = 'NOT_VERIFIED'
        visible_zombies = $null
        process_rows = $null
    }
    if ($null -eq $Lines -or $Lines.Count -lt 2 -or $Lines.Count -gt 150) {
        return $no
    }
    if ($Lines[0].Trim() -notmatch '^PID\s+PPID\s+STAT$') {
        return $no
    }
    $n = 0
    $z = 0
    foreach ($row in $Lines | Select-Object -Skip 1) {
        if ($row.Trim() -match '^[0-9]{1,10}\s+[0-9]{1,10}\s+([A-Za-z<+]{1,16})
    }
    return @{
        process_state_status = 'OBSERVED_WITHOUT_PID1_ATTRIBUTION'
        visible_zombies = $z
        process_rows = $n
    }
}

function Docker-Read([string[]]$Arguments) {
    $binary = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'
    $item = Get-Item -LiteralPath $binary -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'H445_DOCKER_UNTRUSTED'
    }
    $result = @(& $binary @Arguments 2>$null)
    if ($LASTEXITCODE -ne 0 -or $result.Count -gt 150 -or
        (($result -join [Environment]::NewLine).Length -gt 32768)) {
        throw 'H445_DOCKER_READ_FAILED'
    }
    return @($result)
}

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'H445_WINDOWS_REQUIRED'
    }
    # This exact full ID was discovered on the owner's Windows host.
    # Bind to the specific name and recorded image/resource/UID contract.
    $format = '{{.Id}}|{{.Name}}|{{.Image}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.Memory}}|{{.Config.User}}'
    $ident = @(Docker-Read @('container', 'inspect', '--format', $format, $ContainerId))
    if ($ident.Count -ne 1) { throw 'H445_TARGET_UNVERIFIED' }
    $items = $ident[0] -split '\|'
    if ($items.Count -ne 6 -or
        $items[0] -cne $ContainerId -or
        $items[1] -cne '/hermes-h15-windows-permanent' -or
        $items[2] -cne 'sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3' -or
        $items[3] -cne '96' -or
        $items[4] -cne '536870912' -or
        $items[5] -cne '65534:65534') {
        throw 'H445_TARGET_UNVERIFIED'
    }
    $stats = @(Docker-Read @('stats', '--no-stream', '--format', '{{.PIDs}}', $ContainerId))
    if ($stats.Count -ne 1 -or $stats[0].Trim() -cnotmatch '^[0-9]{1,5}$') {
        throw 'H445_STATS_UNAVAILABLE'
    }
    $pids = [int]::Parse($stats[0].Trim())
    $top = @{
        process_state_status = 'NOT_VERIFIED'
        visible_zombies = $null
        process_rows = $null
    }
    try {
        # Docker daemon explicitly REQUIRES a PID column in ps output.
        $rows = @(Docker-Read @('top', $ContainerId, '-eo', 'pid,ppid,stat'))
        $top = Top-Summary -Lines $rows
    } catch {
        # Unsupported Docker ps flags are not proof of no zombie processes.
    }
    $headroom = [Math]::Max(0, 96 - $pids)
    $status = if ($headroom -lt 24) { 'HOLD' } else { 'CAPACITY_OBSERVED_NOT_AUTHORIZED' }
    $receipt = @{
        schema = 'h445-windows-docker-capacity-v1'
        status = $status
        pids_current = $pids
        pids_max = 96
        pids_headroom = $headroom
        process_state_status = $top.process_state_status
        visible_zombies = $top.visible_zombies
        process_rows = $top.process_rows
        pid1_reaper_verified = $false
        rollback_verified = $false
        host_change_authorized = $false
        actions_executed = 0
        changes_applied = $false
    }
    Write-Output ($receipt | ConvertTo-Json -Compress)
    if ($status -eq 'HOLD') { exit 2 }
    exit 0
} catch {
    # No raw exceptions, Docker stderr, host paths, or secrets.
    Write-Output '{"schema":"h445-windows-docker-capacity-v1","status":"HOLD","reason":"OBSERVATION_UNAVAILABLE","actions_executed":0,"changes_applied":false}'
    exit 2
}
) {
            $state = $Matches[1]
        } else {
            return $no
        }
        $n++
        if ($state -cmatch '^Z') { $z++ }
    }
    return @{
        process_state_status = 'OBSERVED_WITHOUT_PID1_ATTRIBUTION'
        visible_zombies = $z
        process_rows = $n
    }
}

function Docker-Read([string[]]$Arguments) {
    $binary = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'
    $item = Get-Item -LiteralPath $binary -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'H445_DOCKER_UNTRUSTED'
    }
    $result = @(& $binary @Arguments 2>$null)
    if ($LASTEXITCODE -ne 0 -or $result.Count -gt 150 -or
        (($result -join [Environment]::NewLine).Length -gt 32768)) {
        throw 'H445_DOCKER_READ_FAILED'
    }
    return @($result)
}

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'H445_WINDOWS_REQUIRED'
    }
    # This exact full ID was discovered on the owner's Windows host.
    # Bind to the specific name and recorded image/resource/UID contract.
    $format = '{{.Id}}|{{.Name}}|{{.Image}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.Memory}}|{{.Config.User}}'
    $ident = @(Docker-Read @('container', 'inspect', '--format', $format, $ContainerId))
    if ($ident.Count -ne 1) { throw 'H445_TARGET_UNVERIFIED' }
    $items = $ident[0] -split '\|'
    if ($items.Count -ne 6 -or
        $items[0] -cne $ContainerId -or
        $items[1] -cne '/hermes-h15-windows-permanent' -or
        $items[2] -cne 'sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3' -or
        $items[3] -cne '96' -or
        $items[4] -cne '536870912' -or
        $items[5] -cne '65534:65534') {
        throw 'H445_TARGET_UNVERIFIED'
    }
    $stats = @(Docker-Read @('stats', '--no-stream', '--format', '{{.PIDs}}', $ContainerId))
    if ($stats.Count -ne 1 -or $stats[0].Trim() -cnotmatch '^[0-9]{1,5}$') {
        throw 'H445_STATS_UNAVAILABLE'
    }
    $pids = [int]::Parse($stats[0].Trim())
    $top = @{
        process_state_status = 'NOT_VERIFIED'
        visible_zombies = $null
        process_rows = $null
    }
    try {
        # Docker daemon explicitly REQUIRES a PID column in ps output.
        $rows = @(Docker-Read @('top', $ContainerId, '-eo', 'pid,ppid,stat'))
        $top = Top-Summary -Lines $rows
    } catch {
        # Unsupported Docker ps flags are not proof of no zombie processes.
    }
    $headroom = [Math]::Max(0, 96 - $pids)
    $status = if ($headroom -lt 24) { 'HOLD' } else { 'CAPACITY_OBSERVED_NOT_AUTHORIZED' }
    $receipt = @{
        schema = 'h445-windows-docker-capacity-v1'
        status = $status
        pids_current = $pids
        pids_max = 96
        pids_headroom = $headroom
        process_state_status = $top.process_state_status
        visible_zombies = $top.visible_zombies
        process_rows = $top.process_rows
        pid1_reaper_verified = $false
        rollback_verified = $false
        host_change_authorized = $false
        actions_executed = 0
        changes_applied = $false
    }
    Write-Output ($receipt | ConvertTo-Json -Compress)
    if ($status -eq 'HOLD') { exit 2 }
    exit 0
} catch {
    # No raw exceptions, Docker stderr, host paths, or secrets.
    Write-Output '{"schema":"h445-windows-docker-capacity-v1","status":"HOLD","reason":"OBSERVATION_UNAVAILABLE","actions_executed":0,"changes_applied":false}'
    exit 2
}
