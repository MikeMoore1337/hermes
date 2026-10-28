#requires -Version 5.1
<#
H445 read-only Windows Docker PID capacity diagnostic.
No container changes, host shell, process termination, or secrets.
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
    $unavailable = @{
        process_state_status = 'NOT_VERIFIED'
        visible_zombies = $null
        process_rows = $null
    }
    if ($null -eq $Lines -or $Lines.Count -lt 2 -or $Lines.Count -gt 150 -or
        $Lines[0].Trim() -notmatch '^PID\s+PPID\s+STAT$') {
        return $unavailable
    }
    $zombies = 0
    $rows = 0
    foreach ($line in $Lines | Select-Object -Skip 1) {
        if ($line.Trim() -match '^[0-9]{1,10}\s+[0-9]{1,10}\s+([A-Za-z<+]{1,16})$') {
            $state = $Matches[1]
        } else {
            return $unavailable
        }
        $rows++
        if ($state -cmatch '^Z') { $zombies++ }
    }
    return @{
        process_state_status = 'OBSERVED_WITHOUT_PID1_ATTRIBUTION'
        visible_zombies = $zombies
        process_rows = $rows
    }
}

function Docker-Read([string[]]$Arguments) {
    $binary = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'
    $item = Get-Item -LiteralPath $binary -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'H445_DOCKER_UNTRUSTED'
    }
    $output = @(& $binary @Arguments 2>$null)
    if ($LASTEXITCODE -ne 0 -or $output.Count -gt 150 -or
        (($output -join [Environment]::NewLine).Length -gt 32768)) {
        throw 'H445_DOCKER_READ_FAILED'
    }
    return @($output)
}

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'H445_WINDOWS_REQUIRED'
    }
    $fmt = '{{.Id}}|{{.Name}}|{{.Image}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.Memory}}|{{.Config.User}}'
    $id = @(Docker-Read @('container', 'inspect', '--format', $fmt, $ContainerId))
    if ($id.Count -ne 1) { throw 'H445_TARGET_UNVERIFIED' }
    $parts = $id[0] -split '\|'
    if ($parts.Count -ne 6 -or
        $parts[0] -cne $ContainerId -or
        $parts[1] -cne '/hermes-h15-windows-permanent' -or
        $parts[2] -cne 'sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3' -or
        $parts[3] -cne '96' -or
        $parts[4] -cne '536870912' -or
        $parts[5] -cne '65534:65534') {
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
        # Docker daemon requires the PID field, even for a stat-only query.
        $result = @(Docker-Read @('top', $ContainerId, '-eo', 'pid,ppid,stat'))
        $top = Top-Summary -Lines $result
    } catch {
        # An unsupported top does not erase the real PID pressure.
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
    # No raw Docker stderr, host paths, command lines, or secret values.
    Write-Output '{"schema":"h445-windows-docker-capacity-v1","status":"HOLD","reason":"OBSERVATION_UNAVAILABLE","actions_executed":0,"changes_applied":false}'
    exit 2
}
