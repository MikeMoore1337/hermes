#requires -Version 5.1
<#
H445 owner Windows read-only scheduled-launcher preflight.
Never runs or changes a scheduled task/container, and never outputs the
action arguments, script path/content, Docker env, mount paths or tokens.
A candidate hash and presence indicators are NOT a validated rollback.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$taskName = 'HermesH15BRCWindows'
$cid = '571a1e2bede31a07638b896e3ef2de677dafa1c000e4a7975e7996257f8ea162'
$image = 'sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3'

function Get-FileArgument([string]$Arguments) {
    # Only -File; reject -Command and EncodedCommand. Never evaluate the string.
    if ($Arguments -match '(?i)(?:^|\s)-(?:Command|EncodedCommand|enc)\s') {
        return $null
    }
    $m = [regex]::Match(
        $Arguments,
        '(?i)(?:^|\s)-File\s+(?:"(?<quoted>[^"]{1,512})"|(?<bare>[^\s"]{1,512}))'
    )
    if (-not $m.Success) { return $null }
    if ($m.Groups['quoted'].Success) { return $m.Groups['quoted'].Value }
    return $m.Groups['bare'].Value
}

function Read-Docker([string[]]$Arguments) {
    $binary = Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'
    $file = Get-Item -LiteralPath $binary -Force -ErrorAction Stop
    if ($file.PSIsContainer -or
        ($file.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'UNTRUSTED_DOCKER_BINARY'
    }
    $result = @(& $binary @Arguments 2>$null)
    if ($LASTEXITCODE -ne 0 -or $result.Count -gt 10 -or
        (($result -join [Environment]::NewLine).Length -gt 4096)) {
        throw 'DOCKER_READ_FAILED'
    }
    return @($result)
}

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        throw 'WINDOWS_HOST_REQUIRED'
    }
    $task = Get-ScheduledTask -TaskName $taskName -ErrorAction Stop
    $info = Get-ScheduledTaskInfo -TaskName $taskName -ErrorAction Stop
    $actions = @($task.Actions)
    if ($actions.Count -ne 1 -or
        $task.Principal.LogonType -ne 'Interactive' -or
        $task.State -notin @('Ready', 'Running')) {
        throw 'TASK_CONTRACT_NOT_VERIFIED'
    }
    $leaf = [IO.Path]::GetFileName(([string]$actions[0].Execute).Trim('"'))
    if ($leaf -notin @('powershell.exe', 'pwsh.exe')) {
        throw 'UNEXPECTED_TASK_EXECUTABLE'
    }
    $source = Get-FileArgument -Arguments ([string]$actions[0].Arguments)
    if ([string]::IsNullOrWhiteSpace($source) -or
        -not [IO.Path]::IsPathRooted($source) -or
        $source.StartsWith('\\') -or
        [IO.Path]::GetExtension($source) -ne '.ps1') {
        throw 'TASK_SOURCE_NOT_VERIFIED'
    }
    $script = Get-Item -LiteralPath $source -Force -ErrorAction Stop
    if ($script.PSIsContainer -or
        ($script.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $script.Length -gt 262144 -or $script.Length -lt 1) {
        throw 'TASK_SOURCE_NOT_VERIFIED'
    }
    $sha = (Get-FileHash -LiteralPath $source -Algorithm SHA256 -ErrorAction Stop).Hash
    if ($sha -notmatch '^[A-F0-9]{64}$') { throw 'TASK_SOURCE_HASH_INVALID' }
    $body = [IO.File]::ReadAllText($script.FullName)
    # Indicators are text-only, may match comments, and cannot authorize cutover.
    $usesDocker = [bool]($body -match '(?i)\bdocker(?:\.exe)?\b')
    $mentionsTarget = $body.Contains('hermes-h15-windows-permanent')
    $mentionsInit = [bool]($body -match '(?i)(?:^|\s)--init(?:\s|$)')
    $mentionsPids = $body.Contains('--pids-limit')
    $mentionsRun = [bool]($body -match '(?i)(?:\bdocker(?:\.exe)?\s+run\b|&\s*\$docker\s+run\b)')
    $mentionsVolume = [bool]($body -match '(?i)(?:--mount|--volume|\s-v\s)')
    $mentionsEnv = [bool]($body -match '(?i)(?:--env-file|--env|\s-e\s)')
    $fmt = '{{.Id}}|{{.Name}}|{{.Image}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.Memory}}|{{.Config.User}}|{{.State.Running}}|{{.HostConfig.RestartPolicy.Name}}|{{len .Mounts}}'
    $record = @(Read-Docker @('container', 'inspect', '--format', $fmt, $cid))
    $expectedPrefix = "$cid|/hermes-h15-windows-permanent|$image|96|536870912|65534:65534|true|no|"
    if ($record.Count -ne 1 -or
        -not $record[0].StartsWith($expectedPrefix, [StringComparison]::Ordinal) -or
        $record[0].Substring($expectedPrefix.Length) -notmatch '^[0-9]{1,2}$') {
        throw 'CONTAINER_IDENTITY_NOT_VERIFIED'
    }
    $localImage = @(Read-Docker @('image', 'inspect', '--format', '{{.Id}}', $image))
    $imageAvailable = ($localImage.Count -eq 1 -and $localImage[0] -ceq $image)
    # Never emit source path, task arguments, host mounts or environment.
    $receipt = @{
        schema = 'h445-task-launcher-readonly-v1'
        status = 'OBSERVED_NOT_AUTHORIZED'
        task_name = $taskName
        task_state = [string]$task.State
        task_logon_type = 'Interactive'
        task_last_result = [long]$info.LastTaskResult
        task_last_run_present = ($null -ne $info.LastRunTime)
        task_next_run_present = ($null -ne $info.NextRunTime)
        script_sha256 = $sha
        script_bytes = [long]$script.Length
        script_uses_docker_text = $usesDocker
        script_mentions_target_text = $mentionsTarget
        script_mentions_init_text = $mentionsInit
        script_mentions_pids_limit_text = $mentionsPids
        script_mentions_run_text = $mentionsRun
        script_mentions_volume_text = $mentionsVolume
        script_mentions_env_text = $mentionsEnv
        original_image_available = $imageAvailable
        docker_identity_verified = $true
        mount_count = [int]::Parse($record[0].Substring($expectedPrefix.Length))
        rollback_verified = $false
        restart_authorized = $false
        changes_applied = $false
    }
    Write-Output ($receipt | ConvertTo-Json -Depth 4 -Compress)
    exit 0
} catch {
    # No exception text: errors could disclose local protected paths.
    Write-Output '{"schema":"h445-task-launcher-readonly-v1","status":"HOLD","reason":"READONLY_PREFLIGHT_INCOMPLETE","rollback_verified":false,"restart_authorized":false,"changes_applied":false}'
    exit 2
}
