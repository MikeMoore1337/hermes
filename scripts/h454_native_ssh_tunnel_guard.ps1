#requires -Version 5.1
<#
.SYNOPSIS
  H454 restricted, interactive, bounded SSH loopback recovery for an owner session.
.DESCRIPTION
  No scheduled task, credential persistence, native bridge, device activation,
  host ACL change or auto-start. Inspect is read-only. Run needs an explicit
  owner switch and stops only the ssh.exe process it created. Private key
  passphrase interaction may be required after a reconnect. This is not
  unattended reboot recovery or authorization to re-pair a revoked device.
#>
[CmdletBinding()]
param(
    [ValidateSet('Inspect', 'Run')]
    [string]$Mode = 'Inspect',
    [switch]$OwnerApproved,
    [ValidateRange(2, 30)]
    [int]$MaxMinutes = 20,
    [ValidateRange(0, 3)]
    [int]$Reconnects = 2
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$port = 38183
$sshExe = Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'
$key = Join-Path $env:USERPROFILE '.ssh\hermes_h454_native_read_ed25519'
$hosts = Join-Path $env:USERPROFILE '.ssh\hermes_h454_verified_host_keys'
$forward = '127.0.0.1:38183:172.29.251.2:3000'
$target = 'hermes-h454-forward@111.88.215.204'
$endpoint = 'http://127.0.0.1:38183/health'

function Assert-RegularFile([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'H454_UNTRUSTED_FILE'
    }
}

function Get-LoopbackListeners {
    return @(Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort $port -State Listen -ErrorAction SilentlyContinue)
}

function Test-RelayHealth {
    # Disable environment proxy resolution; only the fixed loopback endpoint.
    $request = [Net.HttpWebRequest][Net.WebRequest]::Create($endpoint)
    $request.Proxy = $null
    $request.Timeout = 4000
    $request.ReadWriteTimeout = 4000
    $request.AllowAutoRedirect = $false
    $response = $null
    $reader = $null
    try {
        $response = [Net.HttpWebResponse]$request.GetResponse()
        if ([int]$response.StatusCode -ne 200 -or
            $response.ContentLength -gt 4096) { return $false }
        $reader = New-Object IO.StreamReader($response.GetResponseStream())
        $body = New-Object char[] 4097
        $count = 0
        do {
            $chunk = $reader.Read($body, $count, 4097 - $count)
            $count += $chunk
        } while ($chunk -gt 0 -and $count -lt 4097)
        if ($count -eq 0 -or $count -gt 4096) { return $false }
        $data = (-join $body[0..($count - 1)]) | ConvertFrom-Json -ErrorAction Stop
        return ($data.ok -eq $true -and $data.version -eq '2.0.2' -and
                $data.devices -ge 3)
    } catch {
        return $false
    } finally {
        if ($null -ne $reader) { $reader.Dispose() }
        if ($null -ne $response) { $response.Dispose() }
    }
}

function Test-OwnListener([int]$ExpectedPid) {
    $listeners = @(Get-LoopbackListeners)
    return ($listeners.Count -eq 1 -and
            [int]$listeners[0].OwningProcess -eq $ExpectedPid)
}

function Test-ExistingTunnel {
    $listeners = @(Get-LoopbackListeners)
    if ($listeners.Count -ne 1) { return $false }
    $pidValue = [int]$listeners[0].OwningProcess
    $process = Get-CimInstance Win32_Process -Filter "ProcessId=$pidValue" -ErrorAction SilentlyContinue
    if ($null -eq $process -or
        -not [string]::Equals($process.ExecutablePath, $sshExe,
            [StringComparison]::OrdinalIgnoreCase) -or
        -not ($process.CommandLine.Contains($forward)) -or
        -not ($process.CommandLine.Contains($target)) -or
        -not ($process.CommandLine.Contains($key)) -or
        -not ($process.CommandLine.Contains($hosts))) { return $false }
    return (Test-RelayHealth)
}

try {
    if ($env:USERNAME -ne 'Mike') {
        throw 'H454_OWNER_WINDOWS_IDENTITY_REQUIRED'
    }
    if ($Mode -eq 'Run' -and -not $OwnerApproved) {
        throw 'H454_EXPLICIT_OWNER_APPROVAL_REQUIRED'
    }
    foreach ($path in @($sshExe, $key, $hosts)) {
        Assert-RegularFile $path
    }

    if ($Mode -eq 'Inspect') {
        if (Test-ExistingTunnel) {
            'H454_NATIVE_SSH_TUNNEL=PASS'
        } else {
            throw 'H454_TUNNEL_NOT_HEALTHY'
        }
    } else {
        # Refuse touching an already bound port (even if it appears to be SSH).
        # Do not kill, attach to, or inherit someone else's local forward.
        if (@(Get-LoopbackListeners).Count -ne 0) {
            throw 'H454_LOCAL_PORT_ALREADY_BOUND'
        }
        $deadline = (Get-Date).AddMinutes($MaxMinutes)
        $started = 0
        $success = $false
        $args = @(
            '-F', 'none', '-N', '-T', '-p', '25566',
            '-L', $forward, '-i', $key,
            '-o', 'IdentitiesOnly=yes',
            '-o', 'PasswordAuthentication=no',
            '-o', 'KbdInteractiveAuthentication=no',
            '-o', 'StrictHostKeyChecking=yes',
            '-o', "UserKnownHostsFile=$hosts",
            '-o', 'ExitOnForwardFailure=yes',
            '-o', 'ForwardAgent=no',
            '-o', 'GatewayPorts=no',
            '-o', 'ConnectTimeout=10',
            '-o', 'ServerAliveInterval=20',
            '-o', 'ServerAliveCountMax=3',
            $target
        )
        # Start-Process joins -ArgumentList with spaces on Windows PowerShell.
        # Quote literal arguments whose pinned paths contain whitespace.
        # Never run the resulting command through a shell evaluator.
        $argv = ($args | ForEach-Object {
            if ($_.Contains('"')) { throw 'H454_SSH_ARGUMENT_REJECTED' }
            if ($_ -match '\s') { '"' + $_ + '"' } else { $_ }
        }) -join ' '
        while ($started -le $Reconnects -and (Get-Date) -lt $deadline) {
            $started++
            if (@(Get-LoopbackListeners).Count -ne 0) {
                throw 'H454_UNOWNED_LISTENER_AFTER_DISCONNECT'
            }
            'H454_SSH_ATTEMPT=' + $started
            $child = $null
            try {
                # Separate process handle: never terminate other ssh instances.
                $child = Start-Process -FilePath $sshExe -ArgumentList $argv -NoNewWindow -PassThru -ErrorAction Stop
                $ready = $false
                $grace = (Get-Date).AddSeconds(90)
                while ((Get-Date) -lt $grace -and (Get-Date) -lt $deadline) {
                    if ($child.HasExited) { break }
                    if ((Test-OwnListener -ExpectedPid $child.Id) -and (Test-RelayHealth)) {
                        $ready = $true
                        break
                    }
                    Start-Sleep -Seconds 2
                }
                if (-not $ready) {
                    'H454_SSH_CONNECTION=HOLD'
                    continue
                }
                'H454_SSH_CONNECTION=PASS'
                $success = $true
                $failures = 0
                while ((Get-Date) -lt $deadline -and -not $child.HasExited) {
                    Start-Sleep -Seconds 5
                    if ((Test-OwnListener -ExpectedPid $child.Id) -and (Test-RelayHealth)) {
                        $failures = 0
                    } else {
                        $failures++
                        if ($failures -ge 3) { break }
                    }
                }
                'H454_SSH_CONNECTION=DISCONNECTED'
            } finally {
                if ($null -ne $child) {
                    $child.Refresh()
                    if (-not $child.HasExited) {
                        $child.Kill()
                        $child.WaitForExit(5000) | Out-Null
                    }
                    $child.Dispose()
                }
            }
            if ((Get-Date) -lt $deadline -and $started -le $Reconnects) {
                Start-Sleep -Seconds 3
            }
        }
        if (-not $success) { throw 'H454_SSH_NEVER_HEALTHY' }
        'H454_SSH_SESSION=CLOSED'
    }
} catch {
    # Whitelisted reasons only. No exception text, credentials or paths.
    $reasons = @('H454_EXPLICIT_OWNER_APPROVAL_REQUIRED',
                 'H454_OWNER_WINDOWS_IDENTITY_REQUIRED',
                 'H454_LOCAL_PORT_ALREADY_BOUND',
                 'H454_UNOWNED_LISTENER_AFTER_DISCONNECT',
                 'H454_TUNNEL_NOT_HEALTHY',
                 'H454_SSH_NEVER_HEALTHY',
                 'H454_SSH_ARGUMENT_REJECTED',
                 'H454_UNTRUSTED_FILE')
    $reason = 'H454_UNEXPECTED_ERROR'
    if ($reasons -contains $_.Exception.Message) {
        $reason = $_.Exception.Message
    }
    'H454_NATIVE_SSH_TUNNEL=REFUSED'
    'H454_REASON=' + $reason
    throw 'H454_TUNNEL_OPERATOR_FAILED'
}
