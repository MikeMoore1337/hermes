"""Prepare a pinned launcher that retains its verified container on restart.

This is a source-only preparation tool. It never installs or runs a launcher,
starts a task, opens Docker, reads credentials, or authorizes a cutover.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import sys

from scripts.h454_windows_launcher_patch import RUN, RUN_END, PatchRefused

SOURCE_SHA256 = "ffa184e07abde9c6f7a7367e75cef4f313986c4a68ca1ab8aabd60f14d2f0ef1"

HELPERS = r"""    # Keep the verified container across task retries and logons.
    $script:h454ExpectedProfile = '__PROFILE_SHA256__'
    $script:h454ExpectedImage = '__IMAGE_ID__'
    $script:h454TunnelNeedle = '__TUNNEL_NEEDLE__'
    $script:h454ContainerId = $null
    $script:h454OriginalTunnel = $null
    $script:h454DockerHost = 'npipe:////./pipe/dockerDesktopLinuxEngine'
    $script:h454Docker = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Docker\Docker\resources\bin\docker.exe'
    $script:h454SshExe = Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\ssh.exe'
    Require (Test-Path -LiteralPath $script:h454Docker -PathType Leaf) 'H454_DOCKER_NOT_FOUND'
    Require (Test-Path -LiteralPath $script:h454SshExe -PathType Leaf) 'H454_SSH_NOT_FOUND'
    foreach ($h454Executable in @($script:h454Docker, $script:h454SshExe)) {
        $h454Path = $h454Executable
        while (-not [string]::IsNullOrEmpty($h454Path)) {
            Require (-not ((Get-Item -LiteralPath $h454Path -Force).Attributes -band
                [IO.FileAttributes]::ReparsePoint)) 'H454_EXECUTABLE_REPARSE'
            $h454Parent = [IO.Path]::GetDirectoryName($h454Path)
            if ($h454Parent -ceq $h454Path) { break }
            $h454Path = $h454Parent
        }
    }
    foreach ($h454Key in @('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH')) {
        Require ([string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($h454Key, 'Process'))) 'H454_DOCKER_OVERRIDE'
    }
    function Invoke-H454Docker([string[]]$Arguments) {
        $ErrorActionPreference = 'SilentlyContinue'
        $global:LASTEXITCODE = -1
        try {
            $h454Lines = @(& $script:h454Docker @Arguments 2>$null)
            $h454Code = $LASTEXITCODE
        } catch { $h454Lines = @(); $h454Code = -1 }
        return [pscustomobject]@{Code=$h454Code;Lines=$h454Lines}
    }
    function Assert-H454PrivateState([string]$Path) {
        Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
        Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
        $h454Item = Get-Item -LiteralPath $Path -Force
        $h454Dir = $h454Item.Directory
        $h454Parent = $h454Item
        while ($null -ne $h454Parent) {
            Require (-not ($h454Parent.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'H454_STATE_REPARSE'
            if ($h454Parent -is [IO.FileInfo]) { $h454Parent = $h454Parent.Directory }
            else { $h454Parent = $h454Parent.Parent }
        }
        $h454Allowed = @([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
        Require ((Get-Acl -LiteralPath $h454Dir.FullName).AreAccessRulesProtected) 'H454_STATE_ACL_INHERITANCE'
        foreach ($h454Target in @($Path,$h454Dir.FullName)) {
            $h454OwnerFound = $false
            foreach ($h454Rule in (Get-Acl -LiteralPath $h454Target).Access) {
                $h454Sid = $h454Rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
                Require ($h454Sid -in $h454Allowed) 'H454_STATE_ACL'
                if ($h454Sid -ceq $h454Allowed[0] -and $h454Rule.AccessControlType -eq 'Allow') { $h454OwnerFound = $true }
            }
            Require $h454OwnerFound 'H454_STATE_OWNER_ACL'
        }
    }
    function Save-H454State([string]$ExpectedHash,[object]$Value) {
        Require ($ExpectedHash -cmatch '^[A-F0-9]{64}$') 'H454_STATE_HASH_INVALID'
        Assert-H454PrivateState $STATE_PATH
        $h454Dir = [IO.Path]::GetDirectoryName($STATE_PATH)
        $h454Name = 'agent-state-h454-' + [Guid]::NewGuid().ToString('N')
        $h454Pending = Join-Path $h454Dir ($h454Name + '.new')
        $h454Backup = Join-Path $h454Dir ($h454Name + '.bak')
        Require (-not (Test-Path -LiteralPath $h454Pending) -and -not (Test-Path -LiteralPath $h454Backup)) 'H454_STATE_TEMP_COLLISION'
        $h454Bytes = [Text.UTF8Encoding]::new($false).GetBytes(($Value | ConvertTo-Json))
        $h454Sha = [Security.Cryptography.SHA256]::Create()
        try { $h454NewHash = [BitConverter]::ToString($h454Sha.ComputeHash($h454Bytes)).Replace('-', '') }
        finally { $h454Sha.Dispose() }
        $h454Stream = $null; $h454Committed = $false
        try {
            $h454Stream = [IO.File]::Open($h454Pending,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
            $h454Stream.Write($h454Bytes,0,$h454Bytes.Length); $h454Stream.Flush($true)
            $h454Stream.Dispose(); $h454Stream = $null
            Assert-H454PrivateState $h454Pending
            Require ((Get-FileHash -LiteralPath $h454Pending).Hash -ceq $h454NewHash -and
                (Get-FileHash -LiteralPath $STATE_PATH).Hash -ceq $ExpectedHash) 'H454_STATE_DRIFT'
            [IO.File]::Replace($h454Pending,$STATE_PATH,$h454Backup)
            $h454Committed = $true
            Assert-H454PrivateState $STATE_PATH
            Assert-H454PrivateState $h454Backup
            Require ((Get-FileHash -LiteralPath $STATE_PATH).Hash -ceq $h454NewHash -and
                (Get-FileHash -LiteralPath $h454Backup).Hash -ceq $ExpectedHash) 'H454_STATE_COMMIT_DRIFT'
            try { [IO.File]::Delete($h454Backup) } catch { Write-Warning 'H454_STATE_BACKUP_RETAINED' }
        } finally {
            if ($null -ne $h454Stream) { $h454Stream.Dispose() }
            if (-not $h454Committed -and (Test-Path -LiteralPath $h454Pending)) {
                try {
                    Assert-H454PrivateState $h454Pending
                    if ((Get-FileHash -LiteralPath $h454Pending).Hash -ceq $h454NewHash) { [IO.File]::Delete($h454Pending) }
                    else { Write-Warning 'H454_STATE_TEMP_RETAINED' }
                } catch { Write-Warning 'H454_STATE_TEMP_RETAINED' }
            }
        }
    }
    function Assert-H454ExistingTunnel {
        $h454PidField = $state.PSObject.Properties['tunnelPid']
        Require ($null -ne $h454PidField -and ($h454PidField.Value -is [int] -or
            $h454PidField.Value -is [long]) -and $h454PidField.Value -ge 0 -and
            $h454PidField.Value -le [int]::MaxValue) 'H454_TUNNEL_PID_INVALID'
        $h454Pid = [int]$h454PidField.Value
        $h454CreatedField = $state.PSObject.Properties['tunnelCreatedUtcTicks']
        if ($null -ne $h454CreatedField) {
            Require (($h454CreatedField.Value -is [int] -or $h454CreatedField.Value -is [long]) -and
                $h454CreatedField.Value -gt 0 -and $h454CreatedField.Value -le [DateTime]::MaxValue.Ticks -and
                $h454Pid -gt 0) 'H454_TUNNEL_CREATION_INVALID'
        }
        $h454NetErrors = @()
        $h454Listeners = @(Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 38180 -State Listen `
            -ErrorAction SilentlyContinue -ErrorVariable +h454NetErrors)
        foreach ($h454Error in $h454NetErrors) {
            Require ($h454Error.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) 'H454_TUNNEL_LISTENER_QUERY'
        }
        Require ($h454Listeners.Count -le 1) 'H454_TUNNEL_LISTENER_CONFLICT'
        if ($h454Pid -eq 0) {
            Require ($h454Listeners.Count -eq 0) 'H454_TUNNEL_LISTENER_CONFLICT'
            return
        }
        try { $h454Processes = @(Get-CimInstance Win32_Process -Filter ('ProcessId=' + $h454Pid) -ErrorAction Stop) }
        catch { throw 'H454_TUNNEL_PROCESS_QUERY' }
        Require ($h454Processes.Count -le 1) 'H454_TUNNEL_PROCESS_QUERY'
        if ($h454Processes.Count -eq 0) {
            Require ($h454Listeners.Count -eq 0) 'H454_TUNNEL_LISTENER_CONFLICT'
            return
        }
        Require ($h454Listeners.Count -eq 0 -or [int]$h454Listeners[0].OwningProcess -eq $h454Pid) 'H454_TUNNEL_LISTENER_CONFLICT'
        $h454Tunnel = $h454Processes[0]
        if ($null -ne $h454CreatedField) {
            # shortcut: same-user state tampering can forge identity; require OS-bound state if trust expands.
            $h454Probe = $null
            try {
                $h454Probe = Get-Process -Id $h454Pid -ErrorAction Stop
                $null = $h454Probe.Handle
                $h454ActualTicks = $h454Probe.StartTime.ToUniversalTime().Ticks
                $h454CimTicks = ([DateTime]$h454Tunnel.CreationDate).ToUniversalTime().Ticks
                Require ([Math]::Abs($h454ActualTicks - $h454CimTicks) -le 10) 'H454_TUNNEL_PID_REUSED'
                if ($h454ActualTicks -ne [long]$h454CreatedField.Value) {
                    Require ($h454Listeners.Count -eq 0) 'H454_TUNNEL_LISTENER_CONFLICT'
                    $h454RetryErrors = @()
                    $h454Retry = @(Get-NetTCPConnection -LocalAddress '127.0.0.1' -LocalPort 38180 -State Listen `
                        -ErrorAction SilentlyContinue -ErrorVariable +h454RetryErrors)
                    foreach ($h454Error in $h454RetryErrors) {
                        Require ($h454Error.CategoryInfo.Category -eq [Management.Automation.ErrorCategory]::ObjectNotFound) 'H454_TUNNEL_LISTENER_QUERY'
                    }
                    Require ($h454Retry.Count -eq 0) 'H454_TUNNEL_LISTENER_CONFLICT'
                    return
                }
            } catch { throw 'H454_TUNNEL_PROCESS_IDENTITY' }
            finally { if ($null -ne $h454Probe) { $h454Probe.Dispose() } }
        }
        $h454Command = [string]$h454Tunnel.CommandLine
        Require ($h454Tunnel.Name -ieq 'ssh.exe' -and
            [string]::Equals([string]$h454Tunnel.ExecutablePath, $script:h454SshExe, [StringComparison]::OrdinalIgnoreCase) -and
            -not [string]::IsNullOrEmpty($h454Command) -and -not [string]::IsNullOrEmpty($TUNNEL_TARGET) -and
            $h454Command.Contains($TUNNEL_TARGET) -and $h454Command.Contains($script:h454TunnelNeedle)) 'H454_TUNNEL_IDENTITY_UNAVAILABLE'
        $h454Process = $null
        try {
            $h454Process = Get-Process -Id $h454Pid -ErrorAction Stop
            $null = $h454Process.Handle
            $h454Start = $h454Process.StartTime.ToUniversalTime()
            $h454CimStart = ([DateTime]$h454Tunnel.CreationDate).ToUniversalTime()
            $h454StateTime = (Get-Item -LiteralPath $STATE_PATH -Force).LastWriteTimeUtc
            Require ($h454Start -le $h454StateTime -and
                [Math]::Abs($h454Start.Ticks - $h454CimStart.Ticks) -le 10) 'H454_TUNNEL_PID_REUSED'
            $script:h454OriginalTunnel = $h454Process
        } catch {
            if ($null -ne $h454Process) { $h454Process.Dispose() }
            throw 'H454_TUNNEL_PROCESS_IDENTITY'
        }
    }
    function Stop-H454TunnelHandle([object]$Process) {
        if ($null -eq $Process) { return }
        try {
            if (-not $Process.HasExited) {
                try { $Process.Kill() }
                catch { if (-not $Process.HasExited) { throw 'H454_TUNNEL_STOP_FAILED' } }
            }
            Require ($Process.WaitForExit(5000)) 'H454_TUNNEL_STOP_FAILED'
        } finally { $Process.Dispose() }
    }
    function Stop-H454ExistingTunnel {
        try { Stop-H454TunnelHandle $script:h454OriginalTunnel }
        finally { $script:h454OriginalTunnel = $null }
    }
    function Get-H454ContainerProfileHash([object]$h454Item) {
        $h454Mac = $h454Item.Config.PSObject.Properties['MacAddress']
        Require ($h454Item.Id -cmatch '^[a-f0-9]{64}$' -and
            $h454Item.Config.Hostname -ceq $h454Item.Id.Substring(0, 12) -and
            [string]::IsNullOrEmpty($h454Item.Config.Domainname) -and
            ($null -eq $h454Mac -or [string]::IsNullOrEmpty($h454Mac.Value)) -and
            $h454Item.Config.AttachStdout -is [bool] -and $h454Item.Config.AttachStderr -is [bool]) 'H454_CONFIG_IDENTITY'
        $h454Config = [ordered]@{}
        foreach ($h454Prop in @($h454Item.Config.PSObject.Properties | Sort-Object Name)) {
            if ($h454Prop.Name -cnotin @('Hostname','Domainname','MacAddress','Image','AttachStdout','AttachStderr')) {
                if ($h454Prop.Name -ceq 'Labels' -and $null -ne $h454Prop.Value) {
                    # Docker labels are a map; their order is not part of the profile.
                    [string[]]$h454LabelNames = @($h454Prop.Value.PSObject.Properties | ForEach-Object { $_.Name })
                    [Array]::Sort($h454LabelNames, [StringComparer]::Ordinal)
                    $h454Labels = [ordered]@{}
                    foreach ($h454LabelName in $h454LabelNames) {
                        $h454Labels[$h454LabelName] = $h454Prop.Value.PSObject.Properties[$h454LabelName].Value
                    }
                    $h454Config[$h454Prop.Name] = $h454Labels
                } else {
                    $h454Config[$h454Prop.Name] = $h454Prop.Value
                }
            }
        }
        $h454Host = [ordered]@{}
        $h454Oom = $h454Item.HostConfig.PSObject.Properties['OomKillDisable']
        Require ($null -ne $h454Oom -and ($null -eq $h454Oom.Value -or
            ($h454Oom.Value -is [bool] -and -not $h454Oom.Value))) 'H454_OOM_UNSAFE'
        foreach ($h454Prop in @($h454Item.HostConfig.PSObject.Properties | Sort-Object Name)) {
            if ($h454Prop.Name -ceq 'OomKillDisable') { $h454Host[$h454Prop.Name] = $false }
            else { $h454Host[$h454Prop.Name] = $h454Prop.Value }
        }
        $h454Mounts = @(foreach ($h454Mount in $h454Item.Mounts) {
            if ($h454Mount.Type -cne 'tmpfs') {
                $h454Selected = [ordered]@{}
                foreach ($h454Name in @('Type','Name','Source','Destination','Driver','Mode','RW','Propagation')) {
                    $h454Field = $h454Mount.PSObject.Properties[$h454Name]
                    $h454Selected[$h454Name] = if ($null -eq $h454Field) { $null } else { $h454Field.Value }
                }
                $h454Selected
            }
        })
        $h454Networks = @($h454Item.NetworkSettings.Networks.PSObject.Properties | ForEach-Object { $_.Name } | Sort-Object)
        $h454Packet = [ordered]@{Config=$h454Config;HostConfig=$h454Host;Mounts=$h454Mounts;Networks=$h454Networks}
        $h454Bytes = [Text.Encoding]::UTF8.GetBytes((ConvertTo-Json -InputObject $h454Packet -Depth 80 -Compress))
        $h454Sha = [Security.Cryptography.SHA256]::Create()
        try { return [BitConverter]::ToString($h454Sha.ComputeHash($h454Bytes)).Replace('-', '') }
        finally { $h454Sha.Dispose() }
    }
    function Get-H454PreservedContainer {
        Require ($state.imageId -ceq $script:h454ExpectedImage) 'H454_STATE_IMAGE_DRIFT'
        $h454Result = Invoke-H454Docker -Arguments @('--host',$script:h454DockerHost,'container','inspect',$CONTAINER)
        if ($h454Result.Code -ne 0) {
            $h454Names = Invoke-H454Docker -Arguments @('--host',$script:h454DockerHost,'container','ls','--all','--format','{{.Names}}')
            Require ($h454Names.Code -eq 0 -and $h454Names.Lines -cnotcontains $CONTAINER) 'H454_CONTAINER_INSPECT_FAILED'
            return $null
        }
        try { $h454Parsed = ($h454Result.Lines -join "`n") | ConvertFrom-Json }
        catch { throw 'H454_CONTAINER_INSPECT_JSON' }
        if ($h454Parsed -is [array]) {
            Require ($h454Parsed.Count -eq 1) 'H454_CONTAINER_COUNT'
            $h454Item = $h454Parsed[0]
        } else { $h454Item = $h454Parsed }
        Require ($null -ne $h454Item -and $h454Item.Id -cmatch '^[a-f0-9]{64}$' -and
            $h454Item.Name -ceq ('/' + $CONTAINER) -and $h454Item.Image -ceq $script:h454ExpectedImage -and
            $h454Item.State.Running -is [bool]) 'H454_CONTAINER_IDENTITY'
        Require ((Get-H454ContainerProfileHash $h454Item) -ceq $script:h454ExpectedProfile) 'H454_CONTAINER_PROFILE_DRIFT'
        return $h454Item
    }
    function Stop-H454PreservedContainer([switch]$Claim) {
        if (-not $Claim -and $null -eq $script:h454ContainerId) { return }
        if ($Claim) { Require ($null -eq $script:h454ContainerId) 'H454_CONTAINER_ALREADY_CLAIMED' }
        $h454Item = Get-H454PreservedContainer
        if ($null -eq $h454Item) {
            Require ($Claim -and $null -eq $script:h454ContainerId) 'H454_CONTAINER_DISAPPEARED'
            return
        }
        if ($null -ne $script:h454ContainerId) {
            Require ($h454Item.Id -ceq $script:h454ContainerId) 'H454_CONTAINER_ID_DRIFT'
        }
        $script:h454ContainerId = [string]$h454Item.Id
        if ($h454Item.State.Running) {
            $h454Result = Invoke-H454Docker -Arguments @('--host',$script:h454DockerHost,'container','stop','--time','20',$script:h454ContainerId)
            Require ($h454Result.Code -eq 0) 'H454_CONTAINER_STOP_FAILED'
        }
    }
    function Start-H454PreservedContainer {
        if ($null -eq $script:h454ContainerId) { return $false }
        $h454Item = Get-H454PreservedContainer
        Require ($null -ne $h454Item -and $h454Item.Id -ceq $script:h454ContainerId -and
            -not $h454Item.State.Running) 'H454_CONTAINER_RESTART_DRIFT'
        $h454Result = Invoke-H454Docker -Arguments @('--host',$script:h454DockerHost,'container','start',$script:h454ContainerId)
        Require ($h454Result.Code -eq 0) 'H454_CONTAINER_START_FAILED'
        return $true
    }
    function Assert-H454PreservedStarted {
        $h454Item = Get-H454PreservedContainer
        Require ($null -ne $script:h454ContainerId -and $null -ne $h454Item -and
            $h454Item.Id -ceq $script:h454ContainerId -and $h454Item.State.Running) 'H454_CONTAINER_NOT_RUNNING'
    }
"""


def prepare(source: bytes, profile_sha256: str, image_id: str) -> bytes:
    if hashlib.sha256(source).hexdigest() != SOURCE_SHA256:
        raise PatchRefused("SOURCE_HASH_MISMATCH")
    if re.fullmatch(r"[A-Fa-f0-9]{64}", profile_sha256) is None:
        raise PatchRefused("PROFILE_HASH_INVALID")
    if re.fullmatch(r"sha256:[a-f0-9]{64}", image_id) is None:
        raise PatchRefused("IMAGE_ID_INVALID")
    bom = source.startswith(b"\xef\xbb\xbf")
    text = source.decode("utf-8-sig")
    newline = "\r\n" if "\r\n" in text else "\n"
    text = text.replace("\r\n", "\n")
    tunnel = "function Stop-TunnelByPid("
    if text.count(tunnel) != 1:
        raise PatchRefused("SOURCE_STRUCTURE_MISMATCH")
    tunnel_start = text.index(tunnel)
    tunnel_end = text.find("\n}", tunnel_start)
    if tunnel_end == -1:
        raise PatchRefused("SOURCE_STRUCTURE_MISMATCH")
    needles = re.findall(r"\$cmd\.Contains\('([^']+)'\)", text[tunnel_start:tunnel_end])
    if (len(needles) != 1 or not re.fullmatch(r"[A-Za-z0-9.:/_-]{1,160}", needles[0])
            or "38180" not in needles[0]):
        raise PatchRefused("SOURCE_STRUCTURE_MISMATCH")
    if text.count(RUN) != 1 or text.count(RUN_END) != 1:
        raise PatchRefused("SOURCE_STRUCTURE_MISMATCH")
    start = text.index(RUN) + len(RUN)
    end = text.index(RUN_END, start)
    block = text[start:end]
    state_read = "$state = Get-Content -LiteralPath $STATE_PATH -Raw | ConvertFrom-Json"
    state_write = "[IO.File]::WriteAllText($STATE_PATH,($state | ConvertTo-Json),[Text.UTF8Encoding]::new($false))"
    state_pid = "$state.tunnelPid = $SSH_PROCESS.Id"
    if block.count(state_read) != 1 or block.count(state_write) != 1 or block.count(state_pid) != 1:
        raise PatchRefused("SOURCE_STRUCTURE_MISMATCH")
    block = block.replace(state_read, "Assert-H454PrivateState $STATE_PATH\n    $h454StateHash = (Get-FileHash -LiteralPath $STATE_PATH).Hash\n    "
                          + state_read + "\n    Require ((Get-FileHash -LiteralPath $STATE_PATH).Hash -ceq $h454StateHash) 'H454_STATE_READ_DRIFT'", 1)
    block = block.replace(state_write, "Save-H454State $h454StateHash $state", 1)
    pid_pos = block.index(state_pid)
    pid_indent = block[block.rfind("\n", 0, pid_pos) + 1:pid_pos]
    if not pid_indent or pid_indent.strip():
        raise PatchRefused("SOURCE_STRUCTURE_MISMATCH")
    block = block.replace(state_pid, state_pid + "\n" + pid_indent +
        "$state | Add-Member -MemberType NoteProperty -Name tunnelCreatedUtcTicks "
        "-Value ([long]$SSH_PROCESS.StartTime.ToUniversalTime().Ticks) -Force", 1)
    old_tunnel = "Stop-TunnelByPid ([int]$state.tunnelPid)"
    start_ssh = "$SSH_PROCESS = Start-Process -FilePath 'ssh.exe' -ArgumentList $sshArgs -PassThru -WindowStyle Hidden"
    cleanup_ssh = ("        if ($SSH_PROCESS -and -not $SSH_PROCESS.HasExited) {\n"
                   "            Stop-TunnelByPid $SSH_PROCESS.Id\n        }")
    if (block.count("Stop-OwnedContainer") != 2 or block.count("& docker.exe") != 5
            or block.count("& docker.exe run") != 1 or block.count("Assert-ManagedContainer") != 1):
        raise PatchRefused("SOURCE_STRUCTURE_MISMATCH")
    if any(block.count(item) != 1 for item in (old_tunnel, start_ssh, cleanup_ssh)):
        raise PatchRefused("SOURCE_STRUCTURE_MISMATCH")
    stop = block.index("Stop-OwnedContainer")
    stop_indent = block[block.rfind("\n", 0, stop) + 1:stop]
    if not stop_indent or stop_indent.strip():
        raise PatchRefused("SOURCE_STRUCTURE_MISMATCH")
    block = block.replace("Stop-OwnedContainer", "Assert-H454ExistingTunnel\n" + stop_indent + "Stop-H454PreservedContainer -Claim", 1)
    block = block.replace("Stop-OwnedContainer", "Stop-H454PreservedContainer")
    block = block.replace(old_tunnel, "Stop-H454ExistingTunnel", 1)
    block = block.replace(start_ssh, start_ssh.replace("'ssh.exe'", "$script:h454SshExe") + "\n        $null = $SSH_PROCESS.Handle", 1)
    block = block.replace(cleanup_ssh, ("        if ($null -ne $script:h454OriginalTunnel) {\n"
        "            $script:h454OriginalTunnel.Dispose()\n            $script:h454OriginalTunnel = $null\n        }\n"
        "        Stop-H454TunnelHandle $SSH_PROCESS"), 1)
    block = block.replace("Assert-ManagedContainer", "Assert-H454PreservedStarted")
    block = block.replace("& docker.exe", "& $script:h454Docker --host $script:h454DockerHost")
    marker = "& $script:h454Docker --host $script:h454DockerHost run"
    pos = block.index(marker)
    end_pipeline = block.find("| Out-Null", pos)
    if end_pipeline == -1:
        raise PatchRefused("SOURCE_STRUCTURE_MISMATCH")
    end_pipeline += len("| Out-Null")
    indent = block[block.rfind("\n", 0, pos) + 1:pos]
    if not indent or indent.strip():
        raise PatchRefused("SOURCE_STRUCTURE_MISMATCH")
    original = block[pos:end_pipeline - len("| Out-Null")]
    detach = r"(?<!\S)--detach(?=\s|`|$)"
    if (len(re.findall(detach, original)) != 1 or re.search(r"(?<!\S)--rm(?=\s|`|$)", original)
            or not re.search(r"(?<!\S)--pull(?:=|\s+)never(?=\s|`|$)", original)):
        raise PatchRefused("SOURCE_STRUCTURE_MISMATCH")
    create = re.sub(detach, "", original, count=1).replace(marker, marker.replace(" run", " container create"), 1)
    wrapped = ("if (-not (Start-H454PreservedContainer)) {\n"
               + indent + "    $h454CreateExit = -1\n"
               + indent + "    $h454PreviousErrorAction = $ErrorActionPreference\n"
               + indent + "    try {\n" + indent + "        $ErrorActionPreference = 'SilentlyContinue'\n"
               + indent + "        $global:LASTEXITCODE = -1\n"
               + indent + "        $h454Created = @(\n" + indent + "            " + create + " 2>$null\n" + indent + "        )\n"
               + indent + "        $h454CreateExit = $LASTEXITCODE\n"
               + indent + "    } catch { $h454Created = @() } finally { $ErrorActionPreference = $h454PreviousErrorAction }\n"
               + indent + "    Require ($h454CreateExit -eq 0 -and $h454Created.Count -eq 1 -and\n"
               + indent + "        $h454Created[0] -cmatch '^[a-f0-9]{64}$') 'H454_CONTAINER_CREATE_FAILED'\n"
               + indent + "    $script:h454ContainerId = [string]$h454Created[0]\n"
               + indent + "    Require (Start-H454PreservedContainer) 'H454_CONTAINER_START_FAILED'\n"
               + indent + "}")
    block = block[:pos] + wrapped + block[end_pipeline:]
    helpers = (HELPERS.replace("__PROFILE_SHA256__", profile_sha256.upper())
               .replace("__IMAGE_ID__", image_id).replace("__TUNNEL_NEEDLE__", needles[0]))
    changed = text[:start] + helpers + block + text[end:]
    encoded = changed.replace("\n", newline).encode("utf-8")
    return (b"\xef\xbb\xbf" if bom else b"") + encoded


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--profile-sha256", required=True)
    parser.add_argument("--image-id", required=True)
    args = parser.parse_args()
    try:
        for path in (args.source, args.output):
            for parent in (path, *path.parents):
                if parent.is_symlink() or (hasattr(parent, "is_junction") and parent.is_junction()):
                    raise PatchRefused("REPARSE_POINT")
        if args.source.resolve() == args.output.resolve() or args.output.suffix.casefold() != ".ps1":
            raise PatchRefused("OUTPUT_PATH")
        candidate = prepare(args.source.read_bytes(), args.profile_sha256, args.image_id)
        with args.output.open("xb") as stream:
            stream.write(candidate)
    except (PatchRefused, OSError, UnicodeError) as exc:
        reason = str(exc) if type(exc) is PatchRefused else "FILE_OPERATION_REFUSED"
        print("H454_LAUNCHER_PRESERVE=HOLD\nH454_REASON=" + reason)
        return 2
    print("H454_LAUNCHER_PRESERVE=PREPARED\nH454_LIVE_LAUNCHER_CHANGED=FALSE")
    return 0


if __name__ == "__main__":
    sys.exit(main())
