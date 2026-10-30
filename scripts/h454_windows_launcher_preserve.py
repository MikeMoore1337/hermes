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
    $script:h454ContainerId = $null
    $script:h454DockerHost = 'npipe:////./pipe/dockerDesktopLinuxEngine'
    $script:h454Docker = Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Docker\Docker\resources\bin\docker.exe'
    Require (Test-Path -LiteralPath $script:h454Docker -PathType Leaf) 'H454_DOCKER_NOT_FOUND'
    $h454Path = $script:h454Docker
    while (-not [string]::IsNullOrEmpty($h454Path)) {
        Require (-not ((Get-Item -LiteralPath $h454Path -Force).Attributes -band
            [IO.FileAttributes]::ReparsePoint)) 'H454_DOCKER_REPARSE'
        $h454Parent = [IO.Path]::GetDirectoryName($h454Path)
        if ($h454Parent -ceq $h454Path) { break }
        $h454Path = $h454Parent
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
                $h454Config[$h454Prop.Name] = $h454Prop.Value
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
    if text.count(RUN) != 1 or text.count(RUN_END) != 1:
        raise PatchRefused("SOURCE_STRUCTURE_MISMATCH")
    start = text.index(RUN) + len(RUN)
    end = text.index(RUN_END, start)
    block = text[start:end]
    if (block.count("Stop-OwnedContainer") != 2 or block.count("& docker.exe") != 5
            or block.count("& docker.exe run") != 1 or block.count("Assert-ManagedContainer") != 1):
        raise PatchRefused("SOURCE_STRUCTURE_MISMATCH")
    block = block.replace("Stop-OwnedContainer", "Stop-H454PreservedContainer -Claim", 1)
    block = block.replace("Stop-OwnedContainer", "Stop-H454PreservedContainer")
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
    helpers = HELPERS.replace("__PROFILE_SHA256__", profile_sha256.upper()).replace("__IMAGE_ID__", image_id)
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
