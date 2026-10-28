#requires -Version 5.1
<#
H445: OWNER Windows read-only --init cutover feasibility gate.
Reads the existing private, protected rollback snapshot and original launcher
locally. Never exposes launcher content, task XML, Docker Env or mount paths.
Does NOT modify Docker, Task Scheduler, backup, source or credentials.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'

$cid='571a1e2bede31a07638b896e3ef2de677dafa1c000e4a7975e7996257f8ea162'
$image='sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3'
$launcherHash='55EA1245671C8B656A3BBA944945198350668B2920CD46E36ED7CBA56637317E'
$taskName='HermesH15BRCWindows'

function Deny([string]$Code) {
    Write-Output 'H445_INIT_PLAN=HOLD'
    Write-Output ('H445_REASON='+$Code)
    Write-Output 'H445_CUTOVER_AUTHORIZED=FALSE'
    Write-Output 'H445_ROLLBACK_EXECUTION=NOT_TESTED'
    exit 2
}
function Inspect-RunStructure([string]$Source) {
    $tokens=$null
    $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput(
        $Source,[ref]$tokens,[ref]$errors)
    if (@($errors).Count -ne 0) { throw 'SOURCE_AST_INVALID' }
    $calls=@($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst]
    },$true))
    $runCount=0
    $initTokens=0
    $dockerLike=0
    $dockerIndirect=0
    $dockerSplat=0
    foreach ($call in $calls) {
        $elements=@($call.CommandElements)
        if ($elements.Count -lt 1) { continue }
        $executable=$elements[0].Extent.Text.Trim([char[]]@([char]39,[char]34))
        # Classify direct calls by AST only; never output arguments or source.
        # Variable names are an advisory hint, NOT an execution proof.
        $direct=$executable -cmatch '^(?i:(?:\$docker|docker(?:\.exe)?))
function Load-Private([string]$Path) {
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -lt 1 -or $item.Length -gt 2097152) {
        throw 'PRIVATE_FILE_UNSAFE'
    }
    return [IO.File]::ReadAllText($Path)
}
function Read-OneInspect([string]$Text) {
    if ($Text.Length -gt 2097152 -or $Text.Length -lt 2) {
        throw 'INSPECT_SIZE_UNSAFE'
    }
    $obj=@(ConvertFrom-Json -InputObject $Text -ErrorAction Stop)
    if ($obj.Count -ne 1) { throw 'INSPECT_CARDINALITY' }
    return $obj[0]
}
function Match-Section($Saved,$Live,[string]$Section) {
    $a=ConvertTo-Json -InputObject $Saved.$Section -Depth 80 -Compress
    $b=ConvertTo-Json -InputObject $Live.$Section -Depth 80 -Compress
    if ($a -cne $b) { throw 'SNAPSHOT_DRIFT' }
}
try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        Deny 'OWNER_WINDOWS_REQUIRED'
    }
    $dir=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'HermesH445Rollback-20261028'
    $folder=Get-Item -LiteralPath $dir -Force -ErrorAction Stop
    if (-not $folder.PSIsContainer -or
        ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Deny 'SNAPSHOT_DIRECTORY_UNSAFE'
    }
    $acl=Get-Acl -LiteralPath $dir -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected) { Deny 'SNAPSHOT_ACL_NOT_PROTECTED' }
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach ($rule in $acl.Access) {
        $member=$rule.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]).Value
        if ($member -notin @($sid,'S-1-5-18','S-1-5-32-544')) {
            Deny 'SNAPSHOT_ACL_UNEXPECTED'
        }
    }
    $names=@('launcher.ps1','scheduled-task.xml','container-inspect.json','manifest.json')
    $entries=@(Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop)
    if ($entries.Count -ne 4) { Deny 'SNAPSHOT_FILE_SET_DRIFT' }
    foreach ($name in $names) {
        $item=Get-Item -LiteralPath (Join-Path $dir $name) -Force -ErrorAction Stop
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $item.Length -lt 1 -or $item.Length -gt 2097152) {
            Deny 'SNAPSHOT_FILE_UNSAFE'
        }
    }
    $manifest=ConvertFrom-Json -InputObject (Load-Private (Join-Path $dir 'manifest.json'))
    if ($manifest.schema -cne 'h445-owner-local-backup-v1' -or
        $manifest.original_container_id -cne $cid -or
        $manifest.original_image_id -cne $image -or
        $manifest.task_name -cne $taskName -or
        $manifest.rollback_verified -ne $false) { Deny 'MANIFEST_IDENTITY_DRIFT' }
    foreach ($name in @('launcher.ps1','scheduled-task.xml','container-inspect.json')) {
        $prop=$manifest.document_sha256.PSObject.Properties[$name]
        if ($null -eq $prop -or [string]$prop.Value -cnotmatch '^[0-9A-F]{64}$') {
            Deny 'MANIFEST_HASH_MISSING'
        }
        if ((Get-FileHash -LiteralPath (Join-Path $dir $name) -Algorithm SHA256).Hash -cne $prop.Value) {
            Deny 'SNAPSHOT_HASH_DRIFT'
        }
    }
    if ((Get-FileHash -LiteralPath (Join-Path $dir 'launcher.ps1') -Algorithm SHA256).Hash -cne $launcherHash) {
        Deny 'PINNED_LAUNCHER_DRIFT'
    }
    $saved=Read-OneInspect (Load-Private (Join-Path $dir 'container-inspect.json'))
    $docker=Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'
    $bin=Get-Item -LiteralPath $docker -Force -ErrorAction Stop
    if ($bin.PSIsContainer -or
        ($bin.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Deny 'DOCKER_BINARY_UNTRUSTED'
    }
    $raw=@(& $docker container inspect $cid 2>$null)
    if ($LASTEXITCODE -ne 0) { Deny 'LIVE_CONTAINER_UNAVAILABLE' }
    $live=Read-OneInspect ($raw -join [Environment]::NewLine)
    if ($saved.Id -cne $cid -or $saved.Image -cne $image -or
        $live.Id -cne $cid -or $live.Image -cne $image -or
        $live.State.Running -ne $true) { Deny 'CONTAINER_IDENTITY_DRIFT' }
    Match-Section $saved $live 'Config'
    Match-Section $saved $live 'HostConfig'
    Match-Section $saved $live 'Mounts'
    $taskXml=Export-ScheduledTask -TaskName $taskName -ErrorAction Stop
    if ($taskXml -cne (Load-Private (Join-Path $dir 'scheduled-task.xml'))) {
        Deny 'TASK_LAUNCHER_CHANGED'
    }
    if ($saved.Config.User -cne '65534:65534' -or
        $saved.HostConfig.Privileged -ne $false -or
        [long]$saved.HostConfig.PidsLimit -ne 96 -or
        [long]$saved.HostConfig.Memory -ne 536870912 -or
        $saved.HostConfig.RestartPolicy.Name -cne 'no' -or
        @($saved.Mounts).Count -ne 1 -or
        @($saved.Config.Env).Count -lt 1) {
        Deny 'SECURITY_OR_IDENTITY_MATERIAL_DRIFT'
    }
    $imageRow=@(& $docker image inspect --format '{{.Id}}' $image 2>$null)
    if ($LASTEXITCODE -ne 0 -or $imageRow.Count -ne 1 -or $imageRow[0] -cne $image) {
        Deny 'ORIGINAL_IMAGE_NOT_AVAILABLE'
    }
    $structure=Inspect-RunStructure (Load-Private (Join-Path $dir 'launcher.ps1'))
    if ($structure.DockerRunSites -ne 1 -or $structure.LiteralInitTokens -ne 0 -or
        $structure.DockerIndirectCalls -ne 0) {
        # Fixed enums only: private launcher source, arguments, env and paths
        # are NEVER serialized to a receipt or sent over the network.
        Write-Output ('H445_AST_EXPLICIT_RUN_SITES='+(Site-Class $structure.DockerRunSites))
        Write-Output ('H445_AST_DOCKER_LIKE_CALLS='+(Site-Class $structure.DockerLikeCalls))
        Write-Output ('H445_AST_DOCKER_INDIRECT_CALLS='+(Site-Class $structure.DockerIndirectCalls))
        Write-Output ('H445_AST_DOCKER_SPLATTED_CALLS='+(Site-Class $structure.DockerSplattedCalls))
        Write-Output ('H445_AST_LITERAL_INIT_TOKENS='+(Site-Class $structure.LiteralInitTokens))
        Deny 'LAUNCHER_AST_REQUIRES_MANUAL_REVIEW'
    }
    # This proves only a static command site, NOT a safe mechanical edit:
    # options may be dynamically splatted and runtime behavior unobserved.
    Write-Output 'H445_INIT_PLAN=READ_ONLY_PREFLIGHT_PASS'
    Write-Output 'H445_SNAPSHOT_CONFIG_ENV_MOUNTS=EXACT_MATCH'
    Write-Output 'H445_TASK_AND_LAUNCHER_HASH=PASS'
    Write-Output 'H445_DOCKER_RUN_AST_SITE=ONE'
    Write-Output 'H445_INIT_LAUNCHER_PATCH=MANUAL_REVIEW_REQUIRED'
    Write-Output 'H445_DEVICE_IDENTITY_REATTACH=NOT_VERIFIED'
    Write-Output 'H445_ROLLBACK_EXECUTION=NOT_TESTED'
    Write-Output 'H445_CUTOVER_AUTHORIZED=FALSE'
    Write-Output 'H445_ORIGINAL_CONTAINER_CHANGED=FALSE'
    exit 0
} catch {
    # Never print exceptions: they may include private filesystem or task data.
    Deny 'INIT_PLAN_READ_ONLY_PREFLIGHT_FAILED'
}

        $possible=$executable -match '^(?i:(?:\$[a-z0-9_]*docker[a-z0-9_]*|docker(?:\.exe)?))
function Load-Private([string]$Path) {
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -lt 1 -or $item.Length -gt 2097152) {
        throw 'PRIVATE_FILE_UNSAFE'
    }
    return [IO.File]::ReadAllText($Path)
}
function Read-OneInspect([string]$Text) {
    if ($Text.Length -gt 2097152 -or $Text.Length -lt 2) {
        throw 'INSPECT_SIZE_UNSAFE'
    }
    $obj=@(ConvertFrom-Json -InputObject $Text -ErrorAction Stop)
    if ($obj.Count -ne 1) { throw 'INSPECT_CARDINALITY' }
    return $obj[0]
}
function Match-Section($Saved,$Live,[string]$Section) {
    $a=ConvertTo-Json -InputObject $Saved.$Section -Depth 80 -Compress
    $b=ConvertTo-Json -InputObject $Live.$Section -Depth 80 -Compress
    if ($a -cne $b) { throw 'SNAPSHOT_DRIFT' }
}
try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        Deny 'OWNER_WINDOWS_REQUIRED'
    }
    $dir=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'HermesH445Rollback-20261028'
    $folder=Get-Item -LiteralPath $dir -Force -ErrorAction Stop
    if (-not $folder.PSIsContainer -or
        ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Deny 'SNAPSHOT_DIRECTORY_UNSAFE'
    }
    $acl=Get-Acl -LiteralPath $dir -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected) { Deny 'SNAPSHOT_ACL_NOT_PROTECTED' }
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach ($rule in $acl.Access) {
        $member=$rule.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]).Value
        if ($member -notin @($sid,'S-1-5-18','S-1-5-32-544')) {
            Deny 'SNAPSHOT_ACL_UNEXPECTED'
        }
    }
    $names=@('launcher.ps1','scheduled-task.xml','container-inspect.json','manifest.json')
    $entries=@(Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop)
    if ($entries.Count -ne 4) { Deny 'SNAPSHOT_FILE_SET_DRIFT' }
    foreach ($name in $names) {
        $item=Get-Item -LiteralPath (Join-Path $dir $name) -Force -ErrorAction Stop
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $item.Length -lt 1 -or $item.Length -gt 2097152) {
            Deny 'SNAPSHOT_FILE_UNSAFE'
        }
    }
    $manifest=ConvertFrom-Json -InputObject (Load-Private (Join-Path $dir 'manifest.json'))
    if ($manifest.schema -cne 'h445-owner-local-backup-v1' -or
        $manifest.original_container_id -cne $cid -or
        $manifest.original_image_id -cne $image -or
        $manifest.task_name -cne $taskName -or
        $manifest.rollback_verified -ne $false) { Deny 'MANIFEST_IDENTITY_DRIFT' }
    foreach ($name in @('launcher.ps1','scheduled-task.xml','container-inspect.json')) {
        $prop=$manifest.document_sha256.PSObject.Properties[$name]
        if ($null -eq $prop -or [string]$prop.Value -cnotmatch '^[0-9A-F]{64}$') {
            Deny 'MANIFEST_HASH_MISSING'
        }
        if ((Get-FileHash -LiteralPath (Join-Path $dir $name) -Algorithm SHA256).Hash -cne $prop.Value) {
            Deny 'SNAPSHOT_HASH_DRIFT'
        }
    }
    if ((Get-FileHash -LiteralPath (Join-Path $dir 'launcher.ps1') -Algorithm SHA256).Hash -cne $launcherHash) {
        Deny 'PINNED_LAUNCHER_DRIFT'
    }
    $saved=Read-OneInspect (Load-Private (Join-Path $dir 'container-inspect.json'))
    $docker=Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'
    $bin=Get-Item -LiteralPath $docker -Force -ErrorAction Stop
    if ($bin.PSIsContainer -or
        ($bin.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Deny 'DOCKER_BINARY_UNTRUSTED'
    }
    $raw=@(& $docker container inspect $cid 2>$null)
    if ($LASTEXITCODE -ne 0) { Deny 'LIVE_CONTAINER_UNAVAILABLE' }
    $live=Read-OneInspect ($raw -join [Environment]::NewLine)
    if ($saved.Id -cne $cid -or $saved.Image -cne $image -or
        $live.Id -cne $cid -or $live.Image -cne $image -or
        $live.State.Running -ne $true) { Deny 'CONTAINER_IDENTITY_DRIFT' }
    Match-Section $saved $live 'Config'
    Match-Section $saved $live 'HostConfig'
    Match-Section $saved $live 'Mounts'
    $taskXml=Export-ScheduledTask -TaskName $taskName -ErrorAction Stop
    if ($taskXml -cne (Load-Private (Join-Path $dir 'scheduled-task.xml'))) {
        Deny 'TASK_LAUNCHER_CHANGED'
    }
    if ($saved.Config.User -cne '65534:65534' -or
        $saved.HostConfig.Privileged -ne $false -or
        [long]$saved.HostConfig.PidsLimit -ne 96 -or
        [long]$saved.HostConfig.Memory -ne 536870912 -or
        $saved.HostConfig.RestartPolicy.Name -cne 'no' -or
        @($saved.Mounts).Count -ne 1 -or
        @($saved.Config.Env).Count -lt 1) {
        Deny 'SECURITY_OR_IDENTITY_MATERIAL_DRIFT'
    }
    $imageRow=@(& $docker image inspect --format '{{.Id}}' $image 2>$null)
    if ($LASTEXITCODE -ne 0 -or $imageRow.Count -ne 1 -or $imageRow[0] -cne $image) {
        Deny 'ORIGINAL_IMAGE_NOT_AVAILABLE'
    }
    $structure=Inspect-RunStructure (Load-Private (Join-Path $dir 'launcher.ps1'))
    if ($structure.DockerRunSites -ne 1 -or $structure.LiteralInitTokens -ne 0) {
        Deny 'LAUNCHER_AST_REQUIRES_MANUAL_REVIEW'
    }
    # This proves only a static command site, NOT a safe mechanical edit:
    # options may be dynamically splatted and runtime behavior unobserved.
    Write-Output 'H445_INIT_PLAN=READ_ONLY_PREFLIGHT_PASS'
    Write-Output 'H445_SNAPSHOT_CONFIG_ENV_MOUNTS=EXACT_MATCH'
    Write-Output 'H445_TASK_AND_LAUNCHER_HASH=PASS'
    Write-Output 'H445_DOCKER_RUN_AST_SITE=ONE'
    Write-Output 'H445_INIT_LAUNCHER_PATCH=MANUAL_REVIEW_REQUIRED'
    Write-Output 'H445_DEVICE_IDENTITY_REATTACH=NOT_VERIFIED'
    Write-Output 'H445_ROLLBACK_EXECUTION=NOT_TESTED'
    Write-Output 'H445_CUTOVER_AUTHORIZED=FALSE'
    Write-Output 'H445_ORIGINAL_CONTAINER_CHANGED=FALSE'
    exit 0
} catch {
    # Never print exceptions: they may include private filesystem or task data.
    Deny 'INIT_PLAN_READ_ONLY_PREFLIGHT_FAILED'
}

        if (-not $possible) { continue }
        $dockerLike++
        $verb=''
        if ($elements.Count -ge 2) {
            $verb=$elements[1].Extent.Text.Trim([char[]]@([char]39,[char]34))
        }
        $hasSplat=$false
        foreach ($element in $elements) {
            if ($element -is [Management.Automation.Language.VariableExpressionAst] -and
                $element.Splatted) { $hasSplat=$true }
        }
        if ($hasSplat) { $dockerSplat++ }
        if (-not $direct -or $verb -cne 'run') {
            $dockerIndirect++
            continue
        }
        $runCount++
        foreach ($element in $elements) {
            if ($element.Extent.Text -ceq '--init') { $initTokens++ }
        }
    }
    return [pscustomobject]@{
        DockerRunSites=$runCount
        LiteralInitTokens=$initTokens
        DockerLikeCalls=$dockerLike
        DockerIndirectCalls=$dockerIndirect
        DockerSplattedCalls=$dockerSplat
    }
}
function Site-Class([int]$Count) {
    if ($Count -eq 0) { return 'ZERO' }
    if ($Count -eq 1) { return 'ONE' }
    return 'MULTIPLE'
}
function Load-Private([string]$Path) {
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    if ($item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
        $item.Length -lt 1 -or $item.Length -gt 2097152) {
        throw 'PRIVATE_FILE_UNSAFE'
    }
    return [IO.File]::ReadAllText($Path)
}
function Read-OneInspect([string]$Text) {
    if ($Text.Length -gt 2097152 -or $Text.Length -lt 2) {
        throw 'INSPECT_SIZE_UNSAFE'
    }
    $obj=@(ConvertFrom-Json -InputObject $Text -ErrorAction Stop)
    if ($obj.Count -ne 1) { throw 'INSPECT_CARDINALITY' }
    return $obj[0]
}
function Match-Section($Saved,$Live,[string]$Section) {
    $a=ConvertTo-Json -InputObject $Saved.$Section -Depth 80 -Compress
    $b=ConvertTo-Json -InputObject $Live.$Section -Depth 80 -Compress
    if ($a -cne $b) { throw 'SNAPSHOT_DRIFT' }
}
try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        Deny 'OWNER_WINDOWS_REQUIRED'
    }
    $dir=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'HermesH445Rollback-20261028'
    $folder=Get-Item -LiteralPath $dir -Force -ErrorAction Stop
    if (-not $folder.PSIsContainer -or
        ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Deny 'SNAPSHOT_DIRECTORY_UNSAFE'
    }
    $acl=Get-Acl -LiteralPath $dir -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected) { Deny 'SNAPSHOT_ACL_NOT_PROTECTED' }
    $sid=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach ($rule in $acl.Access) {
        $member=$rule.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]).Value
        if ($member -notin @($sid,'S-1-5-18','S-1-5-32-544')) {
            Deny 'SNAPSHOT_ACL_UNEXPECTED'
        }
    }
    $names=@('launcher.ps1','scheduled-task.xml','container-inspect.json','manifest.json')
    $entries=@(Get-ChildItem -LiteralPath $dir -Force -ErrorAction Stop)
    if ($entries.Count -ne 4) { Deny 'SNAPSHOT_FILE_SET_DRIFT' }
    foreach ($name in $names) {
        $item=Get-Item -LiteralPath (Join-Path $dir $name) -Force -ErrorAction Stop
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $item.Length -lt 1 -or $item.Length -gt 2097152) {
            Deny 'SNAPSHOT_FILE_UNSAFE'
        }
    }
    $manifest=ConvertFrom-Json -InputObject (Load-Private (Join-Path $dir 'manifest.json'))
    if ($manifest.schema -cne 'h445-owner-local-backup-v1' -or
        $manifest.original_container_id -cne $cid -or
        $manifest.original_image_id -cne $image -or
        $manifest.task_name -cne $taskName -or
        $manifest.rollback_verified -ne $false) { Deny 'MANIFEST_IDENTITY_DRIFT' }
    foreach ($name in @('launcher.ps1','scheduled-task.xml','container-inspect.json')) {
        $prop=$manifest.document_sha256.PSObject.Properties[$name]
        if ($null -eq $prop -or [string]$prop.Value -cnotmatch '^[0-9A-F]{64}$') {
            Deny 'MANIFEST_HASH_MISSING'
        }
        if ((Get-FileHash -LiteralPath (Join-Path $dir $name) -Algorithm SHA256).Hash -cne $prop.Value) {
            Deny 'SNAPSHOT_HASH_DRIFT'
        }
    }
    if ((Get-FileHash -LiteralPath (Join-Path $dir 'launcher.ps1') -Algorithm SHA256).Hash -cne $launcherHash) {
        Deny 'PINNED_LAUNCHER_DRIFT'
    }
    $saved=Read-OneInspect (Load-Private (Join-Path $dir 'container-inspect.json'))
    $docker=Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'
    $bin=Get-Item -LiteralPath $docker -Force -ErrorAction Stop
    if ($bin.PSIsContainer -or
        ($bin.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Deny 'DOCKER_BINARY_UNTRUSTED'
    }
    $raw=@(& $docker container inspect $cid 2>$null)
    if ($LASTEXITCODE -ne 0) { Deny 'LIVE_CONTAINER_UNAVAILABLE' }
    $live=Read-OneInspect ($raw -join [Environment]::NewLine)
    if ($saved.Id -cne $cid -or $saved.Image -cne $image -or
        $live.Id -cne $cid -or $live.Image -cne $image -or
        $live.State.Running -ne $true) { Deny 'CONTAINER_IDENTITY_DRIFT' }
    Match-Section $saved $live 'Config'
    Match-Section $saved $live 'HostConfig'
    Match-Section $saved $live 'Mounts'
    $taskXml=Export-ScheduledTask -TaskName $taskName -ErrorAction Stop
    if ($taskXml -cne (Load-Private (Join-Path $dir 'scheduled-task.xml'))) {
        Deny 'TASK_LAUNCHER_CHANGED'
    }
    if ($saved.Config.User -cne '65534:65534' -or
        $saved.HostConfig.Privileged -ne $false -or
        [long]$saved.HostConfig.PidsLimit -ne 96 -or
        [long]$saved.HostConfig.Memory -ne 536870912 -or
        $saved.HostConfig.RestartPolicy.Name -cne 'no' -or
        @($saved.Mounts).Count -ne 1 -or
        @($saved.Config.Env).Count -lt 1) {
        Deny 'SECURITY_OR_IDENTITY_MATERIAL_DRIFT'
    }
    $imageRow=@(& $docker image inspect --format '{{.Id}}' $image 2>$null)
    if ($LASTEXITCODE -ne 0 -or $imageRow.Count -ne 1 -or $imageRow[0] -cne $image) {
        Deny 'ORIGINAL_IMAGE_NOT_AVAILABLE'
    }
    $structure=Inspect-RunStructure (Load-Private (Join-Path $dir 'launcher.ps1'))
    if ($structure.DockerRunSites -ne 1 -or $structure.LiteralInitTokens -ne 0) {
        Deny 'LAUNCHER_AST_REQUIRES_MANUAL_REVIEW'
    }
    # This proves only a static command site, NOT a safe mechanical edit:
    # options may be dynamically splatted and runtime behavior unobserved.
    Write-Output 'H445_INIT_PLAN=READ_ONLY_PREFLIGHT_PASS'
    Write-Output 'H445_SNAPSHOT_CONFIG_ENV_MOUNTS=EXACT_MATCH'
    Write-Output 'H445_TASK_AND_LAUNCHER_HASH=PASS'
    Write-Output 'H445_DOCKER_RUN_AST_SITE=ONE'
    Write-Output 'H445_INIT_LAUNCHER_PATCH=MANUAL_REVIEW_REQUIRED'
    Write-Output 'H445_DEVICE_IDENTITY_REATTACH=NOT_VERIFIED'
    Write-Output 'H445_ROLLBACK_EXECUTION=NOT_TESTED'
    Write-Output 'H445_CUTOVER_AUTHORIZED=FALSE'
    Write-Output 'H445_ORIGINAL_CONTAINER_CHANGED=FALSE'
    exit 0
} catch {
    # Never print exceptions: they may include private filesystem or task data.
    Deny 'INIT_PLAN_READ_ONLY_PREFLIGHT_FAILED'
}
