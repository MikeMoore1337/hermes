#requires -Version 5.1
<#
H445 owner Windows local-only, READ-ONLY, in-memory --init candidate gate.
Pinned launcher and snapshot never leave owner Windows; candidate is never saved.
Does NOT invoke any Docker command, Scheduled Task, launcher, process or network.
No source, Docker args, secret or private path ever printed by this script.
#>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'

$launcherSha='55EA1245671C8B656A3BBA944945198350668B2920CD46E36ED7CBA56637317E'
$containerId='571a1e2bede31a07638b896e3ef2de677dafa1c000e4a7975e7996257f8ea162'
$imageId='sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3'
$taskName='HermesH15BRCWindows'

function Deny([string]$Code) {
    Write-Output 'H445_CANDIDATE_DRY_RUN=HOLD'
    Write-Output ('H445_REASON='+$Code)
    Write-Output 'H445_CANDIDATE_WRITE=NONE'
    Write-Output 'H445_CUTOVER_AUTHORIZED=FALSE'
    Write-Output 'H445_ROLLBACK_EXECUTION=NOT_TESTED'
    exit 2
}
function Parse-RunCalls([string]$Source) {
    $tokens=$null
    $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput(
        $Source,[ref]$tokens,[ref]$errors)
    if (@($errors).Count -ne 0) { throw 'PARSE_FAILED' }
    $all=@($ast.FindAll({
        param($node)
        $node -is [Management.Automation.Language.CommandAst]
    },$true))
    $sites=New-Object 'System.Collections.Generic.List[object]'
    foreach ($call in $all) {
        $elements=@($call.CommandElements)
        if ($elements.Count -lt 2) { continue }
        $executable=$elements[0].Extent.Text.Trim([char[]]@([char]39,[char]34))
        $verb=$elements[1].Extent.Text.Trim([char[]]@([char]39,[char]34))
        if ($executable -cnotmatch '^(?i:(?:\$docker|docker(?:\.exe)?))$' -or
            $verb -cne 'run') { continue }
        if ($sites.Count -ge 2) { throw 'RUN_SITE_COUNT_UNEXPECTED' }
        $sites.Add([pscustomobject]@{
            Elements=$elements
            InsertAt=[int]$elements[1].Extent.EndOffset
            Command=$call
        })
    }
    return @($sites.ToArray())
}
function Has-LiteralFlag($Elements,[string[]]$Options) {
    for ($i=2;$i -lt $Elements.Count;$i++) {
        $word=$Elements[$i].Extent.Text
        foreach ($option in $Options) {
            if ($word -ceq $option -or $word.StartsWith($option+'=',[StringComparison]::Ordinal)) {
                return $true
            }
        }
    }
    return $false
}
function One-Spec($Elements,[string[]]$Options) {
    $count=0
    $value=''
    for ($i=2;$i -lt $Elements.Count;$i++) {
        $word=$Elements[$i].Extent.Text
        foreach ($option in $Options) {
            if ($word -ceq $option) {
                if ($i+1 -ge $Elements.Count) { return [pscustomobject]@{ Found='INVALID'; Value='' } }
                $count++
                $value=$Elements[$i+1].Extent.Text
            } elseif ($word.StartsWith($option+'=',[StringComparison]::Ordinal)) {
                $count++
                $value=$word.Substring(($option+'=').Length)
            }
        }
    }
    if ($count -ne 1) { return [pscustomobject]@{ Found='AMBIGUOUS'; Value='' } }
    return [pscustomobject]@{ Found='ONE'; Value=$value }
}
function Equal-Spec($Left,$Right) {
    if ($Left.Found -cne 'ONE' -or $Right.Found -cne 'ONE') {
        return 'UNKNOWN'
    }
    if ($Left.Value -ceq $Right.Value) { return 'SAME_AST_TEXT' }
    return 'DIFFERENT_AST_TEXT'
}
function Preview-InMemory([string]$Source) {
    $calls=@(Parse-RunCalls $Source)
    if ($calls.Count -ne 2) { throw 'RUN_SITE_COUNT_UNEXPECTED' }

    $name0=One-Spec $calls[0].Elements @('--name')
    $name1=One-Spec $calls[1].Elements @('--name')
    $mount0=One-Spec $calls[0].Elements @('-v','--volume','--mount')
    $mount1=One-Spec $calls[1].Elements @('-v','--volume','--mount')
    $network0=One-Spec $calls[0].Elements @('--network')
    $network1=One-Spec $calls[1].Elements @('--network')
    $varSites=0

    foreach ($site in $calls) {
        $e=$site.Elements
        if ($e.Count -lt 5) { throw 'RUN_COMMAND_TOO_SHORT' }
        if (-not (Has-LiteralFlag $e @('--name')) -or
            -not (Has-LiteralFlag $e @('-v','--volume','--mount')) -or
            -not (Has-LiteralFlag $e @('--network')) -or
            (Has-LiteralFlag $e @('--init'))) {
            throw 'RUN_SITE_FLAG_DRIFT'
        }
        $hasVariable=$false
        for ($i=2;$i -lt $e.Count;$i++) {
            if ($e[$i] -is [Management.Automation.Language.VariableExpressionAst]) {
                if ($e[$i].Splatted) { throw 'RUN_SITE_SPLAT_UNSUPPORTED' }
                $hasVariable=$true
            }
        }
        if ($hasVariable) { $varSites++ }
    }
    if ($varSites -ne 2) { throw 'RUN_SITE_DYNAMIC_SHAPE_DRIFT' }

    # Replace from the highest offset to preserve earlier AST byte offsets.
    # Candidate is held only in a process-local .NET string, never written.
    $candidate=$Source
    foreach ($site in @($calls | Sort-Object -Property InsertAt -Descending)) {
        $at=$site.InsertAt
        if ($at -le 0 -or $at -gt $candidate.Length) {
            throw 'RUN_SITE_OFFSET_INVALID'
        }
        $candidate=$candidate.Insert($at,' --init')
    }
    $newCalls=@(Parse-RunCalls $candidate)
    if ($newCalls.Count -ne 2) { throw 'PATCHED_RUN_SITE_COUNT_UNEXPECTED' }
    foreach ($site in $newCalls) {
        $count=0
        foreach ($element in $site.Elements) {
            if ($element.Extent.Text -ceq '--init') { $count++ }
        }
        if ($count -ne 1) { throw 'PATCHED_INIT_FLAG_COUNT_UNEXPECTED' }
    }
    # Verify that exactly two insertions and no other change happened.
    $restored=$candidate
    foreach ($site in @($calls | Sort-Object -Property InsertAt)) {
        $at=$site.InsertAt
        if ($restored.Substring($at,7) -cne ' --init') {
            throw 'PATCH_INSERTION_MISMATCH'
        }
        $restored=$restored.Remove($at,7)
    }
    if ($restored -cne $Source) { throw 'PATCH_REVERSIBILITY_FAILED' }
    return [pscustomobject]@{
        InsertionCount=2
        NameRelation=(Equal-Spec $name0 $name1)
        MountRelation=(Equal-Spec $mount0 $mount1)
        NetworkRelation=(Equal-Spec $network0 $network1)
        DynamicArgumentSites=$varSites
        CandidateNotWritten=$true
    }
}

try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        Deny 'OWNER_WINDOWS_REQUIRED'
    }
    $folder=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'HermesH445Rollback-20261028'
    $item=Get-Item -LiteralPath $folder -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or
        ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Deny 'BACKUP_DIRECTORY_UNSAFE'
    }
    $acl=Get-Acl -LiteralPath $folder -ErrorAction Stop
    if (-not $acl.AreAccessRulesProtected) { Deny 'BACKUP_ACL_NOT_PROTECTED' }
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach ($rule in $acl.Access) {
        $sid=$rule.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]).Value
        if ($sid -notin @($owner,'S-1-5-18','S-1-5-32-544')) {
            Deny 'BACKUP_ACL_UNEXPECTED'
        }
    }
    $names=@('launcher.ps1','scheduled-task.xml','container-inspect.json','manifest.json')
    if (@(Get-ChildItem -LiteralPath $folder -Force -ErrorAction Stop).Count -ne 4) {
        Deny 'BACKUP_FILE_SET_DRIFT'
    }
    foreach ($name in $names) {
        $entry=Get-Item -LiteralPath (Join-Path $folder $name) -Force -ErrorAction Stop
        if ($entry.PSIsContainer -or
            ($entry.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $entry.Length -lt 1 -or $entry.Length -gt 2097152) {
            Deny 'BACKUP_FILE_UNSAFE'
        }
    }
    $manifest=ConvertFrom-Json -InputObject (
        [IO.File]::ReadAllText((Join-Path $folder 'manifest.json')))
    if ($manifest.schema -cne 'h445-owner-local-backup-v1' -or
        $manifest.original_container_id -cne $containerId -or
        $manifest.original_image_id -cne $imageId -or
        $manifest.task_name -cne $taskName -or
        $manifest.rollback_verified -ne $false) {
        Deny 'BACKUP_MANIFEST_DRIFT'
    }
    foreach ($name in @('launcher.ps1','scheduled-task.xml','container-inspect.json')) {
        $prop=$manifest.document_sha256.PSObject.Properties[$name]
        if ($null -eq $prop -or
            [string]$prop.Value -cnotmatch '^[0-9A-F]{64}$' -or
            (Get-FileHash -LiteralPath (Join-Path $folder $name) -Algorithm SHA256).Hash -cne
                [string]$prop.Value) {
            Deny 'BACKUP_CHECKSUM_DRIFT'
        }
    }
    $launcher=Join-Path $folder 'launcher.ps1'
    if ((Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash -cne $launcherSha) {
        Deny 'PINNED_LAUNCHER_DRIFT'
    }
    $result=Preview-InMemory ([IO.File]::ReadAllText($launcher))
    Write-Output 'H445_CANDIDATE_DRY_RUN=PASS'
    Write-Output 'H445_CANDIDATE_INSERTIONS=2'
    Write-Output ('H445_SITE_NAME_SPEC_RELATION='+$result.NameRelation)
    Write-Output ('H445_SITE_MOUNT_SPEC_RELATION='+$result.MountRelation)
    Write-Output ('H445_SITE_NETWORK_SPEC_RELATION='+$result.NetworkRelation)
    Write-Output 'H445_SITE_DYNAMIC_ARGUMENTS=YES'
    Write-Output 'H445_CANDIDATE_AST_REPARSE=PASS'
    Write-Output 'H445_CANDIDATE_MEMORY_ROUNDTRIP=PASS'
    Write-Output 'H445_CANDIDATE_WRITE=NONE'
    Write-Output 'H445_RUNTIME_ARGUMENTS=NOT_VERIFIED'
    Write-Output 'H445_EXECUTED_LAUNCH_BRANCH=NOT_VERIFIED'
    Write-Output 'H445_CUTOVER_AUTHORIZED=FALSE'
    Write-Output 'H445_ROLLBACK_EXECUTION=NOT_TESTED'
    exit 0
} catch {
    # No exception text: a private path/source fragment may be in the error.
    Deny 'CANDIDATE_PRIVATE_DRY_RUN_FAILED'
}
