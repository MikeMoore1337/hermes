#requires -Version 5.1
<#
H445 owner-only offline static Docker run site inventory.
Reads ONLY the pinned launcher in the existing ACL-protected private backup.
Never prints source, arguments, names, environment, paths or credentials.
No Docker commands, task modifications or production state changes.
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
    Write-Output 'H445_LAUNCHER_SITES=HOLD'
    Write-Output ('H445_REASON='+$Code)
    Write-Output 'H445_CUTOVER_AUTHORIZED=FALSE'
    Write-Output 'H445_ROLLBACK_EXECUTION=NOT_TESTED'
    exit 2
}
function Flag-Value([bool]$Found) {
    if ($Found) { return 'YES' }
    return 'NO'
}
function Parent-Has($Node,[string]$Class) {
    $parent=$Node.Parent
    while ($null -ne $parent) {
        if ($parent.GetType().Name -ceq $Class) { return $true }
        $parent=$parent.Parent
    }
    return $false
}
function Find-RunSites([string]$Source) {
    $tokens=$null
    $errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput(
        $Source,[ref]$tokens,[ref]$errors)
    if (@($errors).Count -ne 0) { throw 'SOURCE_PARSE_FAILED' }
    $calls=@($ast.FindAll({
        param($n)
        $n -is [Management.Automation.Language.CommandAst]
    },$true))
    $sites=New-Object 'System.Collections.Generic.List[object]'
    $otherDockerCalls=0
    foreach ($call in $calls) {
        $args=@($call.CommandElements)
        if ($args.Count -lt 1) { continue }
        $exe=$args[0].Extent.Text.Trim([char[]]@([char]39,[char]34))
        if ($exe -cnotmatch '^(?i:(?:\$docker|docker(?:\.exe)?))$') { continue }
        $verb=''
        if ($args.Count -ge 2) {
            $verb=$args[1].Extent.Text.Trim([char[]]@([char]39,[char]34))
        }
        if ($verb -cne 'run') {
            $otherDockerCalls++
            continue
        }
        if ($sites.Count -ge 12) { throw 'RUN_SITE_LIMIT_EXCEEDED' }
        $name=$false
        $mount=$false
        $environment=$false
        $init=$false
        $rm=$false
        $variable=$false
        $network=$false
        $splat=$false
        for ($i=2; $i -lt $args.Count; $i++) {
            $arg=$args[$i]
            # Never expose or log $arg.Extent.Text. Only compare allowlisted
            # Docker option prefixes and the AST node type.
            $literal=$arg.Extent.Text
            if ($literal -match '^--name(?:=|$)') { $name=$true }
            if ($literal -match '^(?:-v|--volume|--mount)(?:=|$)') { $mount=$true }
            if ($literal -match '^(?:-e|--env|--env-file)(?:=|$)') { $environment=$true }
            if ($literal -ceq '--init') { $init=$true }
            if ($literal -ceq '--rm') { $rm=$true }
            if ($literal -match '^--network(?:=|$)') { $network=$true }
            if ($arg -is [Management.Automation.Language.VariableExpressionAst]) {
                $variable=$true
                if ($arg.Splatted) { $splat=$true }
            }
        }
        $context='TOP_LEVEL'
        if (Parent-Has $call 'FunctionDefinitionAst') { $context='FUNCTION' }
        $conditional=(Parent-Has $call 'IfStatementAst') -or
            (Parent-Has $call 'SwitchStatementAst') -or
            (Parent-Has $call 'TryStatementAst')
        $sites.Add([pscustomobject]@{
            Context=$context
            Conditional=(Flag-Value $conditional)
            Name=(Flag-Value $name)
            Mount=(Flag-Value $mount)
            Environment=(Flag-Value $environment)
            Init=(Flag-Value $init)
            Remove=(Flag-Value $rm)
            Network=(Flag-Value $network)
            VariableArgument=(Flag-Value $variable)
            Splat=(Flag-Value $splat)
        })
    }
    return [pscustomobject]@{
        Sites=@($sites.ToArray())
        OtherDockerCalls=$otherDockerCalls
    }
}
function Count-Class([int]$Value) {
    if ($Value -eq 0) { return 'ZERO' }
    if ($Value -eq 1) { return 'ONE' }
    return 'MULTIPLE'
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
    if (-not $acl.AreAccessRulesProtected) { Deny 'BACKUP_ACL_WEAK' }
    $owner=[Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    foreach ($rule in $acl.Access) {
        $sid=$rule.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]).Value
        if ($sid -notin @($owner,'S-1-5-18','S-1-5-32-544')) {
            Deny 'BACKUP_ACL_UNEXPECTED'
        }
    }
    $names=@('launcher.ps1','scheduled-task.xml','container-inspect.json','manifest.json')
    if (@(Get-ChildItem -LiteralPath $dir -Force).Count -ne 4) {
        Deny 'BACKUP_FILE_COUNT'
    }
    foreach ($name in $names) {
        $item=Get-Item -LiteralPath (Join-Path $dir $name) -Force -ErrorAction Stop
        if ($item.PSIsContainer -or
            ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or
            $item.Length -lt 1 -or $item.Length -gt 2097152) {
            Deny 'BACKUP_FILE_INVALID'
        }
    }
    $manifest=ConvertFrom-Json -InputObject (
        [IO.File]::ReadAllText((Join-Path $dir 'manifest.json')))
    if ($manifest.schema -cne 'h445-owner-local-backup-v1' -or
        $manifest.original_container_id -cne $containerId -or
        $manifest.original_image_id -cne $imageId -or
        $manifest.task_name -cne $taskName -or
        $manifest.rollback_verified -ne $false) {
        Deny 'BACKUP_MANIFEST_IDENTITY'
    }
    foreach ($name in @('launcher.ps1','scheduled-task.xml','container-inspect.json')) {
        $property=$manifest.document_sha256.PSObject.Properties[$name]
        if ($null -eq $property -or
            [string]$property.Value -cnotmatch '^[0-9A-F]{64}$' -or
            (Get-FileHash -LiteralPath (Join-Path $dir $name) -Algorithm SHA256).Hash -cne
                [string]$property.Value) {
            Deny 'BACKUP_CHECKSUM_MISMATCH'
        }
    }
    $launcherPath=Join-Path $dir 'launcher.ps1'
    if ((Get-FileHash -LiteralPath $launcherPath -Algorithm SHA256).Hash -cne $launcherSha) {
        Deny 'PINNED_LAUNCHER_MISMATCH'
    }
    $inventory=Find-RunSites ([IO.File]::ReadAllText($launcherPath))
    if (@($inventory.Sites).Count -lt 1) { Deny 'NO_DIRECT_DOCKER_RUN_SITE' }
    Write-Output 'H445_LAUNCHER_SITES=READ_ONLY_INVENTORY'
    Write-Output ('H445_DIRECT_RUN_SITE_COUNT='+@($inventory.Sites).Count)
    Write-Output ('H445_OTHER_DIRECT_DOCKER_CALLS='+(Count-Class $inventory.OtherDockerCalls))
    for ($i=0; $i -lt $inventory.Sites.Count; $i++) {
        $site=$inventory.Sites[$i]
        $prefix='H445_RUN_SITE_'+($i+1).ToString()
        Write-Output ($prefix+'_CONTEXT='+$site.Context)
        Write-Output ($prefix+'_CONDITIONAL='+$site.Conditional)
        Write-Output ($prefix+'_NAME_FLAG='+$site.Name)
        Write-Output ($prefix+'_MOUNT_FLAG='+$site.Mount)
        Write-Output ($prefix+'_ENV_FLAG='+$site.Environment)
        Write-Output ($prefix+'_INIT_FLAG='+$site.Init)
        Write-Output ($prefix+'_RM_FLAG='+$site.Remove)
        Write-Output ($prefix+'_NETWORK_FLAG='+$site.Network)
        Write-Output ($prefix+'_VARIABLE_ARGUMENT='+$site.VariableArgument)
        Write-Output ($prefix+'_SPLAT='+$site.Splat)
    }
    Write-Output 'H445_SITES_STATIC_ONLY=TRUE'
    Write-Output 'H445_EXECUTED_LAUNCH_BRANCH=NOT_VERIFIED'
    Write-Output 'H445_CUTOVER_AUTHORIZED=FALSE'
    Write-Output 'H445_ROLLBACK_EXECUTION=NOT_TESTED'
    exit 0
} catch {
    # Do not echo raw exceptions or source: they might include private paths.
    Deny 'PRIVATE_AST_DIAGNOSTIC_FAILED'
}
