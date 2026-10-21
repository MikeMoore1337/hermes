# Create clean copies of the owner's PUBLIC GitHub code inside the already-mounted H15 workspace.
# Never touches original Windows repo roots, private Second Brain vault or production VPS.
# These are isolated working clones, not syncs of uncommitted local changes.
[CmdletBinding()]
param(
    [ValidateSet('Check','Prepare','Status')][string]$Mode = 'Check',
    [ValidateSet('Hermes','YFC','SecondBrain','Toolkit','All')][string]$Project = 'All'
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$MountHostRoot = Join-Path $HOME 'Hermes-H15-Test'
$ProjectsRoot = Join-Path $MountHostRoot 'projects'
$Manifest = @{
    Hermes = @{ Name = 'hermes'; Repo = 'hermes'; Branch = 'main' }
    YFC = @{ Name = 'your-fitness-coach'; Repo = 'your-fitness-coach'; Branch = 'master' }
    SecondBrain = @{ Name = 'second-brain'; Repo = 'second-brain'; Branch = 'main' }
    Toolkit = @{ Name = 'ai-development-toolkit'; Repo = 'ai-development-toolkit'; Branch = 'main' }
}
$Names = if ($Project -eq 'All') { @('Hermes','YFC','SecondBrain','Toolkit') } else { @($Project) }

function Fail([string]$message) { throw "H15_WORKSPACE_REFUSED=$message" }
function Assert-PlainDirectory([string]$path) {
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if (-not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Fail 'UNTRUSTED_DIRECTORY_OR_REPARSE_POINT'
    }
}
function Repository-Origin([string]$repo) {
    return ('https://github.com/MikeMoore1337/' + $repo + '.git')
}
function Run-Git([string[]]$gitArgs, [string]$failCode) {
    & git.exe @gitArgs
    if ($LASTEXITCODE -ne 0) { Fail $failCode }
}
function Check-Workspace {
    Assert-PlainDirectory $MountHostRoot
    if (Test-Path -LiteralPath $ProjectsRoot) { Assert-PlainDirectory $ProjectsRoot }
    if (-not (Get-Command git.exe -ErrorAction SilentlyContinue)) { Fail 'GIT_MISSING' }
    & git.exe --version
    if ($LASTEXITCODE -ne 0) { Fail 'GIT_VERSION_FAILED' }
    $workspace = Get-Item -LiteralPath $MountHostRoot -Force
    Write-Host "H15_WINDOWS_WORKSPACE=$($workspace.FullName)"
    Write-Host 'H15_BRC_CONTAINER_PROJECTS=/workspace/projects'
    Write-Host 'H15_WORKSPACE_PREFLIGHT=PASS'
}
function Verify-Clone([string]$path,[hashtable]$spec) {
    Assert-PlainDirectory $path
    $gitDir = Join-Path $path '.git'
    Assert-PlainDirectory $gitDir
    $origin = & git.exe -C $path remote get-url origin
    if ($LASTEXITCODE -ne 0 -or $origin.Trim() -cne (Repository-Origin $spec.Repo)) {
        Fail 'EXISTING_REPOSITORY_ORIGIN_MISMATCH'
    }
    $branch = & git.exe -C $path symbolic-ref --quiet --short HEAD
    if ($LASTEXITCODE -ne 0 -or $branch.Trim() -cne $spec.Branch) {
        Fail 'EXISTING_REPOSITORY_BRANCH_MISMATCH'
    }
    Write-Host "H15_WORKSPACE_VERIFIED=$($spec.Name)"
}

Check-Workspace
if ($Mode -eq 'Check') {
    Write-Host 'H15_WORKSPACE_HOST_CHANGES=NONE'
    return
}
if ($Mode -eq 'Status') {
    foreach ($name in $Names) {
        $spec = $Manifest[$name]
        $dest = Join-Path $ProjectsRoot $spec.Name
        if (Test-Path -LiteralPath $dest) { Verify-Clone $dest $spec }
        else { Write-Host "H15_WORKSPACE_MISSING=$($spec.Name)" }
    }
    return
}
if (-not (Test-Path -LiteralPath $ProjectsRoot)) {
    New-Item -Path $ProjectsRoot -ItemType Directory -ErrorAction Stop | Out-Null
}
Assert-PlainDirectory $ProjectsRoot
$prevPrompt = $env:GIT_TERMINAL_PROMPT
$prevInteractive = $env:GCM_INTERACTIVE
try {
    $env:GIT_TERMINAL_PROMPT = '0'
    $env:GCM_INTERACTIVE = 'Never'
    foreach ($name in $Names) {
        $spec = $Manifest[$name]
        $dest = Join-Path $ProjectsRoot $spec.Name
        if (Test-Path -LiteralPath $dest) {
            Verify-Clone $dest $spec
            Write-Host "H15_WORKSPACE_ALREADY_PRESENT_NO_OVERWRITE=$($spec.Name)"
            continue
        }
        $staging = Join-Path $ProjectsRoot ('.h15-staging-' + [Guid]::NewGuid().ToString('N'))
        $url = Repository-Origin $spec.Repo
        Write-Host "H15_WORKSPACE_CLONING=$($spec.Name)"
        # Limit history/bandwidth. Skip global credential helpers; no access to private vault.
        # Shared Windows/Linux checkout: prevent Windows global autocrlf=true
        # from creating CRLF worktrees which the Linux BRC Git sees as dirty.
        # Affects only NEW staged clones; existing directories are untouched.
        Run-Git @('-c','credential.helper=','-c','core.hooksPath=NUL','-c','core.autocrlf=false','clone','--depth','1','--single-branch','--no-tags','--filter=blob:none','--branch',$spec.Branch,'--',$url,$staging) 'PUBLIC_CLONE_FAILED'
        Run-Git @('-C',$staging,'config','--local','core.autocrlf','false') 'LOCAL_LF_POLICY_FAILED'
        Verify-Clone $staging $spec
        # Never delete staging automatically after a failed git command: user can inspect it.
        if (Test-Path -LiteralPath $dest) { Fail 'DESTINATION_CREATED_CONCURRENTLY' }
        Move-Item -LiteralPath $staging -Destination $dest -ErrorAction Stop
        Verify-Clone $dest $spec
        Write-Host "H15_WORKSPACE_CREATED=PASS:$($spec.Name)"
    }
}
finally {
    $env:GIT_TERMINAL_PROMPT = $prevPrompt
    $env:GCM_INTERACTIVE = $prevInteractive
}
Write-Host 'H15_WORKSPACES_PREPARED=PASS'
Write-Host 'H15_EXISTING_LOCAL_PROJECTS=UNTOUCHED'
