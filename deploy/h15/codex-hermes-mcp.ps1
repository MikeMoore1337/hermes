# Configure the existing owner Codex CLI/Desktop profile to use the existing Hermes OAuth MCP.
# Never edits another MCP, global AGENTS.md, subscriptions, API keys, or production hosts.
# Modes: Check (read only), Install (backup + add; not OAuth), Login (interactive OAuth), Status.
[CmdletBinding()]
param([ValidateSet('Check','Install','Login','Status')][string]$Mode = 'Check')
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$ServerName = 'hermes'
$ServerUrl = 'https://mcp.mikemoore.top/mcp'
$CodexRoot = Join-Path $HOME '.codex'
$ConfigPath = Join-Path $CodexRoot 'config.toml'

function Fail([string]$reason) { throw "H15_CODEX_REFUSED=$reason" }
function Native([string]$reason,[scriptblock]$action) {
    & $action
    if ($LASTEXITCODE -ne 0) { Fail $reason }
}
function Validate-Config {
    if (-not (Test-Path -LiteralPath $CodexRoot -PathType Container)) { Fail 'CODEX_HOME_MISSING' }
    $root = Get-Item -LiteralPath $CodexRoot -Force
    if (($root.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { Fail 'CODEX_HOME_LINK' }
    if (Test-Path -LiteralPath $ConfigPath) {
        $info = Get-Item -LiteralPath $ConfigPath -Force
        if ($info.PSIsContainer -or ($info.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            Fail 'CODEX_CONFIG_NOT_REGULAR'
        }
        if ($info.Length -gt 1048576) { Fail 'CODEX_CONFIG_UNEXPECTEDLY_LARGE' }
    }
}
function Has-HermesConfig {
    if (-not (Test-Path -LiteralPath $ConfigPath -PathType Leaf)) { return $false }
    $source = [IO.File]::ReadAllText($ConfigPath)
    return [bool]($source -match '(?m)^\s*\[mcp_servers\.hermes(?:\.|\])')
}
function Assert-HermesEndpoint {
    # When an MCP entry already exists, refuse to log in to an unexpected server.
    $raw = [IO.File]::ReadAllText($ConfigPath)
    $section = [regex]::Match($raw, '(?ms)^\s*\[mcp_servers\.hermes\]\s*(?<body>.*?)(?=^\s*\[|\z)')
    if (-not $section.Success) { Fail 'HERMES_CONFIG_SECTION_NOT_CANONICAL' }
    $url = [regex]::Match($section.Groups['body'].Value, '(?m)^\s*url\s*=\s*"([^"]+)"\s*$')
    if (-not $url.Success -or $url.Groups[1].Value -cne $ServerUrl) {
        Fail 'EXISTING_HERMES_URL_MISMATCH'
    }
}
function Find-Codex {
    foreach ($name in @('codex.exe','codex.cmd','codex')) {
        $c = Get-Command $name -ErrorAction SilentlyContinue
        if ($c -and $c.CommandType -eq 'Application') { return $c.Source }
    }
    Fail 'CODEX_CLI_NOT_FOUND'
}
function Check {
    Validate-Config
    $script:Codex = Find-Codex
    Native 'CODEX_VERSION_FAILED' { & $script:Codex --version }
    if (Has-HermesConfig) {
        Assert-HermesEndpoint
        Write-Host 'H15_CODEX_HERMES_ENTRY=PRESENT'
    } else {
        Write-Host 'H15_CODEX_HERMES_ENTRY=ABSENT'
    }
    Write-Host 'H15_CODEX_PREFLIGHT=PASS'
}

switch ($Mode) {
    'Check' {
        Check
        Write-Host 'H15_CODEX_HOST_CHANGES=NONE'
    }
    'Install' {
        Check
        if (Has-HermesConfig) {
            Write-Host 'H15_CODEX_INSTALL=ALREADY_PRESENT_NO_CHANGE'
            break
        }
        if (Test-Path -LiteralPath $ConfigPath -PathType Leaf) {
            $backupDir = Join-Path $CodexRoot 'hermes-mcp-backups'
            if (-not (Test-Path -LiteralPath $backupDir)) {
                New-Item -ItemType Directory -Path $backupDir -ErrorAction Stop | Out-Null
            }
            $backup = Join-Path $backupDir ('config-' + [guid]::NewGuid().ToString('N') + '.toml')
            Copy-Item -LiteralPath $ConfigPath -Destination $backup -ErrorAction Stop
            $srcHash = (Get-FileHash -LiteralPath $ConfigPath -Algorithm SHA256).Hash
            $dstHash = (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash
            if ($srcHash -ne $dstHash) { Fail 'CONFIG_BACKUP_HASH_MISMATCH' }
            Write-Host 'H15_CODEX_CONFIG_BACKUP=PASS'
            Write-Host "H15_CODEX_BACKUP_LOCATION=$backup"
        } else {
            Write-Host 'H15_CODEX_CONFIG_BACKUP=NOT_REQUIRED_NO_EXISTING_CONFIG'
        }
        Native 'CODEX_MCP_ADD_FAILED' { & $script:Codex mcp add $ServerName --url $ServerUrl }
        if (-not (Has-HermesConfig)) { Fail 'CODEX_MCP_ENTRY_NOT_WRITTEN' }
        Assert-HermesEndpoint
        Write-Host 'H15_CODEX_MCP_ADDED=PASS'
        Write-Host 'H15_CODEX_OAUTH=REQUIRES_INTERACTIVE_LOGIN'
    }
    'Login' {
        Check
        if (-not (Has-HermesConfig)) { Fail 'ADD_SERVER_FIRST' }
        Write-Host 'H15_CODEX_OAUTH=STARTING_INTERACTIVE_BROWSER_FLOW'
        Native 'CODEX_MCP_LOGIN_FAILED' { & $script:Codex mcp login $ServerName }
        Write-Host 'H15_CODEX_OAUTH_COMMAND=PASS'
        Write-Host 'H15_CODEX_RESTART_CLIENT=RECOMMENDED'
    }
    'Status' {
        Check
        Native 'CODEX_MCP_LIST_FAILED' { & $script:Codex mcp list }
        Write-Host 'H15_CODEX_STATUS=PASS'
    }
}
