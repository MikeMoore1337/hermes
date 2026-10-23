#requires -Version 5.1
<#
.SYNOPSIS
  Owner-side, disabled-by-default H15 Windows native-read-only SSH key operator.
.DESCRIPTION
  Preflight is read-only. Generate creates ONLY one dedicated Ed25519 keypair
  after a precise owner action approval. It never contacts a server, configures
  sshd, edits authorized_keys, starts a tunnel or launches the BRC agent.
  Never post private keys, passphrases or server credentials into chat/GitHub.
.LINK
  https://github.com/MikeMoore1337/hermes/issues/454
#>
[CmdletBinding()]
param(
    [ValidateSet('Preflight', 'Generate', 'Fingerprint')]
    [string]$Mode = 'Preflight',
    [switch]$OwnerApproved
)

$ErrorActionPreference = 'Stop'

function Deny([string]$Reason) {
    Write-Output "H454_SSH_IDENTITY=REFUSED:$Reason"
    exit 2
}

if ($Mode -eq 'Generate' -and -not $OwnerApproved) {
    Deny 'EXPLICIT_OWNER_APPROVAL_REQUIRED'
}
if ([string]::IsNullOrWhiteSpace($env:USERPROFILE) -or
    [string]::IsNullOrWhiteSpace($env:WINDIR)) {
    Deny 'WINDOWS_ENVIRONMENT_REQUIRED'
}
$sshDir = Join-Path $env:USERPROFILE '.ssh'
$privatePath = Join-Path $sshDir 'hermes_h454_native_read_ed25519'
$publicPath = "$privatePath.pub"

$directory = Get-Item -LiteralPath $sshDir -Force -ErrorAction SilentlyContinue
if ($null -eq $directory) {
    if ($Mode -eq 'Preflight') {
        Write-Output 'SSH_DIRECTORY=ABSENT'
        Write-Output 'H454_SSH_IDENTITY=NOT_READY'
        exit 0
    }
    Deny 'SSH_DIRECTORY_ABSENT_NO_AUTOCREATE'
}
if (-not $directory.PSIsContainer -or
    ($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
    Deny 'SSH_DIRECTORY_UNSAFE'
}
$private = Get-Item -LiteralPath $privatePath -Force -ErrorAction SilentlyContinue
$public = Get-Item -LiteralPath $publicPath -Force -ErrorAction SilentlyContinue
foreach ($item in @($private, $public)) {
    if ($null -ne $item -and
        ($item.PSIsContainer -or
         ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint))) {
        Deny 'IDENTITY_PATH_UNSAFE'
    }
}

$keygen = Join-Path $env:WINDIR 'System32\OpenSSH\ssh-keygen.exe'
if (-not (Test-Path -LiteralPath $keygen -PathType Leaf)) {
    Deny 'PINNED_SYSTEM_SSH_KEYGEN_MISSING'
}

if ($Mode -eq 'Preflight') {
    Write-Output 'SSH_DIRECTORY=PASS'
    if ($null -eq $private -and $null -eq $public) {
        Write-Output 'NEW_IDENTITY=ABSENT'
    } elseif ($null -ne $private -and $null -ne $public) {
        Write-Output 'NEW_IDENTITY=PRESENT'
    } else {
        Write-Output 'NEW_IDENTITY=PARTIAL_REFUSE_GENERATION'
    }
    Write-Output 'HOST_KEY_AND_ACL=NOT_VERIFIED'
    Write-Output 'H454_SSH_IDENTITY=PREFLIGHT_COMPLETE'
    exit 0
}

if ($Mode -eq 'Fingerprint') {
    if ($null -eq $public -or $null -eq $private) {
        Deny 'KEYPAIR_NOT_PRESENT'
    }
    # Public fingerprint only; no private-key output or external traffic.
    & $keygen -l -E sha256 -f $publicPath
    if ($LASTEXITCODE -ne 0) { Deny 'PUBLIC_KEY_FINGERPRINT_FAILED' }
    Write-Output 'H454_SSH_IDENTITY=FINGERPRINT_ONLY'
    exit 0
}

# Source-only install mode. Do not invoke this until the concrete Windows
# paths/operations have been separately approved by the owner.
if ($null -ne $private -or $null -ne $public) {
    Deny 'IDENTITY_ALREADY_EXISTS_OR_PARTIAL'
}
Write-Output 'H454_SSH_IDENTITY=GENERATE_EXPLICIT'
Write-Output 'SSH_KEY_TYPE=ed25519'
Write-Output 'PRIVATE_KEY_PASSPHRASE=INTERACTIVE_REQUIRED_DO_NOT_ENTER_BLANK'
Write-Output 'PRIVATE_KEY_AND_PUBLIC_KEY_PATHS=OWNER_USERPROFILE_SSH_ONLY'
# Deliberately omit -N to force interactive passphrase entry in owner console.
# No force overwrite: private/public paths were already checked as absent.
& $keygen -t ed25519 -a 100 -C 'hermes-h454-native-read-only' -f $privatePath
if ($LASTEXITCODE -ne 0) {
    Deny 'SSH_KEYGEN_FAILED_INSPECT_PARTIAL_OUTPUT_MANUALLY'
}
if (-not (Test-Path -LiteralPath $privatePath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $publicPath -PathType Leaf)) {
    Deny 'KEYPAIR_NOT_CREATED'
}
# Do not claim protection until post-generation OS ACL and non-empty
# passphrase have been independently verified. Never echo private material.
Write-Output 'KEYPAIR_CREATED=PASS'
Write-Output 'PRIVATE_KEY_ACL=NOT_VERIFIED'
Write-Output 'PASSPHRASE_ENCRYPTION=NOT_VERIFIED'
Write-Output 'VPS_AUTHORIZED_KEYS=NOT_MODIFIED'
Write-Output 'TUNNEL=NOT_STARTED'
Write-Output 'H454_SSH_IDENTITY=CREATED_PENDING_SECURITY_REVIEW'
