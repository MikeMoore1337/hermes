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
    [ValidateSet('Preflight', 'Generate', 'Fingerprint', 'Verify')]
    [string]$Mode = 'Preflight',
    [switch]$OwnerApproved
)

$ErrorActionPreference = 'Stop'

function Deny([string]$Reason) {
    Write-Output "H454_SSH_IDENTITY=REFUSED:$Reason"
    exit 2
}

function Get-OpenSshCipher([string]$Path) {
    # Read-only inspection of the OpenSSH envelope, not key decryption.
    $pem = [System.IO.File]::ReadAllLines($Path)
    if ($pem.Length -lt 3 -or
        $pem[0] -ne '-----BEGIN OPENSSH PRIVATE KEY-----' -or
        $pem[$pem.Length - 1] -ne '-----END OPENSSH PRIVATE KEY-----') {
        throw 'INVALID_OPENSSH_PRIVATE_FORMAT'
    }
    $body = ($pem[1..($pem.Length - 2)] -join '')
    $data = [Convert]::FromBase64String($body)
    $magic = [Text.Encoding]::ASCII.GetBytes("openssh-key-v1$([char]0)")
    if ($data.Length -lt ($magic.Length + 8)) { throw 'SHORT_KEY' }
    for ($i = 0; $i -lt $magic.Length; $i++) {
        if ($data[$i] -ne $magic[$i]) { throw 'INVALID_KEY_MAGIC' }
    }
    $at = $magic.Length
    $length = ([int]$data[$at] -shl 24) -bor
              ([int]$data[$at + 1] -shl 16) -bor
              ([int]$data[$at + 2] -shl 8) -bor
              [int]$data[$at + 3]
    if ($length -lt 1 -or $length -gt 64 -or
        $data.Length -lt ($at + 4 + $length)) {
        throw 'INVALID_CIPHER_LENGTH'
    }
    return [Text.Encoding]::ASCII.GetString($data, $at + 4, $length)
}

function Test-KeyAcl([string]$Path) {
    # Conservative: current owner SID (not a group) plus SYSTEM and local
    # Administrators only. Inherited access for Everyone/Users is denied.
    $acl = Get-Acl -LiteralPath $Path
    $ownerSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    $actualOwner = $acl.GetOwner(
        [Security.Principal.SecurityIdentifier]
    ).Value
    if ($actualOwner -ne $ownerSid) { return $false }
    $trusted = @($ownerSid, 'S-1-5-18', 'S-1-5-32-544')
    foreach ($rule in $acl.Access) {
        if ($rule.AccessControlType -ne 'Allow') { continue }
        $ruleSid = $rule.IdentityReference.Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
        if ($trusted -notcontains $ruleSid) { return $false }
    }
    return $true
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
    if ($Mode -eq 'Verify') {
    # No ssh-keygen invocation, passphrase prompt, file mutation or network.
    # Keep both checks independent and return only bounded status markers.
    $cryptoStatus = 'NOT_VERIFIED'
    $aclStatus = 'NOT_VERIFIED'
    if ($null -ne $private -and $null -ne $public) {
        try {
            if ($private.Length -le 16384 -and $private.Length -gt 0) {
                $cipher = Get-OpenSshCipher -Path $privatePath
                if ($cipher -in @('aes256-ctr', 'aes256-gcm@openssh.com')) {
                    $cryptoStatus = 'PASS'
                } elseif ($cipher -eq 'none') {
                    $cryptoStatus = 'FAIL'
                }
            }
        } catch {
            $cryptoStatus = 'NOT_VERIFIED'
        }
        try {
            if (Test-KeyAcl -Path $privatePath) {
                $aclStatus = 'PASS'
            } else {
                $aclStatus = 'NEEDS_REVIEW'
            }
        } catch {
            $aclStatus = 'NOT_VERIFIED'
        }
    }
    Write-Output "PRIVATE_KEY_ENCRYPTION=$cryptoStatus"
    Write-Output "PRIVATE_KEY_ACL=$aclStatus"
    Write-Output 'SECURITY_INSPECTION=COMPLETE'
    if ($cryptoStatus -ne 'PASS' -or $aclStatus -ne 'PASS') {
        exit 2
    }
    exit 0
}

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
# Verify the private key container cipher without decrypting it.
# ssh-keygen may accept a blank passphrase, but this operator must not.
try {
    $cipher = Get-OpenSshCipher -Path $privatePath
} catch {
    Deny 'PRIVATE_KEY_ENCRYPTION_NOT_VERIFIED_REVIEW_MANUALLY'
}
if ($cipher -eq 'none') {
    Deny 'UNENCRYPTED_PRIVATE_KEY_OWNER_MUST_REMEDIATE_MANUALLY'
}
if ($cipher -notin @('aes256-ctr', 'aes256-gcm@openssh.com')) {
    Deny 'UNEXPECTED_PRIVATE_KEY_CIPHER'
}
Write-Output 'KEYPAIR_CREATED=PASS'
Write-Output 'PRIVATE_KEY_ACL=NOT_VERIFIED'
Write-Output 'PASSPHRASE_ENCRYPTION=PASS'
Write-Output 'VPS_AUTHORIZED_KEYS=NOT_MODIFIED'
Write-Output 'TUNNEL=NOT_STARTED'
Write-Output 'H454_SSH_IDENTITY=CREATED_PENDING_SECURITY_REVIEW'
