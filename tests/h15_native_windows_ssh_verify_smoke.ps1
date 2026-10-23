#requires -Version 5.1
# Hermes #454 synthetic Windows CI only. Never execute on the owner's original
# PC: creates throwaway keys and mutates only RUNNER_TEMP fixture ACLs.
$ErrorActionPreference = 'Stop'
if (-not $env:RUNNER_TEMP -or $env:RUNNER_OS -ne 'Windows') {
    throw 'WINDOWS_CI_RUNNER_ONLY'
}
$originalProfile = $env:USERPROFILE
$root = Join-Path $env:RUNNER_TEMP ('h454-readonly-verification-' + [guid]::NewGuid().ToString('N'))
$sshDirectory = Join-Path $root '.ssh'
$private = Join-Path $sshDirectory 'hermes_h454_native_read_ed25519'
$operator = Join-Path $PSScriptRoot '..\scripts\h15_native_windows_ssh_identity.ps1'
$keygen = Join-Path $env:WINDIR 'System32\OpenSSH\ssh-keygen.exe'
function Assert-Verify([string]$Encrypted, [string]$Acl, [int]$ExpectedCode) {
    $result = @(& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $operator -Mode Verify)
    $code = $LASTEXITCODE
    $actual = $result -join [Environment]::NewLine
    if ($code -ne $ExpectedCode -or
        $actual -notmatch "PRIVATE_KEY_ENCRYPTION=$Encrypted" -or
        $actual -notmatch "PRIVATE_KEY_ACL=$Acl" -or
        $actual -notmatch 'SECURITY_INSPECTION=COMPLETE') {
        # Only bounded, vetted status markers; never emit fixture key material.
        $markers = @($result | Where-Object {
            $_ -match '^(PRIVATE_KEY_ENCRYPTION|PRIVATE_KEY_ACL|SECURITY_INSPECTION)=(PASS|FAIL|NOT_VERIFIED|NEEDS_REVIEW|COMPLETE)
    }
    $global:LASTEXITCODE = 0
}
try {
    New-Item -ItemType Directory -Path $sshDirectory -Force | Out-Null
    $env:USERPROFILE = $root
    # Never use any owner's personal SSH file or a live credential.
    & $keygen -q -t ed25519 -a 100 -N 'H454-SYNTHETIC-TEST-ONLY' -f $private -C 'h454-disposable-ci'
    if ($LASTEXITCODE -ne 0) { throw 'H454_FIXTURE_KEYGEN_FAILED' }

    $acl = Get-Acl -LiteralPath $private
    $acl.SetAccessRuleProtection($true, $false)
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $owner,
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $acl.SetAccessRule($rule)
    Set-Acl -LiteralPath $private -AclObject $acl
    Assert-Verify -Encrypted 'PASS' -Acl 'PASS' -ExpectedCode 0
    Write-Output 'H454_SYNTHETIC_ENCRYPTED_KEY=PASS'

    # Unsafe wide inherited/explicit allowance must never pass as protected.
    $wideAcl = Get-Acl -LiteralPath $private
    $wide = [Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
        [Security.AccessControl.FileSystemRights]::Read,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $wideAcl.AddAccessRule($wide)
    Set-Acl -LiteralPath $private -AclObject $wideAcl
    Assert-Verify -Encrypted 'PASS' -Acl 'NEEDS_REVIEW' -ExpectedCode 2
    Write-Output 'H454_SYNTHETIC_UNSAFE_ACL_DENIED=PASS'

    # Malformed fixture content must not be classified as encrypted. It may
    # be a broken or swapped key file, not a reason to weaken the check.
    [System.IO.File]::WriteAllText($private, 'not-an-openssh-key')
    Assert-Verify -Encrypted 'NOT_VERIFIED' -Acl 'NEEDS_REVIEW' -ExpectedCode 2
    Write-Output 'H454_SYNTHETIC_INVALID_KEY_DENIED=PASS'
}
finally {
    $env:USERPROFILE = $originalProfile
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
    }
}
Write-Output 'H454_SYNTHETIC_KEY_VERIFIER=PASS'

        }) -join ';'
        Write-Output "H454_FIXTURE_ACTUAL_EXIT=$code"
        Write-Output "H454_FIXTURE_ACTUAL_STATUSES=$markers"
        throw 'H454_SYNTHETIC_KEY_VERIFICATION_CONTRACT_FAILED'
    }
    $global:LASTEXITCODE = 0
}
try {
    New-Item -ItemType Directory -Path $sshDirectory -Force | Out-Null
    $env:USERPROFILE = $root
    # Never use any owner's personal SSH file or a live credential.
    & $keygen -q -t ed25519 -a 100 -N 'H454-SYNTHETIC-TEST-ONLY' -f $private -C 'h454-disposable-ci'
    if ($LASTEXITCODE -ne 0) { throw 'H454_FIXTURE_KEYGEN_FAILED' }

    $acl = Get-Acl -LiteralPath $private
    $acl.SetAccessRuleProtection($true, $false)
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $owner,
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $acl.SetAccessRule($rule)
    Set-Acl -LiteralPath $private -AclObject $acl
    Assert-Verify -Encrypted 'PASS' -Acl 'PASS' -ExpectedCode 0
    Write-Output 'H454_SYNTHETIC_ENCRYPTED_KEY=PASS'

    # Unsafe wide inherited/explicit allowance must never pass as protected.
    $wideAcl = Get-Acl -LiteralPath $private
    $wide = [Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
        [Security.AccessControl.FileSystemRights]::Read,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $wideAcl.AddAccessRule($wide)
    Set-Acl -LiteralPath $private -AclObject $wideAcl
    Assert-Verify -Encrypted 'PASS' -Acl 'NEEDS_REVIEW' -ExpectedCode 2
    Write-Output 'H454_SYNTHETIC_UNSAFE_ACL_DENIED=PASS'

    # Malformed fixture content must not be classified as encrypted. It may
    # be a broken or swapped key file, not a reason to weaken the check.
    [System.IO.File]::WriteAllText($private, 'not-an-openssh-key')
    Assert-Verify -Encrypted 'NOT_VERIFIED' -Acl 'NEEDS_REVIEW' -ExpectedCode 2
    Write-Output 'H454_SYNTHETIC_INVALID_KEY_DENIED=PASS'
}
finally {
    $env:USERPROFILE = $originalProfile
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
    }
}
Write-Output 'H454_SYNTHETIC_KEY_VERIFIER=PASS'
