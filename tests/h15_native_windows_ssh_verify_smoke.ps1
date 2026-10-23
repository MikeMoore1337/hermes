#requires -Version 5.1
# Hermes #454 synthetic Windows CI only. Never run on the owner PC.
# Creates throwaway keys and touches ACLs inside RUNNER_TEMP only.
$ErrorActionPreference = 'Stop'
if ($env:RUNNER_OS -ne 'Windows' -or [string]::IsNullOrWhiteSpace($env:RUNNER_TEMP)) {
    throw 'WINDOWS_CI_RUNNER_ONLY'
}
$originalProfile = $env:USERPROFILE
$root = Join-Path $env:RUNNER_TEMP ('h454-ssh-verify-' + [guid]::NewGuid().ToString('N'))
$sshDir = Join-Path $root '.ssh'
$key = Join-Path $sshDir 'hermes_h454_native_read_ed25519'
$operator = Join-Path $PSScriptRoot '..\scripts\h15_native_windows_ssh_identity.ps1'
$keygen = Join-Path $env:WINDIR 'System32\OpenSSH\ssh-keygen.exe'

function Assert-Verify([string]$ExpectedCrypto, [string]$ExpectedAcl, [int]$ExpectedCode) {
    $result = @(& powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $operator -Mode Verify)
    $code = $LASTEXITCODE
    $actual = $result -join ';'
    if ($code -ne $ExpectedCode -or
        $actual -notmatch "PRIVATE_KEY_ENCRYPTION=$ExpectedCrypto" -or
        $actual -notmatch "PRIVATE_KEY_ACL=$ExpectedAcl" -or
        $actual -notmatch 'SECURITY_INSPECTION=COMPLETE') {
        $allowed = @($result | Where-Object {
            $_ -match '^(PRIVATE_KEY_ENCRYPTION|PRIVATE_KEY_ACL|SECURITY_INSPECTION)=(PASS|FAIL|NOT_VERIFIED|NEEDS_REVIEW|COMPLETE)$'
        }) -join ';'
        Write-Output "H454_FIXTURE_ACTUAL_EXIT=$code"
        Write-Output "H454_FIXTURE_ACTUAL_STATUSES=$allowed"
        throw 'H454_SYNTHETIC_KEY_VERIFICATION_CONTRACT_FAILED'
    }
    $global:LASTEXITCODE = 0
}

try {
    New-Item -ItemType Directory -Path $sshDir -Force | Out-Null
    $env:USERPROFILE = $root
    # Synthetic passphrase, never a real user secret.
    & $keygen -q -t ed25519 -a 100 -N 'H454-SYNTHETIC-TEST-ONLY' -f $key -C 'h454-ci-fixture'
    if ($LASTEXITCODE -ne 0) { throw 'H454_FIXTURE_KEYGEN_FAILED' }

    $acl = Get-Acl -LiteralPath $key
    $acl.SetAccessRuleProtection($true, $false)
    $owner = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $rule = [Security.AccessControl.FileSystemAccessRule]::new(
        $owner,
        [Security.AccessControl.FileSystemRights]::FullControl,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $acl.SetAccessRule($rule)
    Set-Acl -LiteralPath $key -AclObject $acl
    Assert-Verify -ExpectedCrypto 'PASS' -ExpectedAcl 'PASS' -ExpectedCode 0
    Write-Output 'H454_SYNTHETIC_ENCRYPTED_KEY=PASS'

    $wideAcl = Get-Acl -LiteralPath $key
    $wide = [Security.AccessControl.FileSystemAccessRule]::new(
        [Security.Principal.SecurityIdentifier]::new('S-1-1-0'),
        [Security.AccessControl.FileSystemRights]::Read,
        [Security.AccessControl.AccessControlType]::Allow
    )
    $wideAcl.AddAccessRule($wide)
    Set-Acl -LiteralPath $key -AclObject $wideAcl
    Assert-Verify -ExpectedCrypto 'PASS' -ExpectedAcl 'NEEDS_REVIEW' -ExpectedCode 2
    Write-Output 'H454_SYNTHETIC_UNSAFE_ACL_DENIED=PASS'

    [System.IO.File]::WriteAllText($key, 'invalid-openssh-key')
    Assert-Verify -ExpectedCrypto 'NOT_VERIFIED' -ExpectedAcl 'NEEDS_REVIEW' -ExpectedCode 2
    Write-Output 'H454_SYNTHETIC_INVALID_KEY_DENIED=PASS'
}
finally {
    $env:USERPROFILE = $originalProfile
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction Stop
    }
}
Write-Output 'H454_SYNTHETIC_KEY_VERIFIER=PASS'
