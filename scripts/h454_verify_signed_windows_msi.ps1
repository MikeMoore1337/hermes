# H454: SignPath Foundation release verifier for MSI and embedded EXE.
# Runs on disposable Windows CI only; performs administrative extraction, not installation.
param(
    [Parameter(Mandatory=$true)][string]$MsiPath,
    [Parameter(Mandatory=$true)][string]$ExpectedSha,
    [Parameter(Mandatory=$true)][string]$OutputDir
)
$ErrorActionPreference = 'Stop'
function Deny([string]$reason) { throw ('H454_SIGNPATH_RELEASE_HOLD_' + $reason) }
try {
    if ($env:RUNNER_OS -ne 'Windows' -or
        $ExpectedSha -cnotmatch '^[a-f0-9]{40}$') { Deny 'RUNNER_OR_SHA' }
    $temp = [IO.Path]::GetFullPath($env:RUNNER_TEMP).TrimEnd('\') + '\'
    $msi = [IO.Path]::GetFullPath($MsiPath)
    $output = [IO.Path]::GetFullPath($OutputDir)
    if (-not $msi.StartsWith($temp, [StringComparison]::OrdinalIgnoreCase) -or
        -not $output.StartsWith($temp, [StringComparison]::OrdinalIgnoreCase) -or
        $msi -eq $output -or
        -not (Test-Path -LiteralPath $msi -PathType Leaf) -or
        (Test-Path -LiteralPath $output) -or
        [IO.Path]::GetExtension($msi) -cne '.msi') {
        Deny 'ARTIFACT_SCOPE'
    }
    function VerifyAuthenticode([string]$file) {
        $signature = Get-AuthenticodeSignature -LiteralPath $file
        if ($signature.Status -ne 'Valid' -or
            $null -eq $signature.SignerCertificate -or
            $signature.SignerCertificate.Subject -notmatch '(?i)SignPath Foundation' -or
            $null -eq $signature.TimeStamperCertificate) {
            Deny 'TRUSTED_SIGNATURE_REQUIRED'
        }
        return $signature.SignerCertificate.Thumbprint
    }
    $msiThumbprint = VerifyAuthenticode $msi
    $windowsInstaller = Join-Path $env:WINDIR 'System32\msiexec.exe'
    $quotedMsi = '"' + $msi + '"'
    $quotedOutput = 'TARGETDIR="' + $output + '"'
    $arguments = @('/a', $quotedMsi, '/qn', '/norestart',
                   $quotedOutput, 'REBOOT=ReallySuppress')
    $run = Start-Process -FilePath $windowsInstaller -ArgumentList $arguments -PassThru -Wait -NoNewWindow
    if ($run.ExitCode -ne 0) { Deny 'EXTRACT_FAILED' }
    $executables = @(Get-ChildItem -LiteralPath $output -Recurse -File |
        Where-Object { $_.Name -ceq 'HermesCommanderNativeService.exe' })
    if ($executables.Count -ne 1) { Deny 'EXACT_EXE_MISSING' }
    $exe = $executables[0].FullName
    $exeThumbprint = VerifyAuthenticode $exe
    if ($exeThumbprint -cne $msiThumbprint) { Deny 'PUBLISHER_MISMATCH' }
    $selftest = Start-Process -FilePath $exe -ArgumentList @('--self-test', $ExpectedSha) -PassThru -Wait
    if ($selftest.ExitCode -ne 0) { Deny 'SOURCE_SHA_MISMATCH' }
    $receipt = @{
        schema = 'h454-signed-msi-receipt-v1'
        source_sha = $ExpectedSha
        msi_sha256 = (Get-FileHash -LiteralPath $msi -Algorithm SHA256).Hash.ToLowerInvariant()
        exe_sha256 = (Get-FileHash -LiteralPath $exe -Algorithm SHA256).Hash.ToLowerInvariant()
        signer_thumbprint = $msiThumbprint
        msi_valid = $true
        exe_valid = $true
        installed_on_owner_host = $false
    } | ConvertTo-Json -Compress
    $receiptFile = Join-Path $temp 'h454-signed-msi-receipt.json'
    if (Test-Path -LiteralPath $receiptFile) { Deny 'RECEIPT_COLLISION' }
    [IO.File]::WriteAllText($receiptFile, $receipt, [Text.Encoding]::ASCII)
    Write-Output 'H454_SIGNPATH_MSI_AND_EXE_VALID=PASS'
    Write-Output 'H454_SIGNPATH_OWNER_HOST_NOT_INSTALLED=YES'
} catch {
    Write-Error -Message 'H454_SIGNPATH_RELEASE_HOLD' -ErrorAction Continue
    exit 2
}
