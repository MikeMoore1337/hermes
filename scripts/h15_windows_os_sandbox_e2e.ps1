#requires -Version 5.1
<#
  H-15 #371: disposable native Windows OS token/ACL negative acceptance.
  Runs on an isolated GitHub Actions Windows runner only.
  DOES NOT install/pair/reconfigure the owner's Windows Hermes agent.
#>
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$root = Join-Path $env:RUNNER_TEMP ("hermes-win-os-gate-" + [guid]::NewGuid().ToString('N'))
$workspace = Join-Path $root "workspace"
$privateDir = Join-Path $root "owner-private"
$protectedDir = Join-Path $root "protected-source"
$taskName = "HermesNativeSandboxGate-" + [guid]::NewGuid().ToString('N')
$systemPowerShell = Join-Path $env:WINDIR "System32\WindowsPowerShell\v1.0\powershell.exe"
$runner = Join-Path $workspace "run-native-test.ps1"
$child = Join-Path $workspace "child-negative.ps1"
$reportPath = Join-Path $workspace "report.json"
$registered = $false

function Invoke-AclCommand {
    param([string[]] $Arguments)
    & icacls.exe @Arguments | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "ICACLS_FAILED" }
}

try {
    foreach ($dir in @($root, $workspace, $privateDir, $protectedDir)) {
        New-Item -ItemType Directory -Path $dir -Force | Out-Null
    }
    [IO.File]::WriteAllText((Join-Path $privateDir 'secret.txt'), 'synthetic-private-canary')
    [IO.File]::WriteAllText((Join-Path $protectedDir 'readonly.txt'), 'synthetic-source-canary')

    # Native Windows kernel ACLs, not a Python/Node path allowlist.
    # Root itself must be traversable by LocalService but its children are
    # separate explicit scopes with no ambient inherited guest access.
    Invoke-AclCommand @($root, '/inheritance:r', '/grant:r',
        '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F',
        '*S-1-5-19:RX')
    Invoke-AclCommand @($workspace, '/inheritance:r', '/grant:r',
        '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F',
        '*S-1-5-19:(OI)(CI)M')
    Invoke-AclCommand @($privateDir, '/inheritance:r', '/grant:r',
        '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F')
    Invoke-AclCommand @($protectedDir, '/inheritance:r', '/grant:r',
        '*S-1-5-18:(OI)(CI)F', '*S-1-5-32-544:(OI)(CI)F',
        '*S-1-5-19:(OI)(CI)RX')
    # Explicitly protect leaf files too to avoid assumptions about
    # inherited ACL reconciliation on different Windows runner images.
    Invoke-AclCommand @((Join-Path $privateDir 'secret.txt'), '/inheritance:r', '/grant:r',
        '*S-1-5-18:F', '*S-1-5-32-544:F')
    Invoke-AclCommand @((Join-Path $protectedDir 'readonly.txt'), '/inheritance:r', '/grant:r',
        '*S-1-5-18:F', '*S-1-5-32-544:F', '*S-1-5-19:RX')

    # PowerShell subprocess is a real child of the scheduled LocalService
    # job: no fake identity, no mocking of Windows authorization.
    $childSource = @'
param(
    [Parameter(Mandatory=$true)][string] $Workspace,
    [Parameter(Mandatory=$true)][string] $PrivateDir,
    [Parameter(Mandatory=$true)][string] $ProtectedDir
)
$ErrorActionPreference = 'Stop'
function Can-Read([string] $File) {
    try { [void][IO.File]::ReadAllText($File); return $true }
    catch { return $false }
}
function Can-Write([string] $File) {
    try { [IO.File]::WriteAllText($File, 'sandbox-write'); return $true }
    catch { return $false }
}
$report = @{
    os_identity_sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    workspace_write = Can-Write (Join-Path $Workspace 'allowed-output.txt')
    protected_read = Can-Read (Join-Path $ProtectedDir 'readonly.txt')
    protected_write = Can-Write (Join-Path $ProtectedDir 'readonly.txt')
    private_read = Can-Read (Join-Path $PrivateDir 'secret.txt')
    private_write = Can-Write (Join-Path $PrivateDir 'attempted-write.txt')
}
$json = ConvertTo-Json -InputObject $report -Compress
[IO.File]::WriteAllText((Join-Path $Workspace 'report.json'), $json)
'@
    [IO.File]::WriteAllText($child, $childSource)

    $parentSource = @'
param(
    [Parameter(Mandatory=$true)][string] $Workspace,
    [Parameter(Mandatory=$true)][string] $PrivateDir,
    [Parameter(Mandatory=$true)][string] $ProtectedDir
)
$ErrorActionPreference = 'Stop'
$child = Join-Path $Workspace 'child-negative.ps1'
$shell = Join-Path $env:WINDIR 'System32\WindowsPowerShell\v1.0\powershell.exe'
& $shell -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $child -Workspace $Workspace -PrivateDir $PrivateDir -ProtectedDir $ProtectedDir
if ($LASTEXITCODE -ne 0) { throw "CHILD_PROCESS_FAILED" }
'@
    [IO.File]::WriteAllText($runner, $parentSource)

    $args = ('-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "{0}" -Workspace "{1}" -PrivateDir "{2}" -ProtectedDir "{3}"' -f $runner,$workspace,$privateDir,$protectedDir)
    $action = New-ScheduledTaskAction -Execute $systemPowerShell -Argument $args -WorkingDirectory $workspace
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\LOCAL SERVICE' -LogonType ServiceAccount -RunLevel Limited
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
    Register-ScheduledTask -TaskName $taskName -Action $action -Principal $principal -Settings $settings | Out-Null
    $registered = $true
    $task = Get-ScheduledTask -TaskName $taskName
    # Task Scheduler normalizes the account spelling (e.g. LocalService
    # without a space). Compare canonical Windows SID, not display names.
    $resolvedSid = if ($task.Principal.UserId -eq 'S-1-5-19') {
        'S-1-5-19'
    } else {
        ([Security.Principal.NTAccount]::new($task.Principal.UserId)).Translate(
            [Security.Principal.SecurityIdentifier]
        ).Value
    }
    if ($resolvedSid -ne 'S-1-5-19') {
        throw "SCHEDULED_TASK_PRINCIPAL_CHANGED"
    }
    Start-ScheduledTask -TaskName $taskName
    $deadline = (Get-Date).AddSeconds(70)
    while (!(Test-Path -LiteralPath $reportPath) -and (Get-Date) -lt $deadline) {
        Start-Sleep -Milliseconds 500
    }
    if (!(Test-Path -LiteralPath $reportPath)) {
        $info = Get-ScheduledTaskInfo -TaskName $taskName
        throw ("NATIVE_WIN_SANDBOX_TIMEOUT_LAST_RESULT={0}" -f $info.LastTaskResult)
    }
    $report = Get-Content -LiteralPath $reportPath -Raw | ConvertFrom-Json
    $truth = @{
        OS_LOCAL_SERVICE_TOKEN = ($report.os_identity_sid -eq 'S-1-5-19')
        OS_WORKSPACE_WRITE = ($report.workspace_write -eq $true)
        OS_PROTECTED_READ = ($report.protected_read -eq $true)
        OS_PROTECTED_WRITE_DENIED = ($report.protected_write -eq $false)
        OS_PRIVATE_READ_DENIED = ($report.private_read -eq $false)
        OS_PRIVATE_WRITE_DENIED = ($report.private_write -eq $false)
    }
    foreach ($name in @($truth.Keys | Sort-Object)) {
        if (!$truth[$name]) { throw ("{0}=FAIL" -f $name) }
        Write-Output ("{0}=PASS" -f $name)
    }
    Write-Output "HERMES_WINDOWS_NATIVE_OS_ACL_E2E=PASS"
}
finally {
    if ($registered) {
        Stop-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false -ErrorAction SilentlyContinue
    }
    if (Test-Path -LiteralPath $root) {
        Remove-Item -LiteralPath $root -Force -Recurse -ErrorAction SilentlyContinue
    }
}
