#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$Launcher)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'
Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
$tokens = $null; $errors = $null
$ast = [Management.Automation.Language.Parser]::ParseFile($Launcher, [ref]$tokens, [ref]$errors)
if (@($errors).Count -ne 0) { throw 'FIXTURE_PARSE' }
$functions = @($ast.FindAll({ param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $x.Name -ceq 'Restart-H454WssTunnel' }, $true))
$loops = @($ast.FindAll({ param($x) $x -is [Management.Automation.Language.WhileStatementAst] -and
    $x.Extent.Text.StartsWith('while ($true) {') }, $true))
$cleanups = @($ast.FindAll({ param($x) $x -is [Management.Automation.Language.TryStatementAst] -and
    $null -ne $x.Finally -and $x.Finally.Extent.Text.Contains('if (-not $h454KeepContainer)') }, $true))
$stateHelpers = @($ast.FindAll({ param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $x.Name -ceq 'Save-H454State' }, $true))
$claimHelpers = @($ast.FindAll({ param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $x.Name -ceq 'Stop-H454PreservedContainer' }, $true))
if ($functions.Count -ne 1 -or $loops.Count -ne 1 -or $cleanups.Count -ne 1 -or $stateHelpers.Count -ne 1 -or
    $claimHelpers.Count -ne 1) { throw 'FIXTURE_SCOPE' }
. ([scriptblock]::Create($functions[0].Extent.Text))
function Require([bool]$Condition, [string]$Code) { if (-not $Condition) { throw $Code } }

$script:starts = 0; $script:healthCalls = 0; $script:saves = 0
$script:badIdentity = $false; $script:alwaysUnhealthy = $false
$script:h454WssRetryReported = $false
$script:stopped = [Collections.Generic.List[int]]::new()
$script:expectedHash = 'A' * 64
$script:h454SshExe = 'synthetic-ssh'
$script:h454DockerHost = 'synthetic-docker'
$script:h454Docker = { $global:LASTEXITCODE = 0; 'true' }
$CONTAINER = 'synthetic-container'
$sshArgs = @('synthetic-arguments')
$state = [pscustomobject]@{tunnelPid=101; tunnelCreatedUtcTicks=1}
$h454StateHash = $script:expectedHash
$SSH_PROCESS = [pscustomobject]@{Id=101; HasExited=$true; Handle=[IntPtr]101; StartTime=[DateTime]::UtcNow}

function Stop-H454TunnelHandle([object]$Process) {
    if ($null -ne $Process) { $script:stopped.Add($Process.Id); $Process.HasExited = $true }
}
function Start-Process {
    param([string]$FilePath, [string[]]$ArgumentList, [switch]$PassThru, [string]$WindowStyle)
    Require ($FilePath -ceq 'synthetic-ssh' -and $ArgumentList[0] -ceq 'synthetic-arguments' -and
        $PassThru -and $WindowStyle -ceq 'Hidden') 'FIXTURE_START_ARGUMENTS'
    $script:starts++
    return [pscustomobject]@{Id=(200 + $script:starts); HasExited=($script:starts -eq 1);
        Handle=[IntPtr](200 + $script:starts); StartTime=[DateTime]::UtcNow}
}
function Start-Sleep {
    param([int]$Seconds)
    if ($Seconds -eq 20) { throw 'FIXTURE_DONE' }
    Require ($Seconds -in @(1,5)) 'FIXTURE_SLEEP'
}
function Test-LocalHealth {
    $script:healthCalls++
    if ($script:alwaysUnhealthy) { return $false }
    return ($script:healthCalls -ne 2)
}
function Assert-H454StartedTunnel([object]$Process) {
    Require ($null -ne $Process -and -not $Process.HasExited) 'FIXTURE_PROCESS'
    if ($script:badIdentity) { throw 'FIXTURE_LISTENER_CONFLICT' }
}
function Save-H454State([string]$ExpectedHash, [object]$Value) {
    Require ($ExpectedHash -ceq $script:expectedHash -and $Value.tunnelPid -eq (200 + $script:starts)) 'FIXTURE_STATE'
    $script:saves++
    $script:expectedHash = if ($script:saves -eq 1) { 'B' * 64 } else { 'C' * 64 }
    return $script:expectedHash
}

$script:claims = 0
function Stop-H454PreservedContainer([switch]$Claim) {
    Require ($Claim -and $script:starts -eq 2 -and $script:healthCalls -eq 1) 'FIXTURE_EARLY_CLAIM'
    $script:claims++
}
$startText = '$SSH_PROCESS = Restart-H454WssTunnel $null $sshArgs'
$endText = 'Stop-H454PreservedContainer -Claim'
$start = $ast.Extent.Text.IndexOf($startText, [StringComparison]::Ordinal)
$end = $ast.Extent.Text.IndexOf($endText, $start, [StringComparison]::Ordinal)
Require ($start -ge 0 -and $end -gt $start) 'FIXTURE_STARTUP_SCOPE'
. ([scriptblock]::Create($ast.Extent.Text.Substring($start, $end + $endText.Length - $start)))
Require ($script:claims -eq 1 -and $SSH_PROCESS.Id -eq 202 -and ($script:stopped -join ',') -ceq '201') 'FIXTURE_STARTUP_RETRY'
$script:starts = 0; $script:healthCalls = 0; $script:stopped.Clear()
$SSH_PROCESS = [pscustomobject]@{Id=101; HasExited=$true; Handle=[IntPtr]101; StartTime=[DateTime]::UtcNow}

try { . ([scriptblock]::Create($loops[0].Extent.Text)); throw 'FIXTURE_LOOP_EXITED' }
catch { if ($_.Exception.Message -cne 'FIXTURE_DONE') { throw } }
Require ($script:starts -eq 3 -and $script:saves -eq 2 -and $state.tunnelPid -eq 203 -and
    $h454StateHash -ceq ('C' * 64) -and ($script:stopped -join ',') -ceq '101,201,202') 'FIXTURE_RECONNECT'
Require (-not $SSH_PROCESS.HasExited -and $SSH_PROCESS.Id -eq 203) 'FIXTURE_ACTIVE_PROCESS'

$script:badIdentity = $true
$next = Restart-H454WssTunnel $null $sshArgs
Require ($null -eq $next -and $script:stopped[-1] -eq 204 -and $script:saves -eq 2) 'FIXTURE_FOREIGN_LISTENER'
$script:badIdentity = $false; $script:alwaysUnhealthy = $true
$before = $script:healthCalls
$next = Restart-H454WssTunnel $null $sshArgs
Require ($null -eq $next -and $script:stopped[-1] -eq 205 -and $script:saves -eq 2 -and
    ($script:healthCalls - $before) -eq 15) 'FIXTURE_UNHEALTHY_TIMEOUT'

. ([scriptblock]::Create($claimHelpers[0].Extent.Text))
$script:h454ContainerId = $null; $script:h454PreflightContainerId = 'a' * 64
$script:containerStopIds = [Collections.Generic.List[string]]::new()
function Get-H454PreservedContainer { return $script:fixtureContainer }
function Invoke-H454Docker([string[]]$Arguments) {
    Require ($Arguments[-2] -ceq '20') 'FIXTURE_CONTAINER_STOP_ARGUMENTS'
    $script:containerStopIds.Add($Arguments[-1])
    return [pscustomobject]@{Code=0}
}
$script:fixtureContainer = [pscustomobject]@{Id=('b' * 64); State=[pscustomobject]@{Running=$true}}
$refused = $false
try { Stop-H454PreservedContainer -Claim } catch { $refused = $true }
Require ($refused -and $script:containerStopIds.Count -eq 0) 'FIXTURE_CONTAINER_SUBSTITUTION'
$script:fixtureContainer = $null; $refused = $false
try { Stop-H454PreservedContainer -Claim } catch { $refused = $true }
Require ($refused -and $script:containerStopIds.Count -eq 0) 'FIXTURE_CONTAINER_DISAPPEARED'
$script:fixtureContainer = [pscustomobject]@{Id=('a' * 64); State=[pscustomobject]@{Running=$true}}
Stop-H454PreservedContainer -Claim
Require ($script:containerStopIds.Count -eq 1 -and $script:containerStopIds[0] -ceq ('a' * 64)) 'FIXTURE_CONTAINER_ID'
$script:h454ContainerId = $null; $script:h454PreflightContainerId = $null; $refused = $false
try { Stop-H454PreservedContainer -Claim } catch { $refused = $true }
Require ($refused -and $script:containerStopIds.Count -eq 1) 'FIXTURE_CONTAINER_APPEARED'

$cleanupText = $cleanups[0].Finally.Extent.Text
$cleanup = [scriptblock]::Create($cleanupText.Substring(1, $cleanupText.Length - 2))
$script:containerStops = 0; $script:h454OriginalTunnel = $null
function Stop-H454PreservedContainer { $script:containerStops++ }
$h454KeepContainer = $true
. $cleanup
Require ($script:containerStops -eq 0 -and $script:stopped[-1] -eq 203) 'FIXTURE_KEEP_CONTAINER'
$h454KeepContainer = $false; $SSH_PROCESS = $null
. $cleanup
Require ($script:containerStops -eq 1) 'FIXTURE_STARTUP_CLEANUP'

$stopHelpers = @($ast.FindAll({ param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst] -and
    $x.Name -ceq 'Stop-H454TunnelHandle' }, $true))
Require ($stopHelpers.Count -eq 1) 'FIXTURE_STOP_SCOPE'
. ([scriptblock]::Create($stopHelpers[0].Extent.Text))
function Start-Process {
    param([string]$FilePath, [string[]]$ArgumentList, [switch]$PassThru, [string]$WindowStyle)
    return Microsoft.PowerShell.Management\Start-Process -FilePath $script:fixturePowerShell `
        -ArgumentList '-NoProfile -NonInteractive -Command Start-Sleep -Seconds 30' -PassThru -WindowStyle Hidden
}
function Test-LocalHealth { return $true }
function Assert-H454StartedTunnel([object]$Process) { Require ($null -ne $Process -and -not $Process.HasExited) 'FIXTURE_CHILD' }
$script:fixturePowerShell = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$oldChild = $null; $newChild = $null
try {
    $oldChild = Start-Process -FilePath 'fixture' -ArgumentList @('fixture') -PassThru -WindowStyle Hidden
    $oldId = $oldChild.Id; $null = $oldChild.Handle
    $oldChild.Kill(); Require ($oldChild.WaitForExit(5000)) 'FIXTURE_CHILD_EXIT'
    $previousChild = $oldChild; $oldChild = $null
    $newChild = Restart-H454WssTunnel $previousChild $sshArgs
    Require ($null -ne $newChild -and $newChild.Id -ne $oldId -and -not $newChild.HasExited) 'FIXTURE_CHILD_RESTART'
} finally {
    if ($null -ne $newChild) { Stop-H454TunnelHandle $newChild }
    if ($null -ne $oldChild) { Stop-H454TunnelHandle $oldChild }
}

. ([scriptblock]::Create($stateHelpers[0].Extent.Text))
function Assert-H454PrivateState([string]$Path) { Require ([IO.File]::Exists($Path)) 'FIXTURE_STATE_FILE' }
$STATE_PATH = Join-Path ([IO.Path]::GetDirectoryName($Launcher)) 'fixture-state.json'
[IO.File]::WriteAllText($STATE_PATH, '{"tunnelPid":101}', [Text.UTF8Encoding]::new($false))
$oldHash = (Get-FileHash -LiteralPath $STATE_PATH).Hash
$newHash = Save-H454State $oldHash ([pscustomobject]@{tunnelPid=203})
Require ($newHash -ceq (Get-FileHash -LiteralPath $STATE_PATH).Hash -and $newHash -cne $oldHash) 'FIXTURE_STATE_HASH'
[IO.File]::WriteAllText($STATE_PATH, 'external-change', [Text.UTF8Encoding]::new($false))
$refused = $false
try { $null = Save-H454State $newHash ([pscustomobject]@{tunnelPid=204}) } catch { $refused = $true }
Require ($refused -and [IO.File]::ReadAllText($STATE_PATH) -ceq 'external-change') 'FIXTURE_STATE_DRIFT'
Write-Output 'H454_WSS_RECONNECT_FIXTURE=PASS'
