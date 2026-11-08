#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$GuardPath,
      [Parameter(Mandatory=$true)][string]$FixtureParent)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
function Require([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
$parent=[IO.Path]::GetFullPath($FixtureParent)
Require ([IO.Directory]::Exists($parent)) 'FIXTURE_PARENT_MISSING'
Require (-not ((Get-Item -LiteralPath $parent -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) 'FIXTURE_PARENT_REPARSE'
$fixture=Join-Path $parent ('guard-fixture-'+[Guid]::NewGuid().ToString('N'))
Require ($fixture.StartsWith($parent+'\',[StringComparison]::OrdinalIgnoreCase) -and
    -not [IO.Directory]::Exists($fixture)) 'FIXTURE_PATH'
[IO.Directory]::CreateDirectory($fixture)|Out-Null
$STATE_PATH=Join-Path $fixture 'state.json'
$marker=Join-Path $fixture 'H454-WSS-TRANSITION.PENDING'
$guard=[scriptblock]::Create([IO.File]::ReadAllText($GuardPath))
$created=[Collections.Generic.List[string]]::new()
try {
    & $guard
    [IO.File]::WriteAllText($marker,'synthetic')
    $refused=$false
    try { & $guard } catch { $refused=$_.Exception.Message -match 'H454_RECOVERY_REQUIRED' }
    Require $refused 'FILE_MARKER_NOT_REFUSED'
    [IO.File]::Delete($marker)
    [IO.Directory]::CreateDirectory($marker)|Out-Null
    $refused=$false
    try { & $guard } catch { $refused=$_.Exception.Message -match 'H454_RECOVERY_REQUIRED' }
    Require $refused 'DIRECTORY_MARKER_NOT_REFUSED'
    [IO.Directory]::Delete($marker)
    for($i=0;$i -lt 513;$i++){
        $path=Join-Path $fixture ('fixture-'+$i.ToString('D3'))
        [IO.File]::WriteAllText($path,'x');$created.Add($path)
    }
    $refused=$false
    try { & $guard } catch { $refused=$_.Exception.Message -match 'H454_STATE_DIRECTORY_OVERSIZE' }
    Require $refused 'OVERSIZE_NOT_REFUSED'
    foreach($path in $created){[IO.File]::Delete($path)}
    $created.Clear()
    [IO.Directory]::Delete($fixture)
    $refused=$false
    try { & $guard } catch { $refused=$true }
    Require $refused 'MISSING_PARENT_NOT_REFUSED'
    'PS51_MAINTENANCE_GUARD=PASS'
} finally {
    foreach($path in $created){[IO.File]::Delete($path)}
    if([IO.File]::Exists($marker)){[IO.File]::Delete($marker)}
    if([IO.Directory]::Exists($marker)){[IO.Directory]::Delete($marker)}
    if([IO.Directory]::Exists($fixture)){[IO.Directory]::Delete($fixture)}
}
