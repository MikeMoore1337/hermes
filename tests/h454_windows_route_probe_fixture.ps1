#requires -Version 5.1
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. (Join-Path $PSScriptRoot '..\scripts\h454_windows_original_restore.ps1')
function Require-H454([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
function Assert-H454RollbackAgentRoute { }
$script:calls=0
$probe={
    param([string[]]$Arguments,[byte[]]$InputBytes)
    Require-H454 ($Arguments[0] -ceq 'exec' -and $null -eq $InputBytes) 'FIXTURE_PROBE_INPUT'
    $script:calls++
    $outputs=@('{"hosts":false,"route":false,"addresses":["192.0.2.1"]}',
        'H454_DIRECT_UPSTREAM=REFUSED','H454_STAGE_EXTERNAL=REFUSED','H454_BROKER_LISTENERS=PASS')
    return [pscustomobject]@{Code=0;Output=$outputs[$script:calls-1]}
}
$snapshot=[pscustomobject]@{
    Agent=[pscustomobject]@{State=[pscustomobject]@{Running=$true}}
    OnPrivate=$true;OnBridge=$false;Network=$null;Plan=[pscustomobject]@{Id='network';Cidr='192.0.2.0/24'}
    Broker=[pscustomobject]@{Id='broker';NetworkSettings=[pscustomobject]@{Networks=[pscustomobject]@{
        fixture=[pscustomobject]@{IPAddress='192.0.2.2'};bridge=[pscustomobject]@{IPAddress='192.0.2.3'}
    }}}
    NetworkName='fixture';Label='label';Bridge=[pscustomobject]@{Id='bridge'};HostAddress='192.0.2.4'
}
Assert-H454OriginalLiveRoute $snapshot 'agent' ('A'*64) $probe
Require-H454 ($script:calls -eq 4) 'FIXTURE_PROBE_COUNT'
'PS51_SYNTHETIC_ROUTE_PROBE_INJECTION=PASS'
