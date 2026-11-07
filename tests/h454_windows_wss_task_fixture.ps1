#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$Source,[Parameter(Mandatory=$true)][string]$GuardPath,
      [Parameter(Mandatory=$true)][string]$AnchorPath)
$ErrorActionPreference='Stop'
. $Source
function Require([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
$parts=Get-H454WssTaskGuardParts
Require ($parts.Guard -ceq [IO.File]::ReadAllText($GuardPath).Replace("`r`n","`n") -and
    $parts.Anchor -ceq [IO.File]::ReadAllText($AnchorPath).Replace("`r`n","`n")) 'FIXTURE_GUARD_DRIFT'
foreach($newline in @("`n","`r`n")){
    $anchor=$parts.Anchor.Replace("`n",$newline);$guard=$parts.Guard.Replace("`n",$newline)
    $before=[Text.Encoding]::UTF8.GetBytes(([string][char]0xfeff)+'before'+$newline+$anchor+'after'+$newline)
    $after=[Text.Encoding]::UTF8.GetBytes(([string][char]0xfeff)+'before'+$newline+$anchor+$guard+'after'+$newline)
    $prepared=New-H454WssGuardBytes $before
    Require ([Convert]::ToBase64String($prepared) -ceq [Convert]::ToBase64String($after)) 'FIXTURE_GUARD_PREPARE'
    Assert-H454WssTaskGuardBytes $before $after
    $refused=$false
    try{Assert-H454WssTaskGuardBytes $before ([Text.Encoding]::UTF8.GetBytes('invalid'))}catch{$refused=$_.Exception.Message -ceq 'H454_WSS_TASK_GUARD'}
    Require $refused 'FIXTURE_GUARD_REFUSAL'
}
$refused=$false
try{Register-H454WssTaskDisabled -OriginalLauncherSha256 ('A'*64)}catch{$refused=$_.Exception.Message -ceq 'H454_WSS_TASK_APPROVAL'}
Require $refused 'FIXTURE_APPROVAL'
$refused=$false
try{Register-H454WssTaskDisabled -OriginalLauncherSha256 'bad' -OwnerApproved}catch{$refused=$_.Exception.Message -ceq 'H454_WSS_TASK_PINS'}
Require $refused 'FIXTURE_PINS'
$user=[Security.Principal.WindowsIdentity]::GetCurrent().Name
$state=Join-Path ([Environment]::GetFolderPath('LocalApplicationData')) 'H454Fixture'
$path=Join-Path $state 'h454-wss-tunnel.ps1'
$digest='A'*64
$start=(Get-Date).AddMinutes(5)
$definition=New-H454WssTaskDefinition $path $digest $user $start
$exe=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\powershell.exe'
Require ($definition.Action.Execute -ceq $exe -and $definition.Action.Arguments -ceq
    ('-WindowStyle Hidden -NoProfile -NonInteractive -ExecutionPolicy Bypass -File "'+$path+'" -ConfigSha256 '+$digest)) 'FIXTURE_ACTION'
Require ([string]$definition.Principal.LogonType -ceq 'Interactive' -and
    [string]$definition.Principal.RunLevel -ceq 'Limited') 'FIXTURE_PRINCIPAL'
Require (-not $definition.Settings.Enabled -and $definition.Settings.ExecutionTimeLimit -ceq 'PT0S' -and
    [string]$definition.Settings.MultipleInstances -ceq 'IgnoreNew') 'FIXTURE_SETTINGS'
Require ($definition.Trigger.Repetition.Interval -ceq 'PT1M' -and
    [string]::IsNullOrEmpty([string]$definition.Trigger.Repetition.Duration) -and
    [string]::IsNullOrEmpty([string]$definition.Trigger.EndBoundary)) 'FIXTURE_TRIGGER'
foreach($case in @('hash','path','past','utc','principal')){
    $p=$path;$h=$digest;$u=$user;$t=$start
    switch($case){
        'hash' {$h='bad'}
        'path' {$p=Join-Path $state 'other.ps1'}
        'past' {$t=(Get-Date).AddMinutes(-1)}
        'utc' {$t=[DateTime]::UtcNow.AddMinutes(5)}
        'principal' {$u='H454_NONEXISTENT_USER'}
    }
    $expected=if($case -ceq 'principal'){'H454_WSS_TASK_PRINCIPAL'}else{'H454_WSS_TASK_INPUT'}
    $refused=$false
    try{$null=New-H454WssTaskDefinition $p $h $u $t}catch{$refused=$_.Exception.Message -ceq $expected}
    Require $refused 'FIXTURE_REFUSAL'
}
'H454_WSS_TASK_DEFINITION=PASS'
