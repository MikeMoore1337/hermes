#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$Source,[Parameter(Mandatory=$true)][string]$FixtureParent)
$ErrorActionPreference='Stop'
function Require([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
$sourceText=[IO.File]::ReadAllText($Source)
$errors=$null;$tokens=$null
[void][Management.Automation.Language.Parser]::ParseInput($sourceText,[ref]$tokens,[ref]$errors)
Require ($errors.Count -eq 0) 'FIXTURE_PARSE'
$configStart=$sourceText.IndexOf('    $settings=[Text.Encoding]',[StringComparison]::Ordinal)
$configEnd=$sourceText.IndexOf('    $launcher=Join-Path',$configStart,[StringComparison]::Ordinal)
$legacyStart=$sourceText.IndexOf('    $launcherText=',[StringComparison]::Ordinal)
$legacyEnd=$sourceText.IndexOf('    $system=',$legacyStart,[StringComparison]::Ordinal)
Require ($configStart -ge 0 -and $configEnd -gt $configStart -and $legacyStart -ge 0 -and $legacyEnd -gt $legacyStart) 'FIXTURE_SCOPE'
$configCheck=[scriptblock]::Create($sourceText.Substring($configStart,$configEnd-$configStart))
$legacyCheck=[scriptblock]::Create($sourceText.Substring($legacyStart,$legacyEnd-$legacyStart))
$parent=[IO.Path]::GetFullPath($FixtureParent)
$directory=Join-Path $parent ('h454-tunnel-fixture-'+[Guid]::NewGuid().ToString('N'))
Require ([IO.Path]::GetDirectoryName($directory) -ceq $parent -and -not (Test-Path -LiteralPath $directory)) 'FIXTURE_PATH'
[IO.Directory]::CreateDirectory($directory)|Out-Null
$config=Join-Path $directory 'config.json'
$launcher=Join-Path $directory 'launcher.ps1'
$settingsBase=@{version=1;sshHost='relay.example.test';sshUser='fixture';sshPort=2222;relayAddress='172.29.1.2';
    caSha256=('A'*64);identitySha256=('B'*64);launcherSha256=('C'*64);nodeSha256=('D'*64);publicKeySha256=('E'*64)}
$legacy=@'
$HOST_ADDR = 'relay.example.test'
$RELAY = '172.29.1.2:3000'
$SSH_PORT = 2222
$TUNNEL_TARGET = "fixture@$HOST_ADDR"
'@
[IO.File]::WriteAllText($launcher,$legacy,[Text.UTF8Encoding]::new($false))
function Write-Config([hashtable]$Value){[IO.File]::WriteAllText($config,($Value|ConvertTo-Json -Compress),[Text.UTF8Encoding]::new($false))}
try {
    Write-Config $settingsBase
    . $configCheck
    . $legacyCheck
    foreach($name in @('sshHost','sshUser','sshPort','relayAddress')){
        $copy=$settingsBase.Clone()
        $copy[$name]=if($name -ceq 'sshPort'){2223}elseif($name -ceq 'relayAddress'){'172.29.1.3'}else{'other'}
        Write-Config $copy
        . $configCheck
        $refused=$false
        try{. $legacyCheck}catch{$refused=$_.Exception.Message -ceq 'H454_TUNNEL_LAUNCHER_DRIFT'}
        Require $refused 'FIXTURE_LAUNCHER_DRIFT'
    }
    foreach($case in @('extra','invalidHost','publicAddress','invalidPort','badHash')){
        $copy=$settingsBase.Clone()
        switch($case){
            'extra' {$copy.extra='not-allowed'}
            'invalidHost' {$copy.sshHost='bad host'}
            'publicAddress' {$copy.relayAddress='8.8.8.8'}
            'invalidPort' {$copy.sshPort=0}
            'badHash' {$copy.caSha256='bad'}
        }
        Write-Config $copy
        $refused=$false
        try{. $configCheck}catch{$refused=$_.Exception.Message -ceq 'H454_TUNNEL_CONFIG'}
        Require $refused 'FIXTURE_CONFIG_REFUSAL'
    }
    $loopStart=$sourceText.IndexOf('$h454JobInitialized=$false',[StringComparison]::Ordinal)
    $tryStart=$sourceText.IndexOf('try {',$loopStart,[StringComparison]::Ordinal)
    $catchStart=$sourceText.LastIndexOf('}catch{',[StringComparison]::Ordinal)
    Require ($loopStart -ge 0 -and $tryStart -gt $loopStart -and $catchStart -gt $tryStart) 'FIXTURE_LOOP_SCOPE'
    $loop=$sourceText.Substring($loopStart,$tryStart-$loopStart)+@'
try {
    $script:h454Attempts++
    if($script:h454Attempts -eq 1){throw 'H454_FIXTURE_TRANSIENT'}
    'H454_WSS_TUNNEL=DISCONNECTED'
'@+$sourceText.Substring($catchStart)
    Require ($loop.Contains('Start-Sleep -Seconds 10')) 'FIXTURE_LOOP_DELAY'
    $loop=$loop.Replace('Start-Sleep -Seconds 10','if($script:h454Attempts -ge 3){break}')
    $script:h454Attempts=0
    $messages=@(& ([scriptblock]::Create($loop)))
    Require ($script:h454Attempts -eq 3 -and 'H454_TUNNEL_REASON=H454_FIXTURE_TRANSIENT' -in $messages -and
        @($messages | Where-Object {$_ -ceq 'H454_WSS_TUNNEL=DISCONNECTED'}).Count -eq 2) 'FIXTURE_LOOP_RETRY'
    'H454_WSS_TUNNEL_FIXTURE=PASS'
}finally{
    foreach($file in @($config,$launcher)){if(Test-Path -LiteralPath $file){Remove-Item -LiteralPath $file -Force}}
    if(Test-Path -LiteralPath $directory){[IO.Directory]::Delete($directory,$false)}
}
