#requires -Version 5.1
# Called only by a trusted operator holding the recovery lock.
function New-H454WssConfigBytes(
    [byte[]]$Original,[byte[]]$Guarded,[string]$CaSha256,[string]$IdentitySha256,
    [string]$NodeSha256,[string]$PublicKeySha256
) {
    foreach($hash in @($CaSha256,$IdentitySha256,$NodeSha256,$PublicKeySha256)){
        if($hash -cnotmatch '^[A-F0-9]{64}$'){throw 'H454_WSS_FILES_PINS'}
    }
    Assert-H454WssTaskGuardBytes $Original $Guarded
    $encoding=[Text.UTF8Encoding]::new($false,$true)
    try{$text=$encoding.GetString($Original)}catch{throw 'H454_WSS_FILES_SOURCE'}
    if($text.Length -gt 0 -and $text[0] -eq [char]0xfeff){$text=$text.Substring(1)}
    $hosts=@([regex]::Matches($text,'(?m)^\s*\$HOST_ADDR\s*=\s*''([^''\r\n]+)''\s*$'))
    $relays=@([regex]::Matches($text,'(?m)^\s*\$RELAY\s*=\s*''([^''\r\n]+)''\s*$'))
    $ports=@([regex]::Matches($text,'(?m)^\s*\$SSH_PORT\s*=\s*([0-9]{1,5})\s*$'))
    $targets=@([regex]::Matches($text,'(?m)^\s*\$TUNNEL_TARGET\s*=\s*"([^"]+)"\s*$'))
    if($hosts.Count -ne 1 -or $relays.Count -ne 1 -or $ports.Count -ne 1 -or $targets.Count -ne 1){throw 'H454_WSS_FILES_SOURCE'}
    $hostName=$hosts[0].Groups[1].Value;$relay=$relays[0].Groups[1].Value;$port=[int]$ports[0].Groups[1].Value
    if($hostName -cnotmatch '^[A-Za-z0-9.-]{1,253}$' -or $port -lt 1 -or $port -gt 65535 -or
        $relay -cnotmatch '^([0-9.]+):3000$'){throw 'H454_WSS_FILES_SOURCE'}
    $relayAddress=$Matches[1];$ip=$null
    if(-not [Net.IPAddress]::TryParse($relayAddress,[ref]$ip) -or $ip.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork -or
        $ip.ToString() -cne $relayAddress){throw 'H454_WSS_FILES_SOURCE'}
    $octets=$ip.GetAddressBytes()
    if(-not ($octets[0] -eq 10 -or ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or
        ($octets[0] -eq 192 -and $octets[1] -eq 168))){throw 'H454_WSS_FILES_SOURCE'}
    $target=$targets[0].Groups[1].Value.Replace('${HOST_ADDR}',$hostName).Replace('$HOST_ADDR',$hostName)
    if($target -cnotmatch '^([a-z_][a-z0-9_-]{0,63})@([A-Za-z0-9.-]{1,253})$' -or $Matches[2] -cne $hostName){throw 'H454_WSS_FILES_SOURCE'}
    $settings=[ordered]@{version=1;sshHost=$hostName;sshUser=$Matches[1];sshPort=$port;relayAddress=$relayAddress;
        caSha256=$CaSha256;identitySha256=$IdentitySha256;launcherSha256=(Hash-H454Bytes $Guarded);
        nodeSha256=$NodeSha256;publicKeySha256=$PublicKeySha256}
    $json=ConvertTo-Json -InputObject $settings -Compress -Depth 3
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($json)
    if($bytes.Length -gt 8192){throw 'H454_WSS_FILES_SIZE'}
    return ,$bytes
}

function Assert-H454WssNode([string]$ExpectedSha256) {
    $node=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'nodejs\node.exe'
    $item=Get-Item -LiteralPath $node -Force -ErrorAction Stop
    if($item.PSIsContainer){throw 'H454_WSS_FILES_NODE'}
    while($null -ne $item){
        if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'H454_WSS_FILES_NODE'}
        if($item -is [IO.FileInfo]){$item=$item.Directory}else{$item=$item.Parent}
    }
    if((Get-FileHash -LiteralPath $node -Algorithm SHA256).Hash -cne $ExpectedSha256 -or
        (Get-AuthenticodeSignature -LiteralPath $node).Status -ne 'Valid'){throw 'H454_WSS_FILES_NODE'}
}

function Install-H454WssFiles(
    [byte[]]$Supervisor,[byte[]]$Identity,[byte[]]$Module,[byte[]]$Ca,
    [string]$SupervisorSha256,[string]$IdentitySha256,[string]$ModuleSha256,[string]$CaSha256,
    [string]$NodeSha256,[string]$PublicKeySha256,[string]$OriginalLauncherSha256,[string]$GuardedLauncherSha256,
    [string]$MarkerSha256,[string]$BackupName,[IO.FileStream]$Lock,[switch]$Apply,[switch]$OwnerApproved
) {
    if($Apply -and -not $OwnerApproved){throw 'H454_WSS_TASK_APPROVAL'}
    foreach($hash in @($SupervisorSha256,$IdentitySha256,$ModuleSha256,$CaSha256,$NodeSha256,$PublicKeySha256,
        $OriginalLauncherSha256,$GuardedLauncherSha256,$MarkerSha256)){
        if($hash -cnotmatch '^[A-F0-9]{64}$'){throw 'H454_WSS_FILES_PINS'}
    }
    $expectedMarker=Get-H454WssMarkerText $OriginalLauncherSha256 $GuardedLauncherSha256 $BackupName
    foreach($pair in @(@($Supervisor,$SupervisorSha256,65536),@($Identity,$IdentitySha256,65536),
        @($Module,$ModuleSha256,16000),@($Ca,$CaSha256,65536))){
        if($null -eq $pair[0] -or $pair[0].Length -le 0 -or $pair[0].Length -gt $pair[2] -or
            (Hash-H454Bytes $pair[0]) -cne $pair[1]){throw 'H454_WSS_FILES_INPUT'}
    }
    $identityText=[Text.UTF8Encoding]::new($false,$true).GetString($Identity)
    $modulePins=@([regex]::Matches($identityText,'(?m)^\$script:h454ModuleHash = ''([A-F0-9]{64})''\r?$'))
    if($modulePins.Count -ne 1 -or $modulePins[0].Groups[1].Value -cne $ModuleSha256){throw 'H454_WSS_FILES_MODULE'}
    $caText=[Text.UTF8Encoding]::new($false,$true).GetString($Ca)
    if($caText -cnotmatch '\A-----BEGIN CERTIFICATE-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END CERTIFICATE-----\r?\n?\z'){
        throw 'H454_WSS_FILES_CA'
    }
    $context=Get-H454WssDisabledLegacy;$state=$context.StateDir
    Assert-H454RecoveryLock $state $Lock
    Assert-H454WssOriginalStopped
    $backup=Join-Path $state $BackupName;$marker=Join-Path $state 'h454-wss-transition.pending'
    $public=Join-Path $state 'wss-ssh-identity.pub'
    Assert-H454WssTaskFile $context.Launcher $GuardedLauncherSha256 200000
    Assert-H454WssTaskFile $backup $OriginalLauncherSha256 200000
    Assert-H454WssTaskFile $marker $MarkerSha256 4096
    Assert-H454WssTaskFile $public $PublicKeySha256 4096
    if([IO.File]::ReadAllText($marker) -cne $expectedMarker){
        throw 'H454_WSS_TASK_MARKER'
    }
    $publicText=[IO.File]::ReadAllText($public)
    if($publicText -cnotmatch '\Assh-ed25519 [A-Za-z0-9+/]{68} hermes-h454-wss\n\z'){throw 'H454_WSS_FILES_PUBLIC'}
    Assert-H454WssNode $NodeSha256
    $config=New-H454WssConfigBytes ([IO.File]::ReadAllBytes($backup)) ([IO.File]::ReadAllBytes($context.Launcher)) `
        $CaSha256 $IdentitySha256 $NodeSha256 $PublicKeySha256
    $configHash=Hash-H454Bytes $config
    $plan=@(
        [pscustomobject]@{Name='h454-wss-identity.ps1';Bytes=$Identity;Hash=$IdentitySha256;Limit=65536},
        [pscustomobject]@{Name='h454_windows_wss_identity.mjs';Bytes=$Module;Hash=$ModuleSha256;Limit=16000},
        [pscustomobject]@{Name='wss-relay-ca.pem';Bytes=$Ca;Hash=$CaSha256;Limit=65536},
        [pscustomobject]@{Name='h454-wss-tunnel.ps1';Bytes=$Supervisor;Hash=$SupervisorSha256;Limit=65536},
        [pscustomobject]@{Name='h454-wss-tunnel-config.json';Bytes=$config;Hash=$configHash;Limit=8192}
    )
    foreach($entry in $plan){
        $entry | Add-Member -NotePropertyName Exists -NotePropertyValue (Test-H454WssStateEntry $state $entry.Name)
        if($entry.Exists){Assert-H454WssTaskFile (Join-Path $state $entry.Name) $entry.Hash $entry.Limit}
    }
    if(-not $Apply){return [pscustomobject]@{Status='PREFLIGHT';ConfigSha256=$configHash;SupervisorSha256=$SupervisorSha256}}
    Assert-H454RecoveryLock $state $Lock
    Assert-H454WssLegacyUnchanged $context.Task $context.Sid
    Assert-H454WssOriginalStopped
    Assert-H454WssTaskFile $marker $MarkerSha256 4096
    Assert-H454WssTaskFile $context.Launcher $GuardedLauncherSha256 200000
    Assert-H454WssTaskFile $backup $OriginalLauncherSha256 200000
    Assert-H454WssTaskFile $public $PublicKeySha256 4096
    foreach($entry in $plan){
        $path=Join-Path $state $entry.Name
        $mode=if($entry.Exists){[IO.FileMode]::Open}else{[IO.FileMode]::CreateNew}
        $access=if($entry.Exists){[IO.FileAccess]::ReadWrite}else{[IO.FileAccess]::Write}
        $stream=[IO.File]::Open($path,$mode,$access,[IO.FileShare]::None)
        try{if(-not $entry.Exists){$stream.Write($entry.Bytes,0,$entry.Bytes.Length)};$stream.Flush($true)}finally{$stream.Dispose()}
        Assert-H454WssTaskFile $path $entry.Hash $entry.Limit
    }
    Assert-H454RecoveryLock $state $Lock
    Assert-H454WssLegacyUnchanged $context.Task $context.Sid
    Assert-H454WssOriginalStopped
    Assert-H454WssTaskFile $marker $MarkerSha256 4096
    return [pscustomobject]@{Status='FILES_READY';ConfigSha256=$configHash;SupervisorSha256=$SupervisorSha256}
}
