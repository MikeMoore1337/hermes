#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$SecureSource,[Parameter(Mandatory=$true)][string]$BrokerSource)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. $SecureSource
. $BrokerSource
$token='brc_dev_'+('a'*43);$device='synthetic-device';$relay='http://host.docker.internal:38180'
$raw=ConvertTo-Json -Compress -InputObject ([ordered]@{relayUrl=$relay;deviceId=$device;
    deviceToken=$token;name='fixture "name"';pairedAt='before'})
$result=Convert-H454BrokerCredential $raw $device
try{
    $gotToken=[Text.Encoding]::UTF8.GetString($result.TokenBytes)
    $agentText=[Text.Encoding]::UTF8.GetString($result.AgentBytes)
    $agent=ConvertFrom-Json -InputObject $agentText
    if($gotToken -cne $token -or $agentText.Contains($token) -or
        $agent.deviceToken -cne ('brc_dev_'+('s'*43)) -or $agent.deviceId -cne $device -or
        $agent.relayUrl -cne $relay -or $agent.name -cne 'fixture "name"' -or $agent.pairedAt -cne 'manual'){
        throw 'BROKER_CREDENTIAL_TRANSFORM'
    }
}finally{[Array]::Clear($result.TokenBytes,0,$result.TokenBytes.Length);[Array]::Clear($result.AgentBytes,0,$result.AgentBytes.Length)}
foreach($bad in @($raw.Replace($token,('brc_dev_'+('s'*43))),$raw.Replace($device,'other'),
    $raw.Replace($relay,'http://example.invalid'),$raw.Replace('"deviceId":','"deviceId":"duplicate","deviceId":'))){
    $refused=$false;try{$null=Convert-H454BrokerCredential $bad $device}catch{$refused=$true}
    if(-not $refused){throw 'BROKER_CREDENTIAL_NOT_REFUSED'}
}
'PS51_BROKER_CREDENTIAL_TRANSFORM=PASS'
'REAL_CREDENTIALS_USED=FALSE'
