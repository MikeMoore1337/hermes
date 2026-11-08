#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$Source)
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
. $Source
$device='synthetic-device';$old='http://synthetic.invalid:1234';$token='brc_dev_'+('a'*43)
$fixture=[ordered]@{relayUrl=$old;deviceId=$device;deviceToken=$token;name='fixture "name": x';pairedAt='synthetic'}
$raw=ConvertTo-Json -InputObject $fixture -Compress
$converted=Convert-H454SecureCredential $raw $device $old | ConvertFrom-Json
if($converted.deviceId -cne $device -or $converted.deviceToken -cne $token -or
   $converted.name -cne $fixture.name -or $converted.pairedAt -cne 'manual' -or
   $converted.relayUrl -cne 'https://host.docker.internal:38184'){throw 'VALID_TRANSFORM'}
$bad=@(
 $raw.Replace('"deviceId":','"deviceId":"duplicate","deviceId":'),
 $raw.Replace('"deviceId":','"device\u0049d":"duplicate","deviceId":'),
 $raw.Replace('"deviceId":','"DeviceId":'),
 $raw.Replace('"pairedAt":','"extra":"x","pairedAt":'),
 $raw.Replace($token,'bad-token'),
 $raw.Replace($device,'other-device'),
 $raw.Replace($old,'https://other.invalid'),
 $raw.Replace('"pairedAt":"synthetic"','"pairedAt":null'),
 $raw.Substring(0,$raw.Length-1)+',}',
 ('x'*8193)
)
foreach($value in $bad){
    $refused=$false
    try { $null=Convert-H454SecureCredential $value $device $old } catch { $refused=$true }
    if(-not $refused){throw 'MALFORMED_CREDENTIAL_ACCEPTED'}
}
'PS51_SECURE_CREDENTIAL_TRANSFORM=PASS'
'REAL_CREDENTIALS_USED=FALSE'
