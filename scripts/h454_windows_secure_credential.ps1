#requires -Version 5.1
function Convert-H454SecureCredential([string]$InputJson,[string]$ExpectedDeviceId,[string]$ExpectedOldRelay) {
    if ([string]::IsNullOrWhiteSpace($InputJson) -or $InputJson.Length -gt 8192) { throw 'CREDENTIAL_FORMAT' }
    $value=$InputJson.Trim()
    if ($value.Length -lt 2 -or $value[0] -cne '{' -or $value[$value.Length-1] -cne '}') { throw 'CREDENTIAL_FORMAT' }
    $body=$value.Substring(1,$value.Length-2)
    $pattern='\G\s*"(?<key>relayUrl|deviceId|deviceToken|name|pairedAt)"\s*:\s*"(?:[^"\\\x00-\x1f]|\\["\\/bfnrt]|\\u[0-9A-Fa-f]{4})*"\s*(?<sep>,|$)'
    $regex=[regex]::new($pattern,[Text.RegularExpressions.RegexOptions]::None,[TimeSpan]::FromSeconds(1))
    $seen=[Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    $offset=0
    while ($offset -lt $body.Length) {
        try { $match=$regex.Match($body,$offset) } catch { throw 'CREDENTIAL_FORMAT' }
        if (-not $match.Success -or $match.Index -ne $offset -or -not $seen.Add($match.Groups['key'].Value)) { throw 'CREDENTIAL_FIELDS' }
        $offset+=$match.Length
        if ($match.Groups['sep'].Value -ceq ',' -and $offset -eq $body.Length) { throw 'CREDENTIAL_FIELDS' }
        if ($match.Groups['sep'].Value -ceq '' -and $offset -ne $body.Length) { throw 'CREDENTIAL_FIELDS' }
    }
    if ($seen.Count -ne 5) { throw 'CREDENTIAL_FIELDS' }
    try { $data=ConvertFrom-Json -InputObject $value -ErrorAction Stop }
    catch { throw 'CREDENTIAL_FORMAT' }
    if ($data.deviceId -cne $ExpectedDeviceId -or $data.relayUrl -cne $ExpectedOldRelay -or
        $data.deviceToken -cnotmatch '^brc_dev_[A-Za-z0-9_-]{40,256}$' -or
        $data.name.Length -gt 1024 -or $data.pairedAt.Length -gt 1024) { throw 'CREDENTIAL_IDENTITY' }
    $data.relayUrl='https://host.docker.internal:38184'
    $data.pairedAt='manual'
    try { return [string](ConvertTo-Json -InputObject $data -Compress -Depth 4 -ErrorAction Stop) }
    catch { throw 'CREDENTIAL_FORMAT' }
}
