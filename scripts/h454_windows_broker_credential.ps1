#requires -Version 5.1
# The caller clears both byte arrays and does not log the returned object.
function Convert-H454BrokerCredential([string]$InputJson,[string]$ExpectedDeviceId) {
    $oldRelay='http://host.docker.internal:38180'
    $surrogate='brc_dev_'+('s'*43)
    $converted=Convert-H454SecureCredential $InputJson $ExpectedDeviceId $oldRelay
    $data=ConvertFrom-Json -InputObject $converted -ErrorAction Stop
    if($data.deviceToken -ceq $surrogate){throw 'CREDENTIAL_SURROGATE_COLLISION'}
    $token=[Text.UTF8Encoding]::new($false).GetBytes([string]$data.deviceToken)
    $data.deviceToken=$surrogate
    $data.relayUrl=$oldRelay
    $agent=$null
    try {
        $json=ConvertTo-Json -InputObject $data -Compress -Depth 4 -ErrorAction Stop
        $agent=[Text.UTF8Encoding]::new($false).GetBytes($json)
        if($token.Length -gt 264 -or $agent.Length -gt 16384){throw 'CREDENTIAL_SIZE'}
        return [pscustomobject]@{TokenBytes=$token;AgentBytes=$agent}
    } catch {
        [Array]::Clear($token,0,$token.Length)
        if($null -ne $agent){[Array]::Clear($agent,0,$agent.Length)}
        throw
    }
}
