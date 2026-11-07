#requires -Version 5.1
# Docker administrator and the supplied, freshly inspected object remain trusted.
function Get-H454IPv4Number([string]$Address) {
    $ip=$null
    Require-H454 ([Net.IPAddress]::TryParse($Address,[ref]$ip) -and
        $ip.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
        $ip.ToString() -ceq $Address) 'ROLLBACK_NETWORK_ADDRESS'
    $b=$ip.GetAddressBytes()
    return (([uint64]$b[0] -shl 24) -bor ([uint64]$b[1] -shl 16) -bor ([uint64]$b[2] -shl 8) -bor [uint64]$b[3])
}

function Test-H454PrivateIPv4([uint64]$Number) {
    $a=$Number -shr 24;$b=($Number -shr 16) -band 255
    return ($a -eq 10 -or ($a -eq 172 -and $b -ge 16 -and $b -le 31) -or ($a -eq 192 -and $b -eq 168))
}

function Assert-H454InternalNetworkMembers(
    [object]$Network, [string]$NetworkId, [string]$NetworkName,
    [string]$LabelName, [string]$LabelValue, [string]$AgentId, [string]$ProxyId
) {
    Require-H454 ($NetworkId -cmatch '^[a-f0-9]{64}$' -and
        $AgentId -cmatch '^[a-f0-9]{64}$' -and $ProxyId -cmatch '^[a-f0-9]{64}$' -and
        $AgentId -cne $ProxyId -and $NetworkName -cmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,127}$' -and
        $LabelName -cmatch '^com\.hermes\.h454\.[a-z][a-z0-9.-]{0,40}$' -and
        $LabelValue -cmatch '^[a-f0-9]{32}$') 'ROLLBACK_NETWORK_PINS'
    Require-H454 ($null -ne $Network -and $Network.Id -ceq $NetworkId -and $Network.Name -ceq $NetworkName -and
        $Network.Driver -ceq 'bridge' -and $Network.Internal -is [bool] -and $Network.Internal -eq $true -and
        $Network.EnableIPv6 -is [bool] -and $Network.EnableIPv6 -eq $false) 'ROLLBACK_NETWORK_DRIFT'
    $label=if($null -ne $Network.Labels){$Network.Labels.PSObject.Properties[$LabelName]}else{$null}
    Require-H454 ($null -ne $label -and $label.Value -is [string] -and $label.Value -ceq $LabelValue) 'ROLLBACK_NETWORK_LABEL'
    Require-H454 ($null -ne $Network.Containers) 'ROLLBACK_NETWORK_MEMBERS'
    $ids=@($Network.Containers.PSObject.Properties | ForEach-Object { $_.Name })
    Require-H454 ($ids.Count -eq 2 -and $ids -ccontains $AgentId -and $ids -ccontains $ProxyId) 'ROLLBACK_NETWORK_MEMBERS'
}

function Assert-H454RollbackAgentRoute(
    [object]$Network,[object]$Agent,[object]$Proxy,
    [string]$NetworkId,[string]$NetworkName,[string]$LabelName,[string]$LabelValue,
    [string]$AgentId,[string]$ProxyId,[string]$UpstreamId,[string]$UpstreamName,[string]$NetworkCidr,
    [object]$ResolvedAddresses,[object]$HostsFileHasOverride
) {
    Assert-H454InternalNetworkMembers $Network $NetworkId $NetworkName $LabelName $LabelValue $AgentId $ProxyId
    Require-H454 ($UpstreamId -cmatch '^[a-f0-9]{64}$' -and $UpstreamId -cne $NetworkId -and
        $UpstreamName -cmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,127}$' -and $UpstreamName -cne $NetworkName) 'ROLLBACK_UPSTREAM_PIN'
    Require-H454 ($NetworkCidr -cmatch '^((?:[0-9]{1,3}\.){3}[0-9]{1,3})/([8-9]|[12][0-9]|30)$') 'ROLLBACK_NETWORK_CIDR'
    $base=Get-H454IPv4Number $Matches[1];$prefix=[int]$Matches[2]
    $size=[uint64]1 -shl (32-$prefix);$last=$base+$size-1
    $configs=@($Network.IPAM.Config)
    Require-H454 ($configs.Count -eq 1 -and $null -ne $configs[0] -and $configs[0].Subnet -ceq $NetworkCidr -and
        ($base % $size) -eq 0 -and (Test-H454PrivateIPv4 $base) -and (Test-H454PrivateIPv4 $last)) 'ROLLBACK_NETWORK_CIDR'
    $gateway=Get-H454IPv4Number $configs[0].Gateway
    Require-H454 ($gateway -gt $base -and $gateway -lt $last) 'ROLLBACK_NETWORK_GATEWAY'
    Require-H454 ($null -ne $Agent -and $null -ne $Proxy -and $Agent.Id -ceq $AgentId -and $Proxy.Id -ceq $ProxyId -and
        $Agent.State.Running -is [bool] -and $Agent.State.Running -and
        $Proxy.State.Running -is [bool] -and $Proxy.State.Running) 'ROLLBACK_CONTAINER_DRIFT'
    Require-H454 ($null -eq $Agent.HostConfig.ExtraHosts -or @($Agent.HostConfig.ExtraHosts).Count -eq 0) 'ROLLBACK_HOST_OVERRIDE'
    Require-H454 ($HostsFileHasOverride -is [bool] -and -not $HostsFileHasOverride) 'ROLLBACK_HOST_OVERRIDE'
    $agentNetworks=@($Agent.NetworkSettings.Networks.PSObject.Properties)
    $proxyNetworks=@($Proxy.NetworkSettings.Networks.PSObject.Properties)
    Require-H454 ($agentNetworks.Count -eq 1 -and $agentNetworks[0].Name -ceq $NetworkName -and
        $proxyNetworks.Count -eq 2 -and @($proxyNetworks.Name) -ccontains $NetworkName -and
        @($proxyNetworks.Name) -ccontains $UpstreamName) 'ROLLBACK_CONTAINER_NETWORKS'
    $agentEndpoint=$agentNetworks[0].Value
    $proxyEndpoint=$Proxy.NetworkSettings.Networks.PSObject.Properties[$NetworkName].Value
    $upstreamEndpoint=$Proxy.NetworkSettings.Networks.PSObject.Properties[$UpstreamName].Value
    Require-H454 ($agentEndpoint.NetworkID -ceq $NetworkId -and $proxyEndpoint.NetworkID -ceq $NetworkId -and
        $upstreamEndpoint.NetworkID -ceq $UpstreamId -and
        @($proxyEndpoint.Aliases) -ccontains 'host.docker.internal') 'ROLLBACK_CONTAINER_NETWORKS'
    $upstreamAddress=Get-H454IPv4Number $upstreamEndpoint.IPAddress
    Require-H454 ((Test-H454PrivateIPv4 $upstreamAddress) -and
        ($upstreamAddress -lt $base -or $upstreamAddress -gt $last)) 'ROLLBACK_UPSTREAM_ADDRESS'
    foreach($alias in @($upstreamEndpoint.Aliases)) {
        Require-H454 ($null -eq $alias -or ($alias -is [string] -and
            -not $alias.TrimEnd('.').Equals('host.docker.internal',[StringComparison]::OrdinalIgnoreCase))) 'ROLLBACK_CONTAINER_NETWORKS'
    }
    $agentAddress=$null;$proxyAddress=$null
    Require-H454 ([Net.IPAddress]::TryParse([string]$agentEndpoint.IPAddress,[ref]$agentAddress) -and
        [Net.IPAddress]::TryParse([string]$proxyEndpoint.IPAddress,[ref]$proxyAddress) -and
        $agentAddress.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
        $proxyAddress.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
        $agentAddress.ToString() -ceq $agentEndpoint.IPAddress -and $proxyAddress.ToString() -ceq $proxyEndpoint.IPAddress -and
        $agentAddress.ToString() -cne $proxyAddress.ToString() -and
        [string]::IsNullOrEmpty($agentEndpoint.GlobalIPv6Address) -and
        [string]::IsNullOrEmpty($proxyEndpoint.GlobalIPv6Address)) 'ROLLBACK_NETWORK_ADDRESS'
    foreach($ip in @($agentAddress,$proxyAddress)) {
        $number=Get-H454IPv4Number $ip.ToString()
        Require-H454 ($number -gt $base -and $number -lt $last -and $number -ne $gateway) 'ROLLBACK_NETWORK_ADDRESS'
    }
    foreach($pair in @(@($AgentId,$agentAddress.ToString()),@($ProxyId,$proxyAddress.ToString()))) {
        $member=$Network.Containers.PSObject.Properties[$pair[0]].Value
        Require-H454 ($member.IPv4Address -ceq ($pair[1]+'/'+$prefix)) 'ROLLBACK_NETWORK_ADDRESS'
    }
    Require-H454 ($ResolvedAddresses -is [array] -and $ResolvedAddresses.Count -gt 0) 'ROLLBACK_DNS'
    foreach($address in $ResolvedAddresses) {
        Require-H454 ($address -is [string] -and $address -ceq $proxyAddress.ToString()) 'ROLLBACK_DNS'
    }
}
