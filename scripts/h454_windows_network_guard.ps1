#requires -Version 5.1
# Docker administrator and the supplied, freshly inspected object remain trusted.
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
