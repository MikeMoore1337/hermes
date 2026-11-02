#requires -Version 5.1
# The caller pins the original launcher and separately verifies the actual route.
function Assert-H454OriginalProfile(
    [object]$Container,[string]$Launcher,[string]$LauncherSha256,
    [string]$OriginalId,[string]$OriginalImage,[string]$OriginalName,[string]$NetworkName
) {
    Require-H454 ($OriginalId -cmatch '^[a-f0-9]{64}$' -and $OriginalImage -cmatch '^sha256:[a-f0-9]{64}$' -and
        $OriginalName -cmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,127}$' -and
        $NetworkName -cmatch '^[a-zA-Z0-9][a-zA-Z0-9_.-]{1,127}$') 'H454_ORIGINAL_PROFILE_PINS'
    Assert-H454WssTaskFile $Launcher $LauncherSha256 200000
    Require-H454 ($null -ne $Container -and $Container.Id -ceq $OriginalId -and
        $Container.Image -ceq $OriginalImage -and $Container.Name -ceq ('/'+$OriginalName) -and
        $null -ne $Container.HostConfig -and $null -ne $Container.NetworkSettings) 'H454_ORIGINAL_PROFILE_IDENTITY'
    $dns=$Container.HostConfig.PSObject.Properties['Dns']
    $networks=$Container.NetworkSettings.PSObject.Properties['Networks']
    Require-H454 ($null -ne $dns -and ($null -eq $dns.Value -or ($dns.Value -is [array] -and $dns.Value.Count -eq 0)) -and
        $null -ne $networks -and $null -ne $networks.Value) 'H454_ORIGINAL_PROFILE_NETWORK'
    $names=@($networks.Value.PSObject.Properties.Name)
    Require-H454 ($names.Count -eq 1 -and $names[0] -ceq $NetworkName -and
        ($null -eq $Container.HostConfig.ExtraHosts -or @($Container.HostConfig.ExtraHosts).Count -eq 0)) 'H454_ORIGINAL_PROFILE_NETWORK'
    $bytes=[IO.File]::ReadAllBytes($Launcher)
    Require-H454 ((Hash-H454Bytes $bytes) -ceq $LauncherSha256) 'H454_ORIGINAL_PROFILE_SOURCE'
    $text=[Text.UTF8Encoding]::new($false,$true).GetString($bytes)
    if($text.Length -gt 0 -and $text[0] -eq [char]0xfeff){$text=$text.Substring(1)}
    $pins=@([regex]::Matches($text,'(?m)^\s*\$script:h454ExpectedProfile\s*=\s*''([A-Fa-f0-9]{64})''\s*$'))
    $tokens=$null;$errors=$null
    $ast=[Management.Automation.Language.Parser]::ParseInput($text,[ref]$tokens,[ref]$errors)
    $hashers=@($ast.FindAll({param($node) $node -is [Management.Automation.Language.FunctionDefinitionAst] -and
        $node.Name -ceq 'Get-H454ContainerProfileHash'},$true))
    Require-H454 ($pins.Count -eq 1 -and @($errors).Count -eq 0 -and $hashers.Count -eq 1) 'H454_ORIGINAL_PROFILE_SOURCE'
    function Require([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
    . ([scriptblock]::Create($hashers[0].Extent.Text))
    $oldDns=$dns.Value;$oldNetworks=$networks.Value
    try {
        $dns.Value=$null
        if($NetworkName -cne 'bridge'){$networks.Value=[pscustomobject]@{bridge=[pscustomobject]@{}}}
        $actual=Get-H454ContainerProfileHash $Container
    } finally {$dns.Value=$oldDns;$networks.Value=$oldNetworks}
    Require-H454 ($actual -ceq $pins[0].Groups[1].Value.ToUpperInvariant()) 'H454_ORIGINAL_PROFILE_DRIFT'
}
