#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$FixtureLauncher)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$h454Tokens=$null;$h454Errors=$null
$h454Ast=[Management.Automation.Language.Parser]::ParseFile($FixtureLauncher,[ref]$h454Tokens,[ref]$h454Errors)
if(@($h454Errors).Count -ne 0){throw 'FIXTURE_SOURCE_PARSE'}
$h454Names=@('Invoke-H454Docker','Assert-H454ExistingTunnel','Stop-H454ExistingTunnel','Stop-H454TunnelHandle',
             'Get-H454ContainerProfileHash','Get-H454PreservedContainer','Stop-H454PreservedContainer',
             'Start-H454PreservedContainer','Assert-H454PreservedStarted')
$h454Functions=@($h454Ast.FindAll({param($x)$x -is [Management.Automation.Language.FunctionDefinitionAst]},$true)|Where-Object {$_.Name -cin $h454Names})
if($h454Functions.Count -ne $h454Names.Count){throw 'FIXTURE_FUNCTION_SCOPE'}
foreach($h454Function in $h454Functions){. ([scriptblock]::Create($h454Function.Extent.Text))}
$h454Branches=@($h454Ast.FindAll({param($x)$x -is [Management.Automation.Language.IfStatementAst] -and
    $x.Extent.Text.StartsWith('if (-not (Start-H454PreservedContainer))')},$true))
if($h454Branches.Count -ne 1){throw 'FIXTURE_BRANCH_SCOPE'}
$h454CreateBranch=[scriptblock]::Create($h454Branches[0].Extent.Text)
function Require([bool]$Condition,[string]$Code){if(-not $Condition){throw $Code}}
$h454Loops=@($h454Ast.FindAll({param($x)$x -is [Management.Automation.Language.WhileStatementAst] -and
    $x.Extent.Text.StartsWith('while (-not [string]::IsNullOrEmpty($h454Path))')},$true))
if($h454Loops.Count -ne 1){throw 'FIXTURE_PATH_LOOP_SCOPE'}
$h454Path=Join-Path $env:SystemRoot 'System32\cmd.exe'
. ([scriptblock]::Create($h454Loops[0].Extent.Text))
function Get-NetTCPConnection {
    [CmdletBinding()]param([string]$LocalAddress,[int]$LocalPort,[string]$State)
    if($script:h454NetFailure){Write-Error -Category PermissionDenied -Message 'synthetic-network-query';return}
    if($script:h454NoListener){Write-Error -Category ObjectNotFound -Message 'synthetic-empty';return}
    [pscustomobject]@{OwningProcess=$script:h454ListenerPid}
}
function Get-CimInstance {
    [CmdletBinding()]param([string]$ClassName,[string]$Filter)
    if($script:h454CimFailure){throw 'synthetic-process-query'}
    if($script:h454TunnelExists){$script:h454Tunnel}
}
function Get-Process {
    [CmdletBinding()]param([int]$Id)
    $p=[pscustomobject]@{Handle=[IntPtr]101;StartTime=$script:h454StartTime;HasExited=$false}
    $p|Add-Member -MemberType ScriptMethod -Name Kill -Value {
        $script:h454TunnelEvents.Add('kill')
        if($script:h454KillMode -ceq 'failure'){throw 'synthetic-kill-failure'}
        $this.HasExited=$true
        if($script:h454KillMode -ceq 'exited'){throw 'synthetic-already-exited'}
    }
    $p|Add-Member -MemberType ScriptMethod -Name WaitForExit -Value {param($Timeout) return [bool]$this.HasExited}
    $p|Add-Member -MemberType ScriptMethod -Name Dispose -Value {$script:h454TunnelEvents.Add('dispose')}
    return $p
}
function Get-Item {
    [CmdletBinding()]param([string]$LiteralPath,[switch]$Force)
    if($LiteralPath -cne $STATE_PATH){throw 'FIXTURE_STATE_PATH'}
    [pscustomobject]@{LastWriteTimeUtc=$script:h454StateTime}
}
function New-H454Fixture {
    return [pscustomobject]@{
        Id=('1'*64);Name='/synthetic-agent';Image=('sha256:'+('a'*64));
        State=[pscustomobject]@{Running=$true};
        Config=[pscustomobject]@{Hostname=('1'*12);Domainname='';MacAddress='';Image='fixture-tag';User='65534:65534';
            AttachStdout=$true;AttachStderr=$true;Env=@('TEST_FIXTURE=1');
            Labels=[pscustomobject]@{'com.hermes.scope'='synthetic'}};
        HostConfig=[pscustomobject]@{Init=$true;PidsLimit=128;Memory=536870912;
            Privileged=$false;ReadonlyRootfs=$true;OomKillDisable=$null;
            Tmpfs=[pscustomobject]@{'/tmp'='rw,noexec';'/run/brc'='rw,noexec'};
            CapDrop=@('ALL');SecurityOpt=@('no-new-privileges')};
        Mounts=@([pscustomobject]@{Type='bind';Source='fixture-workspace';Destination='/workspace';RW=$true});
        NetworkSettings=[pscustomobject]@{Networks=[pscustomobject]@{bridge=[pscustomobject]@{}}}
    }
}
function Reset-H454Fixture {
    $script:h454Item=New-H454Fixture
    $script:h454Exists=$true;$script:h454InspectFails=$false;$script:h454ListFails=$false;$script:h454ContainerId=$null
    $script:h454CreateDrift=$false;$script:h454CreateBadId=$false
    $state.imageId='sha256:'+('a'*64)
    $state.tunnelPid=101
    $script:h454OriginalTunnel=$null
    $script:h454TunnelEvents=[Collections.Generic.List[string]]::new()
    $script:h454KillMode='normal'
    $script:h454NetFailure=$false;$script:h454NoListener=$false;$script:h454ListenerPid=101
    $script:h454CimFailure=$false;$script:h454TunnelExists=$true
    $script:h454StartTime=[DateTime]::UtcNow.AddMinutes(-5)
    $script:h454StateTime=[DateTime]::UtcNow.AddMinutes(-1)
    $script:h454Tunnel=[pscustomobject]@{Name='ssh.exe';
        ExecutablePath=(Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\ssh.exe');
        CommandLine='fixture-target 38180:fixture';CreationDate=$script:h454StartTime}
    $script:h454Events=[Collections.Generic.List[string]]::new()
    $script:h454ExpectedProfile=Get-H454ContainerProfileHash $script:h454Item
}
function Expect-H454Refusal([scriptblock]$Action) {
    $h454Refused=$false
    try { & $Action } catch { $h454Refused=$true }
    Require $h454Refused 'FIXTURE_EXPECTED_REFUSAL'
    Require ($script:h454Events.Count -eq 0) 'FIXTURE_UNEXPECTED_MUTATION'
}
$CONTAINER='synthetic-agent'
$state=[pscustomobject]@{imageId=('sha256:'+('a'*64));tunnelPid=101}
$STATE_PATH='synthetic-state'
$TUNNEL_TARGET='fixture-target'
$script:h454TunnelNeedle='38180:fixture'
$script:h454SshExe=Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\ssh.exe'
$script:h454ExpectedImage=$state.imageId
$script:h454DockerHost='npipe:////./pipe/dockerDesktopLinuxEngine'
$script:h454Docker={
    $global:LASTEXITCODE=0
    Require ($args.Count -ge 4 -and $args[0] -ceq '--host' -and
        $args[1] -ceq 'npipe:////./pipe/dockerDesktopLinuxEngine' -and $args[2] -ceq 'container') 'FIXTURE_DOCKER_SCOPE'
    switch -CaseSensitive ($args[3]) {
        'inspect' {
            if (-not $script:h454Exists -or $script:h454InspectFails) { $global:LASTEXITCODE=1; Write-Error 'synthetic-inspect-error'; return }
            ConvertTo-Json -InputObject @($script:h454Item) -Depth 80 -Compress
        }
        'ls' {
            if($script:h454ListFails){$global:LASTEXITCODE=1;Write-Error 'synthetic-list-error';return}
            if($script:h454Exists){$CONTAINER}
        }
        'create' {
            if ($script:h454Exists) { $global:LASTEXITCODE=1; Write-Error 'synthetic-name-conflict'; return }
            Require ($args -ccontains '--pull' -and $args -ccontains 'never' -and $args -cnotcontains '--detach') 'FIXTURE_CREATE_FLAGS'
            $script:h454Events.Add('create')
            $script:h454Item=New-H454Fixture
            $script:h454Item.State.Running=$false
            if($script:h454CreateDrift){$script:h454Item.HostConfig.Privileged=$true}
            $script:h454Exists=$true
            if($script:h454CreateBadId){'invalid-id'} else {$script:h454Item.Id}
        }
        'stop' {
            Require ($script:h454Exists -and $args[-1] -ceq $script:h454Item.Id) 'FIXTURE_STOP_TARGET'
            $script:h454Events.Add('stop')
            $script:h454Item.State.Running=$false
        }
        'start' {
            Require ($script:h454Exists -and $args[-1] -ceq $script:h454Item.Id) 'FIXTURE_START_TARGET'
            $script:h454Events.Add('start')
            $script:h454Item.State.Running=$true
        }
        default { throw 'FIXTURE_UNEXPECTED_DOCKER_VERB' }
    }
}

# Exercise real PS5.1 native stderr handling, independent of the Docker mock.
$h454MockDocker=$script:h454Docker
$script:h454Docker=Join-Path $env:SystemRoot 'System32\cmd.exe'
$h454Native=Invoke-H454Docker -Arguments @('/d','/c','h454-synthetic-nonexistent-command')
Require ($h454Native.Code -ne 0 -and $h454Native.Lines.Count -eq 0) 'NATIVE_STDERR_HANDLING'
$script:h454Docker=$h454MockDocker

# A process handle obtained from our own hidden child remains the stop target.
$h454Child=$null
try {
    $h454PS51=Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    $h454Child=Start-Process -FilePath $h454PS51 -ArgumentList '-NoProfile -NonInteractive -Command Start-Sleep -Seconds 30' -WindowStyle Hidden -PassThru
    $null=$h454Child.Handle
    Stop-H454TunnelHandle $h454Child
    $h454Child=$null
} finally {
    if($null -ne $h454Child){try{if(-not $h454Child.HasExited){$h454Child.Kill();[void]$h454Child.WaitForExit(5000)}}catch{};$h454Child.Dispose()}
}

# A verified existing tunnel or an absent tunnel and listener is safe to proceed.
Reset-H454Fixture
Assert-H454ExistingTunnel
Require ($null -ne $script:h454OriginalTunnel) 'VERIFIED_TUNNEL_HANDLE_MISSING'
Stop-H454ExistingTunnel
Require (($script:h454TunnelEvents -join ',') -ceq 'kill,dispose') 'VERIFIED_TUNNEL_HANDLE_NOT_USED'
Reset-H454Fixture
$script:h454KillMode='exited'
$h454Process=Get-Process -Id 101
Stop-H454TunnelHandle $h454Process
Require (($script:h454TunnelEvents -join ',') -ceq 'kill,dispose') 'EXIT_RACE_NOT_HANDLED'
Reset-H454Fixture
$script:h454KillMode='failure'
$h454Process=Get-Process -Id 101
$h454Refused=$false
try {Stop-H454TunnelHandle $h454Process} catch {$h454Refused=$true}
Require ($h454Refused -and ($script:h454TunnelEvents -join ',') -ceq 'kill,dispose') 'FAILED_KILL_NOT_REPORTED'
Reset-H454Fixture
$script:h454NoListener=$true;$script:h454TunnelExists=$false
Assert-H454ExistingTunnel
Reset-H454Fixture
$script:h454NoListener=$true
Assert-H454ExistingTunnel
Reset-H454Fixture
$script:h454NoListener=$true;$state.tunnelPid=0
Assert-H454ExistingTunnel

# An unverified or replaced tunnel must fail before stopping the live container.
foreach($h454Case in @('unavailable','name','path','target','forward','listener','stale-listener','zero-listener','neterror','cimerror','age','reused','pid')) {
    Reset-H454Fixture
    switch($h454Case) {
        'unavailable' {$script:h454Tunnel.CommandLine=$null}
        'name' {$script:h454Tunnel.Name='other.exe'}
        'path' {$script:h454Tunnel.ExecutablePath='untrusted'}
        'target' {$script:h454Tunnel.CommandLine='other-target 38180:fixture'}
        'forward' {$script:h454Tunnel.CommandLine='fixture-target other-forward'}
        'listener' {$script:h454ListenerPid=102}
        'stale-listener' {$script:h454TunnelExists=$false}
        'zero-listener' {$state.tunnelPid=0}
        'neterror' {$script:h454NetFailure=$true}
        'cimerror' {$script:h454CimFailure=$true}
        'age' {$script:h454StartTime=[DateTime]::UtcNow}
        'reused' {$script:h454Tunnel.CreationDate=$script:h454StartTime.AddSeconds(1)}
        'pid' {$state.tunnelPid='not-a-pid'}
    }
    $h454Refused=$false
    try {Assert-H454ExistingTunnel;Stop-H454PreservedContainer -Claim} catch {$h454Refused=$true}
    Stop-H454PreservedContainer
    Require ($h454Refused -and $script:h454Item.State.Running -and $script:h454Events.Count -eq 0 -and
        $script:h454TunnelEvents -cnotcontains 'kill') 'UNVERIFIED_TUNNEL_STOPPED_CONTAINER'
}

# A running original is stopped, restarted under the identical ID, and retained.
Reset-H454Fixture
Stop-H454PreservedContainer -Claim
Require (-not $script:h454Item.State.Running -and $script:h454ContainerId -ceq ('1'*64)) 'RUNNING_NOT_RETAINED'
Require (Start-H454PreservedContainer) 'RUNNING_NOT_RESTARTED'
Assert-H454PreservedStarted
Stop-H454PreservedContainer
Require (($script:h454Events -join ',') -ceq 'stop,start,stop' -and $script:h454Exists) 'RUNNING_LIFECYCLE'

# A stopped original is started without being removed or recreated.
Reset-H454Fixture
$script:h454Item.State.Running=$false
Stop-H454PreservedContainer -Claim
Require (Start-H454PreservedContainer) 'STOPPED_NOT_RESTARTED'
Assert-H454PreservedStarted
Require (($script:h454Events -join ',') -ceq 'start') 'STOPPED_LIFECYCLE'

# A missing container is created stopped, checked, then started by immutable ID.
Reset-H454Fixture
$script:h454Exists=$false
Stop-H454PreservedContainer -Claim
. $h454CreateBranch
Assert-H454PreservedStarted
Require (($script:h454Events -join ',') -ceq 'create,start') 'MISSING_FALLBACK'

# A bad newly created profile or malformed create receipt never starts it.
foreach($h454Case in @('profile','receipt')) {
    Reset-H454Fixture
    $script:h454Exists=$false
    if($h454Case -ceq 'profile'){$script:h454CreateDrift=$true}else{$script:h454CreateBadId=$true}
    Stop-H454PreservedContainer -Claim
    $h454Refused=$false
    try {. $h454CreateBranch} catch {$h454Refused=$true}
    Require ($h454Refused -and ($script:h454Events -join ',') -ceq 'create' -and
        $script:h454Exists -and -not $script:h454Item.State.Running) 'UNSAFE_CREATE_STARTED'
    Require ($ErrorActionPreference -ceq 'Stop') 'ERROR_PREFERENCE_NOT_RESTORED'
}

# A name claimed by another actor before creation fails without touching it.
Reset-H454Fixture
$script:h454Exists=$false
Stop-H454PreservedContainer -Claim
$script:h454Exists=$true
$h454Refused=$false
try {. $h454CreateBranch} catch {$h454Refused=$true}
Stop-H454PreservedContainer
Require ($h454Refused -and $script:h454Item.State.Running -and $script:h454Events.Count -eq 0) 'CREATE_NAME_RACE'

# Cleanup cannot adopt or stop a container when this invocation claimed none.
Reset-H454Fixture
Stop-H454PreservedContainer
Require ($script:h454Item.State.Running -and $script:h454Events.Count -eq 0) 'UNCLAIMED_CLEANUP'

# Metadata drift, an inspection error for an existing name, or ID replacement
# must all refuse before a Docker stop/start can affect the unexpected object.
foreach($h454Case in @('privileged','mount','init','oom','image','state','network','hostname','domain','mac','inspect','list')) {
    Reset-H454Fixture
    switch($h454Case) {
        'privileged' {$script:h454Item.HostConfig.Privileged=$true}
        'mount' {$script:h454Item.Mounts[0].Source='unexpected'}
        'init' {$script:h454Item.HostConfig.Init=$false}
        'oom' {$script:h454Item.HostConfig.OomKillDisable=$true}
        'image' {$script:h454Item.Image='sha256:'+('b'*64)}
        'state' {$state.imageId='sha256:'+('b'*64)}
        'network' {$script:h454Item.NetworkSettings.Networks | Add-Member -NotePropertyName unexpected -NotePropertyValue ([pscustomobject]@{})}
        'hostname' {$script:h454Item.Config.Hostname='other'}
        'domain' {$script:h454Item.Config.Domainname='other'}
        'mac' {$script:h454Item.Config.MacAddress='11:22:33:44:55:66'}
        'inspect' {$script:h454InspectFails=$true}
        'list' {$script:h454InspectFails=$true;$script:h454ListFails=$true}
    }
    Expect-H454Refusal { Stop-H454PreservedContainer -Claim }
}
Reset-H454Fixture
$script:h454Item.State.Running=$false
Stop-H454PreservedContainer -Claim
$script:h454Item.Id='2'*64
Expect-H454Refusal { Start-H454PreservedContainer }

# Docker's volatile generated hostname/image spelling and attach defaults may
# differ between create and run without changing the security profile.
Reset-H454Fixture
$script:h454Item.Id='2'*64
$script:h454Item.Config.Hostname='2'*12
$script:h454Item.Config.Image='different-spelling'
$script:h454Item.Config.AttachStdout=$false
$script:h454Item.Config.AttachStderr=$false
Require ((Get-H454ContainerProfileHash $script:h454Item) -ceq $script:h454ExpectedProfile) 'VOLATILE_CONFIG_DRIFT'
$script:h454Item.Config.PSObject.Properties.Remove('MacAddress')
Require ((Get-H454ContainerProfileHash $script:h454Item) -ceq $script:h454ExpectedProfile) 'OMITTED_EMPTY_MAC'

# Docker labels are a map: order must not change the pinned profile.
Reset-H454Fixture
$script:h454Item.Config.Labels=[pscustomobject][ordered]@{'z.example'='z';'com.hermes.scope'='synthetic';'A.example'='a'}
$script:h454ExpectedProfile=Get-H454ContainerProfileHash $script:h454Item
$script:h454Item.Config.Labels=[pscustomobject][ordered]@{'A.example'='a';'com.hermes.scope'='synthetic';'z.example'='z'}
Require ((Get-H454ContainerProfileHash $script:h454Item) -ceq $script:h454ExpectedProfile) 'LABEL_ORDER_CHANGED_PROFILE'
$script:h454Item.Config.Labels.'A.example'='tampered'
Expect-H454Refusal { Stop-H454PreservedContainer -Claim }
$script:h454Item.Config.Labels.'A.example'='a'
$script:h454Item.Config.Labels|Add-Member -NotePropertyName 'new.example' -NotePropertyValue 'unexpected'
Expect-H454Refusal { Stop-H454PreservedContainer -Claim }
$script:h454Item.Config.Labels.PSObject.Properties.Remove('new.example')
$script:h454Item.Config.Labels.PSObject.Properties.Remove('z.example')
Expect-H454Refusal { Stop-H454PreservedContainer -Claim }
'H454_LAUNCHER_PRESERVE_FIXTURES=PASS'
