#requires -Version 5.1
<# Owner-side WSS SSH identity preparation; never contacts a server or starts BRC. #>
[CmdletBinding()]
param(
    [ValidateSet('Preflight','Generate','Restore')][string]$Mode = 'Preflight',
    [Parameter(Mandatory=$true)][string]$LauncherSha256,
    [Parameter(Mandatory=$true)][string]$NodeSha256,
    [switch]$OwnerApproved
)

$ErrorActionPreference = 'Stop'
$script:h454ModuleHash = '0EE71955970241E42659A9FBB93C72A6C37937AD7D83506EB96EEFE8413B9286'
$script:h454Entropy = [Text.Encoding]::UTF8.GetBytes('Hermes-H454-WSS-SSH-Identity-v1')

function Require-H454([bool]$Condition,[string]$Reason) { if(-not $Condition){throw $Reason} }

function Assert-H454TaskPrincipal([object]$Principal) {
    try{$sid=([Security.Principal.NTAccount][string]$Principal.UserId).Translate([Security.Principal.SecurityIdentifier]).Value}
    catch{throw 'H454_IDENTITY_TASK_PRINCIPAL'}
    Require-H454 ($sid -ceq [Security.Principal.WindowsIdentity]::GetCurrent().User.Value -and
        [string]$Principal.LogonType -ceq 'Interactive') 'H454_IDENTITY_TASK_PRINCIPAL'
}

function Assert-H454NoReparse([string]$Path) {
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    while($null -ne $item){
        Require-H454 (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'H454_IDENTITY_REPARSE'
        if($item -is [IO.FileInfo]){$item=$item.Directory}else{$item=$item.Parent}
    }
}

function Assert-H454Private([string]$Path) {
    Assert-H454NoReparse $Path
    $item=Get-Item -LiteralPath $Path -Force
    $dir=if($item.PSIsContainer){$item}else{$item.Directory}
    Require-H454 ((Get-Acl -LiteralPath $dir.FullName).AreAccessRulesProtected) 'H454_IDENTITY_ACL_INHERITED'
    $allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
    foreach($target in @($item.FullName,$dir.FullName)){
        $acl=Get-Acl -LiteralPath $target
        Require-H454 ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -in $allowed) 'H454_IDENTITY_OWNER'
        $own=$false
        foreach($rule in $acl.Access){
            $sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            Require-H454 ($sid -in $allowed) 'H454_IDENTITY_ACL'
            if($sid -ceq $allowed[0] -and $rule.AccessControlType -eq 'Allow'){$own=$true}
        }
        Require-H454 $own 'H454_IDENTITY_OWNER_ACL'
    }
}

function Get-H454Hash([byte[]]$Bytes) {
    $sha=[Security.Cryptography.SHA256]::Create()
    try{return [BitConverter]::ToString($sha.ComputeHash($Bytes)).Replace('-','')}
    finally{$sha.Dispose()}
}

function Write-H454NewPrivateFile([string]$Path,[byte[]]$Bytes) {
    Require-H454 ($null -ne $Bytes -and $Bytes.Length -gt 0 -and $Bytes.Length -le 16384) 'H454_IDENTITY_SIZE'
    $stream=[IO.File]::Open($Path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None)
    try{$stream.Write($Bytes,0,$Bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    Assert-H454Private $Path
    Require-H454 ((Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ceq (Get-H454Hash $Bytes)) 'H454_IDENTITY_FILE_DRIFT'
}

function Invoke-H454Process([string]$Exe,[string]$Arguments,[byte[]]$InputBytes) {
    $info=[Diagnostics.ProcessStartInfo]::new()
    $info.FileName=$Exe;$info.Arguments=$Arguments;$info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $proc=[Diagnostics.Process]::new();$proc.StartInfo=$info
    try{
        Require-H454 $proc.Start() 'H454_IDENTITY_PROCESS_START'
        $out=$proc.StandardOutput.ReadToEndAsync();$err=$proc.StandardError.ReadToEndAsync()
        if($null -ne $InputBytes){$proc.StandardInput.BaseStream.Write($InputBytes,0,$InputBytes.Length)}
        $proc.StandardInput.Close()
        if(-not $proc.WaitForExit(15000)){try{$proc.Kill()}catch{};throw 'H454_IDENTITY_PROCESS_TIMEOUT'}
        $output=$out.GetAwaiter().GetResult();$null=$err.GetAwaiter().GetResult()
        Require-H454 ($output.Length -le 1048576) 'H454_IDENTITY_PROCESS_OUTPUT'
        return [pscustomobject]@{Code=$proc.ExitCode;Output=$output}
    }finally{$proc.Dispose()}
}

function Invoke-H454IdentityNode([string]$Action,[byte[]]$InputBytes,[string]$Node,[string]$Module64,[string]$SshAdd) {
    Require-H454 ($Action -cin @('generate','public','load')) 'H454_IDENTITY_MODE'
    $code="import('data:text/javascript;base64,$Module64').then(m=>m.run(process.argv[1],process.argv[2])).catch(()=>{console.error('H454_IDENTITY_HOLD');process.exitCode=2})"
    $args='--input-type=module -e "'+$code+'" '+$Action
    if($Action -ceq 'load'){$args+=' "'+$SshAdd+'"'}
    $result=Invoke-H454Process $Node $args $InputBytes
    Require-H454 ($result.Code -eq 0 -and $result.Output.Length -le 4096) 'H454_IDENTITY_NODE_FAILED'
    return [string]$result.Output
}

function Get-H454AgentKeys([string]$SshAdd) {
    $result=Invoke-H454Process $SshAdd '-L' $null
    Require-H454 ($result.Code -in @(0,1)) 'H454_IDENTITY_AGENT_UNAVAILABLE'
    return [string]$result.Output
}

function Restore-H454Identity([string]$StateDir,[string]$Node,[string]$Module64,[string]$SshAdd) {
    Add-Type -AssemblyName System.Security
    $backup=Join-Path $StateDir 'wss-ssh-identity.dpapi'
    $public=Join-Path $StateDir 'wss-ssh-identity.pub'
    Assert-H454Private $backup
    $item=Get-Item -LiteralPath $backup -Force
    Require-H454 (-not $item.PSIsContainer -and $item.Length -gt 0 -and $item.Length -le 16384) 'H454_IDENTITY_BACKUP'
    $encrypted=[IO.File]::ReadAllBytes($backup);$backupHash=Get-H454Hash $encrypted;$plain=$null
    try{
        try{$plain=[Security.Cryptography.ProtectedData]::Unprotect($encrypted,$script:h454Entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)}
        catch{throw 'H454_IDENTITY_UNPROTECT'}
        Require-H454 ($plain.Length -gt 0 -and $plain.Length -le 4096) 'H454_IDENTITY_SIZE'
        $key=Invoke-H454IdentityNode 'public' $plain $Node $Module64 $SshAdd
        Require-H454 ($key -cmatch '^ssh-ed25519 [A-Za-z0-9+/]{68} hermes-h454-wss$') 'H454_IDENTITY_PUBLIC'
        $expected=[Text.UTF8Encoding]::new($false).GetBytes($key+"`n")
        if(Test-Path -LiteralPath $public){
            Assert-H454Private $public
            $entry=Get-Item -LiteralPath $public -Force
            Require-H454 (-not $entry.PSIsContainer -and $entry.Length -gt 0 -and $entry.Length -le 4096 -and
                (Get-FileHash -LiteralPath $public -Algorithm SHA256).Hash -ceq (Get-H454Hash $expected)) 'H454_IDENTITY_PUBLIC_DRIFT'
        }else{Write-H454NewPrivateFile $public $expected}
        Require-H454 ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ceq $backupHash) 'H454_IDENTITY_BACKUP_DRIFT'
        $needle=($key -split ' ')[0..1] -join ' '
        $agent=Get-H454AgentKeys $SshAdd
        $matches=@($agent -split "`r?`n"|Where-Object {($_ -split '\s+')[0..1] -join ' ' -ceq $needle})
        Require-H454 ($matches.Count -le 1) 'H454_IDENTITY_AGENT_DUPLICATE'
        if($matches.Count -eq 0){
            $loaded=Invoke-H454IdentityNode 'load' $plain $Node $Module64 $SshAdd
            Require-H454 ($loaded -ceq 'H454_IDENTITY_LOADED') 'H454_IDENTITY_LOAD'
        }
        $after=Get-H454AgentKeys $SshAdd
        $matches=@($after -split "`r?`n"|Where-Object {($_ -split '\s+')[0..1] -join ' ' -ceq $needle})
        Require-H454 ($matches.Count -eq 1 -and
            (Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ceq $backupHash -and
            (Get-FileHash -LiteralPath $public -Algorithm SHA256).Hash -ceq (Get-H454Hash $expected)) 'H454_IDENTITY_AGENT_DRIFT'
    }finally{if($null -ne $plain){[Array]::Clear($plain,0,$plain.Length)}}
}

try{
    Require-H454 ($LauncherSha256 -cmatch '^[A-Fa-f0-9]{64}$' -and $NodeSha256 -cmatch '^[A-Fa-f0-9]{64}$') 'H454_IDENTITY_PINS'
    Require-H454 ($Mode -ceq 'Preflight' -or $OwnerApproved) 'H454_IDENTITY_APPROVAL'
    foreach($name in @('SSH_AUTH_SOCK','NODE_OPTIONS','NODE_PATH')){
        Require-H454 ([string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name,'Process'))) 'H454_IDENTITY_ENVIRONMENT'
    }
    $system=[Environment]::GetFolderPath('System');$windows=[Environment]::GetFolderPath('Windows')
    Require-H454 ([IO.Path]::GetFullPath($env:SystemRoot) -ieq [IO.Path]::GetFullPath($windows)) 'H454_IDENTITY_SYSTEM'
    $powershell=Join-Path $system 'WindowsPowerShell\v1.0\powershell.exe'
    $sshAdd=Join-Path $system 'OpenSSH\ssh-add.exe'
    $node=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'nodejs\node.exe'
    foreach($exe in @($powershell,$sshAdd,$node)){Assert-H454NoReparse $exe;Require-H454 (Test-Path -LiteralPath $exe -PathType Leaf) 'H454_IDENTITY_EXECUTABLE'}
    Require-H454 ((Get-FileHash -LiteralPath $node -Algorithm SHA256).Hash -ieq $NodeSha256 -and
        (Get-AuthenticodeSignature -LiteralPath $node).Status -eq 'Valid') 'H454_IDENTITY_NODE_PIN'
    $task=Get-ScheduledTask -TaskName 'HermesH15BRCWindows' -ErrorAction Stop
    Assert-H454TaskPrincipal $task.Principal
    $actions=@($task.Actions)
    Require-H454 ($actions.Count -eq 1 -and [IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables([string]$actions[0].Execute)) -ieq
        [IO.Path]::GetFullPath($powershell)) 'H454_IDENTITY_TASK'
    $match=[regex]::Match([string]$actions[0].Arguments,'(?i)^\s*-NoProfile\s+-ExecutionPolicy\s+(?:Bypass|RemoteSigned|AllSigned|Restricted|Unrestricted|Default|Undefined)\s+-File\s+(?:"([^"]+)"|(\S+))\s+-Mode\s+Run\s*$')
    Require-H454 $match.Success 'H454_IDENTITY_TASK'
    $launcher=if($match.Groups[1].Success){$match.Groups[1].Value}else{$match.Groups[2].Value}
    Require-H454 ([IO.Path]::IsPathRooted($launcher) -and $launcher -notmatch '"') 'H454_IDENTITY_TASK'
    $launcher=[IO.Path]::GetFullPath($launcher);$stateDir=[IO.Path]::GetDirectoryName($launcher)
    Require-H454 ([IO.Path]::GetDirectoryName($stateDir) -ieq [Environment]::GetFolderPath('LocalApplicationData')) 'H454_IDENTITY_STATE_DIR'
    Assert-H454Private $launcher
    Require-H454 ((Get-FileHash -LiteralPath $launcher -Algorithm SHA256).Hash -ieq $LauncherSha256) 'H454_IDENTITY_LAUNCHER_PIN'
    $module=Join-Path $PSScriptRoot 'h454_windows_wss_identity.mjs'
    Assert-H454NoReparse $module
    $bytes=[IO.File]::ReadAllBytes($module)
    Require-H454 ($bytes.Length -gt 0 -and $bytes.Length -le 16000 -and (Get-H454Hash $bytes) -ceq $script:h454ModuleHash) 'H454_IDENTITY_MODULE_PIN'
    $module64=[Convert]::ToBase64String($bytes)
    $backup=Join-Path $stateDir 'wss-ssh-identity.dpapi';$public=Join-Path $stateDir 'wss-ssh-identity.pub'
    if($Mode -ceq 'Preflight'){
        Write-Output 'H454_WSS_IDENTITY_PREFLIGHT=PASS'
        Write-Output ('H454_WSS_IDENTITY_FILES='+$(if(Test-Path -LiteralPath $backup){'BACKUP_PRESENT'}else{'BACKUP_ABSENT'})+','+$(if(Test-Path -LiteralPath $public){'PUBLIC_PRESENT'}else{'PUBLIC_ABSENT'}))
        exit 0
    }
    if($Mode -ceq 'Generate'){
        Require-H454 (-not (Test-Path -LiteralPath $backup) -and -not (Test-Path -LiteralPath $public)) 'H454_IDENTITY_ALREADY_EXISTS'
        Add-Type -AssemblyName System.Security
        $json=Invoke-H454IdentityNode 'generate' $null $node $module64 $sshAdd
        $plain=[Text.UTF8Encoding]::new($false).GetBytes($json);$json=$null
        try{
            $null=Invoke-H454IdentityNode 'public' $plain $node $module64 $sshAdd
            $encrypted=[Security.Cryptography.ProtectedData]::Protect($plain,$script:h454Entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)
            Write-H454NewPrivateFile $backup $encrypted
        }finally{[Array]::Clear($plain,0,$plain.Length)}
    }
    Restore-H454Identity $stateDir $node $module64 $sshAdd
    Write-Output 'H454_WSS_IDENTITY=READY'
    Write-Output 'H454_PRIVATE_STORAGE=DPAPI_CURRENT_USER'
    Write-Output 'H454_SERVER_AUTHORIZATION=NOT_INSTALLED'
}catch{
    $reason=$_.Exception.Message
    if($reason -cnotmatch '^H454_[A-Z0-9_]{1,80}$'){$reason='H454_IDENTITY_INTERNAL'}
    Write-Output 'H454_WSS_IDENTITY=HOLD';Write-Output $reason;exit 2
}
