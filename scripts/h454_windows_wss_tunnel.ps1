#requires -Version 5.1
[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidatePattern('^[A-Fa-f0-9]{64}$')][string]$ConfigSha256,[switch]$Preflight)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
function Require([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
    function Assert-H454DedicatedProcess([string[]]$h454Args,[string]$ScriptPath) {
        $h454Seen = [Collections.Generic.HashSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
        $h454Index = 1
        while ($h454Index -lt $h454Args.Length -and $h454Args[$h454Index] -ine '-File') {
            $h454Switch = $h454Args[$h454Index]
            Require ($h454Seen.Add($h454Switch)) 'H454_DEDICATED_PROCESS_REQUIRED'
            if ($h454Switch -iin @('-NoProfile','-NonInteractive','-NoLogo')) { $h454Index++; continue }
            if ($h454Switch -ieq '-ExecutionPolicy') { $h454Allowed = @('Bypass','RemoteSigned','AllSigned','Restricted','Unrestricted','Default','Undefined') }
            elseif ($h454Switch -ieq '-WindowStyle') { $h454Allowed = @('Normal','Hidden','Minimized','Maximized') }
            else { throw 'H454_DEDICATED_PROCESS_REQUIRED' }
            $h454Index++
            Require ($h454Index -lt $h454Args.Length -and $h454Args[$h454Index] -iin $h454Allowed) 'H454_DEDICATED_PROCESS_REQUIRED'
            $h454Index++
        }
        Require ($h454Seen.Contains('-NoProfile') -and $h454Index + 1 -lt $h454Args.Length -and
            $h454Args[$h454Index] -ieq '-File' -and
            -not [string]::IsNullOrEmpty($ScriptPath) -and
            [IO.Path]::GetFullPath($h454Args[$h454Index + 1]) -ieq [IO.Path]::GetFullPath($ScriptPath)) 'H454_DEDICATED_PROCESS_REQUIRED'
    }
    function Initialize-H454TunnelJob([string]$ScriptPath) {
        Assert-H454DedicatedProcess ([Environment]::GetCommandLineArgs()) $ScriptPath
        Require ($null -eq ('H454TunnelJob' -as [type])) 'H454_JOB_TYPE_OCCUPIED'
        Add-Type -ErrorAction Stop -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class H454TunnelJob {
    [StructLayout(LayoutKind.Sequential)]
    struct Basic {
        public long PerProcessUserTimeLimit, PerJobUserTimeLimit;
        public uint LimitFlags;
        public UIntPtr MinimumWorkingSetSize, MaximumWorkingSetSize;
        public uint ActiveProcessLimit;
        public UIntPtr Affinity;
        public uint PriorityClass, SchedulingClass;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct Counters {
        public ulong ReadOperationCount, WriteOperationCount, OtherOperationCount;
        public ulong ReadTransferCount, WriteTransferCount, OtherTransferCount;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct Extended {
        public Basic BasicLimitInformation;
        public Counters IoInfo;
        public UIntPtr ProcessMemoryLimit, JobMemoryLimit, PeakProcessMemoryUsed, PeakJobMemoryUsed;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool SetInformationJobObject(IntPtr job, int infoClass, ref Extended info, uint length);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll")]
    static extern IntPtr GetCurrentProcess();
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool CloseHandle(IntPtr handle);
    static IntPtr ownedJob;
    public static bool Attach() {
        if (ownedJob != IntPtr.Zero) return false;
        IntPtr job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) return false;
        Extended info = new Extended();
        info.BasicLimitInformation.LimitFlags = 0x2000;
        if (!SetInformationJobObject(job, 9, ref info, (uint)Marshal.SizeOf(typeof(Extended))) ||
            !AssignProcessToJobObject(job, GetCurrentProcess())) {
            CloseHandle(job); return false;
        }
        // The non-inheritable handle remains open until the launcher process exits.
        ownedJob = job;
        return true;
    }
}
'@
        Require ([H454TunnelJob]::Attach()) 'H454_JOB_ASSIGN_FAILED'
    }

function Assert-H454Private([string]$Path){
    $item=Get-Item -LiteralPath $Path -Force -ErrorAction Stop
    $cursor=$item
    while($null -ne $cursor){
        Require (-not ($cursor.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'H454_TUNNEL_REPARSE'
        if($cursor -is [IO.FileInfo]){$cursor=$cursor.Directory}else{$cursor=$cursor.Parent}
    }
    $dir=if($item.PSIsContainer){$item}else{$item.Directory}
    Require ((Get-Acl -LiteralPath $dir.FullName).AreAccessRulesProtected) 'H454_TUNNEL_ACL'
    $allowed=@([Security.Principal.WindowsIdentity]::GetCurrent().User.Value,'S-1-5-18','S-1-5-32-544')
    foreach($target in @($item.FullName,$dir.FullName)){
        $acl=Get-Acl -LiteralPath $target
        Require ($acl.GetOwner([Security.Principal.SecurityIdentifier]).Value -in $allowed) 'H454_TUNNEL_OWNER'
        $own=$false
        foreach($rule in $acl.Access){
            $sid=$rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value
            Require ($sid -in $allowed) 'H454_TUNNEL_ACL'
            if($sid -ceq $allowed[0] -and $rule.AccessControlType -eq 'Allow'){$own=$true}
        }
        Require $own 'H454_TUNNEL_ACL'
    }
}
function Assert-H454File([string]$Path,[string]$Digest,[int]$Limit){
    Assert-H454Private $Path
    $item=Get-Item -LiteralPath $Path -Force
    Require (-not $item.PSIsContainer -and $item.Length -gt 0 -and $item.Length -le $Limit -and
        (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash -ceq $Digest) 'H454_TUNNEL_FILE'
}
$h454JobInitialized=$false
while($true){
try {
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Utility\Microsoft.PowerShell.Utility.psd1') -ErrorAction Stop
    Import-Module (Join-Path $PSHOME 'Modules\Microsoft.PowerShell.Security\Microsoft.PowerShell.Security.psd1') -ErrorAction Stop
    $netModule=Join-Path ([Environment]::GetFolderPath('System')) 'WindowsPowerShell\v1.0\Modules\NetTCPIP\NetTCPIP.psd1'
    Import-Module $netModule -ErrorAction Stop
    foreach($name in @('SSH_AUTH_SOCK','NODE_OPTIONS','NODE_PATH')){
        Require ([string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name,'Process'))) 'H454_TUNNEL_ENVIRONMENT'
    }
    $stateDir=[IO.Path]::GetDirectoryName($PSCommandPath)
    Require ([IO.Path]::GetDirectoryName($stateDir) -ieq [Environment]::GetFolderPath('LocalApplicationData')) 'H454_TUNNEL_STATE'
    $config=Join-Path $stateDir 'h454-wss-tunnel-config.json'
    Assert-H454File $config $ConfigSha256.ToUpperInvariant() 8192
    $settings=[Text.Encoding]::UTF8.GetString([IO.File]::ReadAllBytes($config)) | ConvertFrom-Json -ErrorAction Stop
    $names=@($settings.PSObject.Properties.Name | Sort-Object)
    $expected=@('caSha256','identitySha256','launcherSha256','nodeSha256','publicKeySha256',
        'relayAddress','sshHost','sshPort','sshUser','version') | Sort-Object
    Require (($names -join ',') -ceq ($expected -join ',') -and $settings.version -is [int] -and $settings.version -eq 1) 'H454_TUNNEL_CONFIG'
    foreach($name in @('caSha256','identitySha256','launcherSha256','nodeSha256','publicKeySha256')){
        Require ($settings.$name -is [string] -and $settings.$name -cmatch '^[A-F0-9]{64}$') 'H454_TUNNEL_CONFIG'
    }
    Require ($settings.sshHost -is [string] -and $settings.sshHost -cmatch '^[A-Za-z0-9.-]{1,253}$' -and
        $settings.sshUser -is [string] -and $settings.sshUser -cmatch '^[a-z_][a-z0-9_-]{0,63}$' -and
        $settings.sshPort -is [int] -and $settings.sshPort -ge 1 -and $settings.sshPort -le 65535 -and
        $settings.relayAddress -is [string]) 'H454_TUNNEL_CONFIG'
    $relay=$null
    Require ([Net.IPAddress]::TryParse($settings.relayAddress,[ref]$relay) -and
        $relay.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork -and
        $relay.ToString() -ceq $settings.relayAddress) 'H454_TUNNEL_CONFIG'
    $octets=$relay.GetAddressBytes()
    Require ($octets[0] -eq 10 -or ($octets[0] -eq 172 -and $octets[1] -ge 16 -and $octets[1] -le 31) -or
        ($octets[0] -eq 192 -and $octets[1] -eq 168)) 'H454_TUNNEL_CONFIG'
    $launcher=Join-Path $stateDir 'Hermes-H15-Windows-Permanent.ps1'
    $identity=Join-Path $stateDir 'h454-wss-identity.ps1'
    $public=Join-Path $stateDir 'wss-ssh-identity.pub'
    $ca=Join-Path $stateDir 'wss-relay-ca.pem'
    Assert-H454File $launcher $settings.launcherSha256 1048576
    Assert-H454File $identity $settings.identitySha256 65536
    Assert-H454File $public $settings.publicKeySha256 4096
    Assert-H454File $ca $settings.caSha256 65536
    $launcherText=[IO.File]::ReadAllText($launcher)
    $hostMatches=@([regex]::Matches($launcherText,'(?m)^\s*\$HOST_ADDR\s*=\s*''([^''\r\n]+)''\s*$'))
    $relayMatches=@([regex]::Matches($launcherText,'(?m)^\s*\$RELAY\s*=\s*''([^''\r\n]+)''\s*$'))
    $portMatches=@([regex]::Matches($launcherText,'(?m)^\s*\$SSH_PORT\s*=\s*([0-9]{1,5})\s*$'))
    $targetMatches=@([regex]::Matches($launcherText,'(?m)^\s*\$TUNNEL_TARGET\s*=\s*"([^"]+)"\s*$'))
    Require ($hostMatches.Count -eq 1 -and $relayMatches.Count -eq 1 -and $portMatches.Count -eq 1 -and
        $targetMatches.Count -eq 1 -and $hostMatches[0].Groups[1].Value -ceq $settings.sshHost -and
        $relayMatches[0].Groups[1].Value -ceq ($settings.relayAddress+':3000') -and
        [int]$portMatches[0].Groups[1].Value -eq $settings.sshPort) 'H454_TUNNEL_LAUNCHER_DRIFT'
    $launcherTarget=$targetMatches[0].Groups[1].Value.Replace('${HOST_ADDR}',$settings.sshHost).Replace('$HOST_ADDR',$settings.sshHost)
    Require ($launcherTarget -ceq ($settings.sshUser+'@'+$settings.sshHost)) 'H454_TUNNEL_LAUNCHER_DRIFT'
    $system=[Environment]::GetFolderPath('System')
    $powershell=Join-Path $system 'WindowsPowerShell\v1.0\powershell.exe'
    $ssh=Join-Path $system 'OpenSSH\ssh.exe'
    Require ((Get-AuthenticodeSignature -LiteralPath $ssh).Status -eq 'Valid') 'H454_TUNNEL_SSH'
    if($Preflight){'H454_WSS_TUNNEL_PREFLIGHT=PASS';exit 0}
    if(-not $h454JobInitialized){
        Initialize-H454TunnelJob $PSCommandPath
        $h454JobInitialized=$true
    }
    & $powershell -WindowStyle Hidden -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $identity -Mode Restore `
        -LauncherSha256 $settings.launcherSha256 -NodeSha256 $settings.nodeSha256 -OwnerApproved
    Require ($LASTEXITCODE -eq 0) 'H454_TUNNEL_IDENTITY'
    Require (@(Get-NetTCPConnection -LocalPort 38184 -State Listen -ErrorAction SilentlyContinue).Count -eq 0) 'H454_TUNNEL_PORT'
    $forward='127.0.0.1:38184:{0}:3001' -f $settings.relayAddress
    $target='{0}@{1}' -f $settings.sshUser,$settings.sshHost
    $sshArgs=@('-F','NUL','-N','-T','-p',[string]$settings.sshPort,'-i',$public,'-L',$forward,
        '-o','IdentitiesOnly=yes','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
        '-o','UpdateHostKeys=no','-o','ExitOnForwardFailure=yes','-o','ForwardAgent=no',
        '-o','ForwardX11=no','-o','PermitLocalCommand=no','-o','ProxyCommand=none',
        '-o','ProxyJump=none','-o','ConnectTimeout=10','-o','NumberOfPasswordPrompts=0',
        '-o','ServerAliveInterval=10','-o','ServerAliveCountMax=2',$target)
    & $ssh @sshArgs 1>$null 2>$null
    'H454_WSS_TUNNEL=DISCONNECTED'
}catch{
    $reason=$_.Exception.Message
    if($reason -cnotmatch '^H454_[A-Z0-9_]{1,60}$'){$reason='H454_TUNNEL_INTERNAL'}
    'H454_WSS_TUNNEL=HOLD';'H454_TUNNEL_REASON='+$reason
    if($Preflight){exit 1}
}
Start-Sleep -Seconds 10
}
