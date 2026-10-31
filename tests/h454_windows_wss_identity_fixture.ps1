#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$FixtureParent)
$ErrorActionPreference='Stop'
$source=Join-Path $PSScriptRoot '..\scripts\h454_windows_wss_identity.ps1'
$tokens=$null;$errors=$null
$ast=[Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if($errors.Count){throw 'FIXTURE_PARSE'}
foreach($name in @('Require-H454','Assert-H454TaskPrincipal','Assert-H454NoReparse','Assert-H454Private','Get-H454Hash',
    'Write-H454NewPrivateFile','Invoke-H454Process','Invoke-H454IdentityNode','Get-H454AgentKeys','Restore-H454Identity')){
    $found=@($ast.FindAll({param($x) $x -is [Management.Automation.Language.FunctionDefinitionAst] -and $x.Name -ceq $name},$true))
    if($found.Count -ne 1){throw 'FIXTURE_FUNCTION'}
    . ([scriptblock]::Create($found[0].Extent.Text))
}
$parent=[IO.Path]::GetFullPath($FixtureParent)
Assert-H454NoReparse $parent
Require-H454 ((Get-Item -LiteralPath $parent -Force).PSIsContainer) 'FIXTURE_SCOPE'
$dir=Join-Path $parent ('h454-identity-fixture-'+[Guid]::NewGuid().ToString('N'))
Require-H454 ([IO.Path]::GetDirectoryName($dir) -ceq $parent -and -not(Test-Path -LiteralPath $dir)) 'FIXTURE_SCOPE'
[IO.Directory]::CreateDirectory($dir)|Out-Null
$sid=[Security.Principal.WindowsIdentity]::GetCurrent().User
$acl=[Security.AccessControl.DirectorySecurity]::new();$acl.SetAccessRuleProtection($true,$false);$acl.SetOwner($sid)
foreach($identity in @($sid,[Security.Principal.SecurityIdentifier]::new('S-1-5-18'),[Security.Principal.SecurityIdentifier]::new('S-1-5-32-544'))){
    $rule=[Security.AccessControl.FileSystemAccessRule]::new($identity,'FullControl','ContainerInherit,ObjectInherit','None','Allow')
    $acl.AddAccessRule($rule)
}
Set-Acl -LiteralPath $dir -AclObject $acl
$script:h454Entropy=[Text.Encoding]::UTF8.GetBytes('Hermes-H454-WSS-SSH-Identity-v1')
$node=Get-Command node.exe -CommandType Application | Select-Object -First 1 -ExpandProperty Source
$ssh=Join-Path ([Environment]::GetFolderPath('System')) 'OpenSSH\ssh-add.exe'
$module=Join-Path $PSScriptRoot '..\scripts\h454_windows_wss_identity.mjs'
$module64=[Convert]::ToBase64String([IO.File]::ReadAllBytes($module))
$backup=Join-Path $dir 'wss-ssh-identity.dpapi';$public=Join-Path $dir 'wss-ssh-identity.pub'
$key=$null;$plain=$null;$cleanup=$false;$agentOwned=$false
try{
    $principal=[pscustomobject]@{UserId=[Security.Principal.WindowsIdentity]::GetCurrent().Name;LogonType='Interactive'}
    Assert-H454TaskPrincipal $principal
    $principal.LogonType='ServiceAccount'
    $rejected=$false;try{Assert-H454TaskPrincipal $principal}catch{$rejected=$_.Exception.Message -ceq 'H454_IDENTITY_TASK_PRINCIPAL'}
    Require-H454 $rejected 'FIXTURE_TASK_PRINCIPAL'
    Require-H454 ([string]::IsNullOrEmpty($env:SSH_AUTH_SOCK) -and [string]::IsNullOrEmpty($env:NODE_OPTIONS) -and
        [string]::IsNullOrEmpty($env:NODE_PATH)) 'FIXTURE_ENV'
    Add-Type -AssemblyName System.Security
    Write-Output 'H454_IDENTITY_FIXTURE_GENERATE'
    $json=Invoke-H454IdentityNode 'generate' $null $node $module64 $ssh
    $plain=[Text.UTF8Encoding]::new($false).GetBytes($json);$json=$null
    $key=Invoke-H454IdentityNode 'public' $plain $node $module64 $ssh
    $needle=($key -split ' ')[0..1] -join ' '
    $before=Get-H454AgentKeys $ssh
    Require-H454 (@($before -split "`r?`n"|Where-Object {($_ -split '\s+')[0..1] -join ' ' -ceq $needle}).Count -eq 0) 'FIXTURE_KEY_COLLISION'
    $agentOwned=$true
    $encrypted=[Security.Cryptography.ProtectedData]::Protect($plain,$script:h454Entropy,[Security.Cryptography.DataProtectionScope]::CurrentUser)
    Write-H454NewPrivateFile $backup $encrypted
    [IO.File]::WriteAllText($public,'DO_NOT_OVERWRITE',[Text.UTF8Encoding]::new($false))
    $rejected=$false;try{Restore-H454Identity $dir $node $module64 $ssh}catch{$rejected=$_.Exception.Message -ceq 'H454_IDENTITY_PUBLIC_DRIFT'}
    Require-H454 ($rejected -and [IO.File]::ReadAllText($public) -ceq 'DO_NOT_OVERWRITE') 'FIXTURE_PUBLIC_OVERWRITE'
    [IO.File]::Delete($public)
    Write-Output 'H454_IDENTITY_FIXTURE_RESTORE'
    Restore-H454Identity $dir $node $module64 $ssh
    Require-H454 ([IO.File]::ReadAllText($public) -ceq ($key+"`n")) 'FIXTURE_PUBLIC'
    $hash=(Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash
    Restore-H454Identity $dir $node $module64 $ssh
    Require-H454 ((Get-FileHash -LiteralPath $backup -Algorithm SHA256).Hash -ceq $hash) 'FIXTURE_RESTORE_DRIFT'
    $bad=[IO.File]::ReadAllBytes($backup);$bad[$bad.Length-1]=$bad[$bad.Length-1] -bxor 1;[IO.File]::WriteAllBytes($backup,$bad)
    $rejected=$false;try{Restore-H454Identity $dir $node $module64 $ssh}catch{$rejected=$_.Exception.Message -ceq 'H454_IDENTITY_UNPROTECT'}
    Require-H454 $rejected 'FIXTURE_CORRUPT_BACKUP'
    Write-Output 'H454_SYNTHETIC_IDENTITY_DPAPI=PASS'
}finally{
    if($null -ne $plain){[Array]::Clear($plain,0,$plain.Length)}
    if($agentOwned){
        try{
            $needle=($key -split ' ')[0..1] -join ' '
            $present=@((Get-H454AgentKeys $ssh) -split "`r?`n"|Where-Object {($_ -split '\s+')[0..1] -join ' ' -ceq $needle}).Count
            if($present -eq 1){
                Require-H454 ((Test-Path -LiteralPath $public) -and [IO.File]::ReadAllText($public) -ceq ($key+"`n")) 'FIXTURE_CLEANUP_KEY'
                $removed=Invoke-H454Process $ssh ('-d "'+$public+'"') $null
                Require-H454 ($removed.Code -eq 0) 'FIXTURE_CLEANUP_KEY'
            }
            $present=@((Get-H454AgentKeys $ssh) -split "`r?`n"|Where-Object {($_ -split '\s+')[0..1] -join ' ' -ceq $needle}).Count
            Require-H454 ($present -eq 0) 'FIXTURE_CLEANUP_KEY'
            $cleanup=$true
        }catch{Write-Output 'H454_SYNTHETIC_IDENTITY_CLEANUP=HOLD'}
    }else{$cleanup=$true}
    if($cleanup -and (Test-Path -LiteralPath $dir)){
        Require-H454 ([IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($dir)) -ceq $parent) 'FIXTURE_SCOPE'
        Assert-H454NoReparse $dir
        Require-H454 (@(Get-ChildItem -LiteralPath $dir -Force -Recurse|Where-Object {$_.Attributes -band [IO.FileAttributes]::ReparsePoint}).Count -eq 0) 'FIXTURE_SCOPE'
        Remove-Item -LiteralPath $dir -Recurse -Force
    }
    if(-not $cleanup){throw 'FIXTURE_CLEANUP_KEY'}
}
