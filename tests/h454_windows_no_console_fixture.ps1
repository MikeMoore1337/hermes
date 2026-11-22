#requires -Version 5.1
param([Parameter(Mandatory=$true)][string]$Source,[Parameter(Mandatory=$true)][string]$FixtureParent)
$ErrorActionPreference='Stop'
function Require-H454([bool]$Condition,[string]$Reason){if(-not $Condition){throw $Reason}}
$parent=[IO.Path]::GetFullPath($FixtureParent)
$dir=Join-Path $parent ('h454-noconsole-'+[Guid]::NewGuid().ToString('N'))
Require-H454 ([IO.Path]::GetDirectoryName($dir) -ceq $parent -and -not (Test-Path -LiteralPath $dir)) 'FIXTURE_PATH'
[IO.Directory]::CreateDirectory($dir)|Out-Null
$exe=Join-Path $dir 'h454_windows_no_console.exe'
$guard=Join-Path $dir 'h454_windows_guard_operator.ps1'
$probeSource=Join-Path $dir 'probe.cs';$probe=Join-Path $dir 'probe.dll';$marker=Join-Path $dir 'result.txt'
$compiler=Join-Path ([Environment]::GetFolderPath('Windows')) 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
function Run-H454Hidden([string]$File,[string]$Arguments){
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$File;$info.Arguments=$Arguments
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $proc=[Diagnostics.Process]::Start($info)
    try{if(-not $proc.WaitForExit(30000)){try{$proc.Kill()}catch{};throw 'FIXTURE_TIMEOUT'};return $proc.ExitCode}finally{$proc.Dispose()}
}
try {
    Require-H454 ((Get-AuthenticodeSignature -LiteralPath $compiler).Status -eq 'Valid') 'FIXTURE_COMPILER'
    $probeCode='using System; using System.Runtime.InteropServices; public static class H454ConsoleProbe { [DllImport("kernel32.dll")] public static extern IntPtr GetConsoleWindow(); }'
    [IO.File]::WriteAllText($probeSource,$probeCode,[Text.UTF8Encoding]::new($false))
    Require-H454 ((Run-H454Hidden $compiler ('/nologo /target:library /out:"'+$probe+'" "'+$probeSource+'"')) -eq 0) 'FIXTURE_PROBE_COMPILE'
    Require-H454 ((Run-H454Hidden $compiler ('/nologo /target:winexe /out:"'+$exe+'" "'+[IO.Path]::GetFullPath($Source)+'"')) -eq 0) 'FIXTURE_COMPILE'
    $stream=[IO.File]::OpenRead($exe);$reader=[IO.BinaryReader]::new($stream)
    try{$stream.Position=0x3c;$offset=$reader.ReadInt32();$stream.Position=$offset+4+20+68;$subsystem=$reader.ReadUInt16()}finally{$reader.Dispose();$stream.Dispose()}
    Require-H454 ($subsystem -eq 2) 'FIXTURE_NOT_WINDOWS_GUI'
    $guardCode=@'
Add-Type -Path (Join-Path $PSScriptRoot 'probe.dll')
if ([H454ConsoleProbe]::GetConsoleWindow() -eq [IntPtr]::Zero) { [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'result.txt'),'NO_CONSOLE') }
else { [IO.File]::WriteAllText((Join-Path $PSScriptRoot 'result.txt'),'CONSOLE_PRESENT') }
Write-Output 'H454_SYNTHETIC_OUTPUT'
exit 17
'@
    [IO.File]::WriteAllText($guard,$guardCode,[Text.UTF8Encoding]::new($false))
    $arguments='-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "'+$guard+'" -RestoreOriginal -AutoRecover -Apply -OwnerApproved'
    $encoded=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($arguments))
    Require-H454 ((Run-H454Hidden $exe $encoded) -eq 17) 'FIXTURE_EXIT_CODE'
    Require-H454 ([IO.File]::ReadAllText($marker) -ceq 'NO_CONSOLE') 'FIXTURE_CONSOLE_CREATED'
    [IO.File]::Delete($marker)
    Require-H454 ((Run-H454Hidden $exe 'not-base64') -eq 2 -and -not (Test-Path -LiteralPath $marker)) 'FIXTURE_INVALID_BASE64'
    $bad=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($arguments.Replace('-AutoRecover','-RestageOnly')))
    Require-H454 ((Run-H454Hidden $exe $bad) -eq 2 -and -not (Test-Path -LiteralPath $marker)) 'FIXTURE_WRONG_MODE'
    $bad=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($arguments.Replace($guard,(Join-Path $parent 'other.ps1'))))
    Require-H454 ((Run-H454Hidden $exe $bad) -eq 2 -and -not (Test-Path -LiteralPath $marker)) 'FIXTURE_WRONG_GUARD'
    $bad=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($arguments+"`n"))
    Require-H454 ((Run-H454Hidden $exe $bad) -eq 2 -and -not (Test-Path -LiteralPath $marker)) 'FIXTURE_CONTROL_CHARACTER'
    'PS51_NO_CONSOLE_LAUNCHER=PASS'
} finally {
    foreach($file in @($marker,$guard,$probe,$probeSource,$exe)){if([IO.File]::Exists($file)){[IO.File]::Delete($file)}}
    [IO.Directory]::Delete($dir,$false)
}
