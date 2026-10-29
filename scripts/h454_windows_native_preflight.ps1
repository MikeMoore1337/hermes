#requires -Version 5.1
<# Read-only PS5.1 interpreter/stdin preflight. No Docker, credentials or tasks. #>
[CmdletBinding()]
param()
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Get-H454Application([string]$Name) {
    # PS5.1 can return several ApplicationInfo objects for duplicate PATH entries.
    $command = Get-Command $Name -CommandType Application -ErrorAction Stop | Select-Object -First 1
    $path = [string]$command.Path
    if (-not [IO.Path]::IsPathRooted($path) -or
        -not [IO.File]::Exists($path)) { throw 'EXECUTABLE_RESOLUTION_FAILED' }
    $item = Get-Item -LiteralPath $path -Force -ErrorAction Stop
    if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {
        throw 'EXECUTABLE_RESOLUTION_FAILED'
    }
    return $item.FullName
}

function Get-H454Python {
    # py is a launcher; ProcessStartInfo must receive the actual interpreter.
    $resolved = @(& py.exe -3.14 -I -B -c 'import sys; print(sys.executable)' 2>$null)
    if ($LASTEXITCODE -ne 0 -or $resolved.Count -ne 1) { throw 'PYTHON_RESOLUTION_FAILED' }
    $python = [string]$resolved[0]
    if (-not [IO.Path]::IsPathRooted($python) -or
        [IO.Path]::GetFileName($python) -ine 'python.exe') { throw 'PYTHON_PATH_INVALID' }
    $item = Get-Item -LiteralPath $python -Force -ErrorAction Stop
    if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'PYTHON_PATH_INVALID'
    }
    return $item.FullName
}

function Invoke-H454StdinProbe([string]$Python) {
    $process = New-Object Diagnostics.Process
    $settings = New-Object Diagnostics.ProcessStartInfo
    $settings.FileName = $Python
    $settings.Arguments = '-I -B -'
    $settings.UseShellExecute = $false
    $settings.CreateNoWindow = $true
    $settings.RedirectStandardInput = $true
    $settings.RedirectStandardOutput = $true
    $settings.RedirectStandardError = $true
    $settings.StandardOutputEncoding = [Text.UTF8Encoding]::new($false)
    $settings.StandardErrorEncoding = [Text.UTF8Encoding]::new($false)
    $process.StartInfo = $settings
    try {
        if (-not $process.Start()) { throw 'PROCESS_START_FAILED' }
        $stdout = $process.StandardOutput.ReadToEndAsync()
        $stderr = $process.StandardError.ReadToEndAsync()
        $probe = "import sys`nassert sys.version_info[:2] == (3, 14)`ns = '" + [char]0x0416 + "'`nassert ord(s) == 1046`nprint('H454_STDIN_UTF8=PASS')`n"
        $bytes = [Text.UTF8Encoding]::new($false).GetBytes($probe)
        $inputStream = $process.StandardInput.BaseStream
        try {
            if (-not $inputStream.WriteAsync($bytes, 0, $bytes.Length).Wait(10000)) {
                throw 'COMMAND_TIMEOUT'
            }
        } finally { $inputStream.Close() }
        if (-not $process.WaitForExit(10000)) { throw 'COMMAND_TIMEOUT' }
        if ($process.ExitCode -ne 0 -or
            $stdout.GetAwaiter().GetResult().Trim() -cne 'H454_STDIN_UTF8=PASS' -or
            $stderr.GetAwaiter().GetResult().Length -ne 0) { throw 'STDIN_PROBE_FAILED' }
    } finally {
        try { if (-not $process.HasExited) { $process.Kill() } } catch {}
        $process.Dispose()
    }
}

function Write-H454NativeFailure($Record) {
    Write-Output 'H454_NATIVE_PREFLIGHT=HOLD'
    $reason = [string]$Record.Exception.Message
    if ($reason -cnotin @('EXECUTABLE_RESOLUTION_FAILED','PYTHON_RESOLUTION_FAILED','PYTHON_PATH_INVALID',
        'PROCESS_START_FAILED','COMMAND_TIMEOUT','STDIN_PROBE_FAILED')) {
        $reason = 'RUNTIME_EXCEPTION'
    }
    Write-Output ('H454_REASON=' + $reason)
    $exception = $Record.Exception
    for ($depth = 0; $null -ne $exception -and $depth -lt 8; $depth++) {
        if ($exception -is [ComponentModel.Win32Exception]) {
            Write-Output ('H454_WIN32_CODE=' + [int]$exception.NativeErrorCode)
            break
        }
        $exception = $exception.InnerException
    }
    Write-Output 'H454_CHANGES_APPLIED=FALSE'
}

if ($MyInvocation.InvocationName -ne '.') {
    try {
        $python = Get-H454Python
        $null = Get-H454Application 'git.exe'
        $null = Get-H454Application 'curl.exe'
        Invoke-H454StdinProbe $python
        Write-Output 'H454_NATIVE_PREFLIGHT=PASS'
        Write-Output 'H454_PYTHON_DIRECT_INTERPRETER=PASS'
        Write-Output 'H454_WINDOWS_EXECUTABLES=PASS'
        Write-Output 'H454_PS51_STDIN_SELFTEST=PASS'
        Write-Output 'H454_CHANGES_APPLIED=FALSE'
    } catch {
        Write-H454NativeFailure $_
        exit 2
    }
}
