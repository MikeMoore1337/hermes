param(
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$')][string]$HermesAlias,
    [ValidatePattern('^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$')][string]$YfcAlias,
    [switch]$SelfTest,
    [switch]$CryptoSelfTest
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

function Read-Bounded([System.IO.Stream]$Stream) {
    $buffer = [byte[]]::new(2049)
    $count = 0
    while ($count -lt $buffer.Length) {
        $n = $Stream.Read($buffer, $count, $buffer.Length - $count)
        if ($n -eq 0) { break }
        $count += $n
    }
    if ($count -lt 1 -or $count -gt 2048) {
        [Array]::Clear($buffer, 0, $buffer.Length)
        throw 'H454_PIPE_LENGTH'
    }
    return ,@($buffer, $count)
}

function New-HiddenProcessInfo([string]$FileName) {
    $info = [Diagnostics.ProcessStartInfo]::new()
    $info.FileName = $FileName
    $info.UseShellExecute = $false
    $info.CreateNoWindow = $true
    $info.WindowStyle = [Diagnostics.ProcessWindowStyle]::Hidden
    $info.RedirectStandardOutput = $true
    $info.RedirectStandardError = $true
    return $info
}

if ($SelfTest) {
    $inputBytes = [Text.Encoding]::ASCII.GetBytes('synthetic')
    $fixture = [IO.MemoryStream]::new($inputBytes)
    $result = Read-Bounded $fixture
    if ($result[1] -ne $inputBytes.Length) { throw 'H454_SELFTEST' }
    $output = [IO.MemoryStream]::new()
    $output.Write($result[0], 0, $result[1])
    if ([Text.Encoding]::ASCII.GetString($output.ToArray()) -cne 'synthetic') { throw 'H454_SELFTEST' }
    [Array]::Clear($result[0], 0, $result[0].Length)
    if (@($result[0] | Where-Object { $_ -ne 0 }).Count -ne 0) { throw 'H454_SELFTEST' }
    $output.Dispose()
    $fixture.Dispose()
    $fixture = [IO.MemoryStream]::new([byte[]]::new(2049))
    try { Read-Bounded $fixture | Out-Null; throw 'H454_SELFTEST' }
    catch { if ($_.Exception.Message -ne 'H454_PIPE_LENGTH') { throw } }
    finally { $fixture.Dispose() }
    $info = New-HiddenProcessInfo ([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
    foreach ($arg in @('-NoProfile','-NonInteractive','-Command','[Console]::Out.Write("synthetic")')) { $info.ArgumentList.Add($arg) }
    $child = [Diagnostics.Process]::Start($info)
    try {
        $childError = $child.StandardError.ReadToEndAsync()
        $result = Read-Bounded $child.StandardOutput.BaseStream
        if (-not $child.WaitForExit(10000) -or $child.ExitCode -ne 0 -or
            [Text.Encoding]::ASCII.GetString($result[0],0,$result[1]) -cne 'synthetic') { throw 'H454_SELFTEST' }
        $sinkInfo = New-HiddenProcessInfo ([Diagnostics.Process]::GetCurrentProcess().MainModule.FileName)
        $sinkInfo.RedirectStandardInput = $true
        $sinkCode = '$b=[byte[]]::new(9);$n=[Console]::OpenStandardInput().Read($b,0,9);if($n -eq 9 -and [Text.Encoding]::ASCII.GetString($b) -ceq "synthetic"){[Console]::Out.Write("PASS")}else{exit 2}'
        foreach ($arg in @('-NoProfile','-NonInteractive','-Command',$sinkCode)) { $sinkInfo.ArgumentList.Add($arg) }
        $sink = [Diagnostics.Process]::Start($sinkInfo)
        try {
            $sinkOut = $sink.StandardOutput.ReadToEndAsync(); $sinkErr = $sink.StandardError.ReadToEndAsync()
            $sink.StandardInput.BaseStream.Write($result[0],0,$result[1]); $sink.StandardInput.Close()
            if (-not $sink.WaitForExit(10000) -or $sink.ExitCode -ne 0 -or
                $sinkOut.GetAwaiter().GetResult() -cne 'PASS') { throw 'H454_SELFTEST' }
        } finally {
            [Array]::Clear($result[0],0,$result[0].Length)
            if (-not $sink.HasExited) { $sink.Kill($true) }
            $sink.Dispose()
        }
    } finally {
        if (-not $child.HasExited) { $child.Kill($true) }
        $child.Dispose()
    }
    Write-Output 'H454_BRIDGE_SELFTEST_PASS'
    return
}

try {
    if (-not $HermesAlias -or -not $YfcAlias -or $HermesAlias -ceq $YfcAlias) { throw 'H454_ALIAS' }
    $ssh = Join-Path $env:WINDIR 'System32\OpenSSH\ssh.exe'
    if (-not (Test-Path -LiteralPath $ssh -PathType Leaf) -or
        (Get-AuthenticodeSignature -LiteralPath $ssh).Status -ne 'Valid') { throw 'H454_SSH' }

    $senderHash = '2c4f2af2c2bb5ab680507dcd190331ef1bffebbe6fde5807bde2389a96d0e868'
    $receiverHash = '6c826f9b2a9adbb33f6e2fbae0f066a4e896faebe2bea2135b4a07f39aa10cc1'
    $senderFile = '/root/h454-yfc-sender-preview/sender.py'
    $receiverFile = '/root/h454-yfc-receiver-preview/receiver.py'
    $senderBase = 'printf "%s  %s\n" "' + $senderHash + '" "' + $senderFile + '" | sha256sum -c --status && PYTHONPATH=/opt/hermes-agent-owner/releases/main-5b62d5bba585c6bb6d1f7f6abe6a7def33ab4f7d exec python3 -B ' + $senderFile
    $receiverBase = 'cd /root/h454-yfc-audit-4ef40634/source && printf "%s  %s\n" "34a7b4a5bae9d6f21f6eea68bedb5fb492af50626426a671be42106f31817ddf" "../source.sha256" | sha256sum -c --status && sha256sum -c --status ../source.sha256 && test "$(find scripts device_fabric -type f | wc -l)" -eq 30 && printf "%s  %s\n" "' + $receiverHash + '" "' + $receiverFile + '" | sha256sum -c --status && PYTHONPATH=/root/h454-yfc-audit-4ef40634/source exec python3 -B ' + $receiverFile

    function Start-Ssh([string]$Alias, [string]$Command, [bool]$InputPipe) {
        $info = New-HiddenProcessInfo $ssh
        $info.RedirectStandardInput = $InputPipe
        foreach ($argument in @('-T','-o','BatchMode=yes','-o','StrictHostKeyChecking=yes',
                                '-o','ConnectTimeout=10','-o','ServerAliveInterval=15',
                                '-o','ServerAliveCountMax=3','-o','ForwardAgent=no',
                                '-o','ForwardX11=no','-o','ClearAllForwardings=yes',
                                '-o','PermitLocalCommand=no','-o','ControlMaster=no',
                                '-o','ProxyCommand=none','-o','ProxyJump=none',$Alias,$Command)) {
            $info.ArgumentList.Add($argument)
        }
        return [Diagnostics.Process]::Start($info)
    }

    function Transfer-Cipher([Diagnostics.Process]$Source, [string]$Mode, [string]$Expected) {
        $data = $null; $destination = $null
        try {
            $data = Read-Bounded $Source.StandardOutput.BaseStream
            $Source.WaitForExit()
            if ($Source.ExitCode -ne 0 -or $data[1] -ne 512) { throw 'H454_SENDER' }
            $destination = Start-Ssh $YfcAlias ($receiverBase + ' ' + $Mode) $true
            $destinationOut = $destination.StandardOutput.ReadToEndAsync()
            $destinationErr = $destination.StandardError.ReadToEndAsync()
            $destination.StandardInput.BaseStream.Write($data[0],0,$data[1])
            $destination.StandardInput.BaseStream.Flush(); $destination.StandardInput.Close()
            if (-not $destination.WaitForExit(30000) -or $destination.ExitCode -ne 0 -or
                $destinationOut.GetAwaiter().GetResult().Trim() -cne $Expected) { throw 'H454_RECEIVER' }
        } finally {
            if ($null -ne $data) { [Array]::Clear($data[0],0,$data[0].Length) }
            if ($null -ne $destination) {
                if (-not $destination.HasExited) { $destination.Kill($true) }
                $destination.Dispose()
            }
        }
    }

    $check = Start-Ssh $YfcAlias ($receiverBase + ' preflight') $false
    $outTask = $check.StandardOutput.ReadToEndAsync(); $errTask = $check.StandardError.ReadToEndAsync()
    if (-not $check.WaitForExit(30000) -or $check.ExitCode -ne 0 -or
        $outTask.GetAwaiter().GetResult().Trim() -cne 'H454_YFC_RECEIVER_PREFLIGHT_PASS_NO_MUTATION') { throw 'H454_PREFLIGHT' }
    $check.Dispose()
    if ($CryptoSelfTest) {
        $sender = Start-Ssh $HermesAlias ($senderBase + ' selftest') $false
        $senderErr = $sender.StandardError.ReadToEndAsync()
        Transfer-Cipher $sender 'selftest' 'H454_YFC_CRYPTO_SELFTEST_PASS'
        Write-Output 'H454_YFC_CRYPTO_SELFTEST_PASS'
        return
    }
    $check = Start-Ssh $HermesAlias 'test ! -e /var/lib/hermes-h454-yfc-enrollment.pending && test ! -e /run/hermes-h454-yfc-enrollment && test ! -L /run/hermes-h454-yfc-enrollment' $false
    $outTask = $check.StandardOutput.ReadToEndAsync(); $errTask = $check.StandardError.ReadToEndAsync()
    if (-not $check.WaitForExit(30000) -or $check.ExitCode -ne 0) { throw 'H454_PRIOR_ATTEMPT' }
    $check.Dispose()

    $sender = Start-Ssh $HermesAlias ($senderBase + ' sender') $false
    $senderErr = $sender.StandardError.ReadToEndAsync()
    $ready = Start-Ssh $HermesAlias 'for n in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do test -S /run/hermes-h454-yfc-enrollment/owner.sock && exit 0; sleep 1; done; exit 1' $false
    $readyOut = $ready.StandardOutput.ReadToEndAsync(); $readyErr = $ready.StandardError.ReadToEndAsync()
    if (-not $ready.WaitForExit(35000) -or $ready.ExitCode -ne 0 -or $sender.HasExited) { throw 'H454_NOT_READY' }
    $ready.Dispose()
    Write-Output 'H454_YFC_OWNER_TERMINAL_READY'

    Transfer-Cipher $sender 'receive' 'H454_YFC_OWNER_DEVICE_PAIRED_NATIVE_OFF'
    Write-Output 'H454_YFC_OWNER_DEVICE_PAIRED_NATIVE_OFF'
} catch {
    Write-Output 'H454_YFC_BRIDGE_HOLD_NO_AUTO_RETRY'
    exit 2
} finally {
    foreach ($name in @('check','ready','sender','receiver')) {
        $variable = Get-Variable -Name $name -ErrorAction SilentlyContinue
        if ($null -ne $variable -and $null -ne $variable.Value) {
            try {
                if (-not $variable.Value.HasExited) { $variable.Value.Kill($true) }
                $variable.Value.Dispose()
            } catch { }
        }
    }
}
