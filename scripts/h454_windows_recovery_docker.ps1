#requires -Version 5.1
# A timeout is ambiguous: the daemon may still finish the requested action.
function Invoke-H454RecoveryDocker(
    [string[]]$Arguments,[string]$DockerSha256,[byte[]]$InputBytes=$null,[int]$TimeoutSeconds=20
) {
    Require-H454 ($DockerSha256 -cmatch '^[A-F0-9]{64}$' -and $null -ne $Arguments -and
        $Arguments.Count -gt 0 -and $Arguments.Count -le 48 -and $TimeoutSeconds -ge 1 -and $TimeoutSeconds -le 60 -and
        ($null -eq $InputBytes -or $InputBytes.Length -le 16384)) 'H454_DOCKER_INPUT'
    foreach($argument in $Arguments){
        Require-H454 ($null -ne $argument -and $argument -cmatch '^[A-Za-z0-9_./:=+,()''\[\]-]{1,8192}$' -and
            $argument -cnotmatch '^--(?:host|context|config|tlsverify|tlscacert|tlscert|tlskey)(?:=|$)' -and
            $argument -cnotmatch '^-(?:H|c)') 'H454_DOCKER_ARGUMENT'
    }
    foreach($name in @('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH','DOCKER_CONFIG','DOCKER_API_VERSION')){
        Require-H454 ([string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name,'Process'))) 'H454_DOCKER_ENV'
    }
    $docker=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Docker\Docker\resources\bin\docker.exe'
    $item=Get-Item -LiteralPath $docker -Force -ErrorAction Stop
    Require-H454 (-not $item.PSIsContainer) 'H454_DOCKER_BINARY'
    while($null -ne $item){
        Require-H454 (-not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)) 'H454_DOCKER_BINARY'
        if($item -is [IO.FileInfo]){$item=$item.Directory}else{$item=$item.Parent}
    }
    Require-H454 ((Get-FileHash -LiteralPath $docker -Algorithm SHA256).Hash -ceq $DockerSha256 -and
        (Get-AuthenticodeSignature -LiteralPath $docker).Status -eq 'Valid') 'H454_DOCKER_BINARY'
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$docker
    $info.Arguments='--host npipe:////./pipe/dockerDesktopLinuxEngine '+($Arguments -join ' ')
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true
    $info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
    $process=[Diagnostics.Process]::new();$process.StartInfo=$info
    try {
        Require-H454 $process.Start() 'H454_DOCKER_START'
        $output=$process.StandardOutput.ReadToEndAsync();$errors=$process.StandardError.ReadToEndAsync()
        try{
            if($null -ne $InputBytes -and $InputBytes.Length -gt 0){
                $write=$process.StandardInput.BaseStream.WriteAsync($InputBytes,0,$InputBytes.Length)
                if(-not $write.Wait(5000)){throw 'H454_DOCKER_AMBIGUOUS'}
                $write.GetAwaiter().GetResult()
            }
            $process.StandardInput.Close()
        }catch{try{$process.Kill()}catch{};throw 'H454_DOCKER_AMBIGUOUS'}
        if(-not $process.WaitForExit($TimeoutSeconds*1000)){try{$process.Kill()}catch{};throw 'H454_DOCKER_AMBIGUOUS'}
        $raw=$output.GetAwaiter().GetResult();$null=$errors.GetAwaiter().GetResult()
        Require-H454 ($raw.Length -le 2097152) 'H454_DOCKER_OUTPUT'
        return [pscustomobject]@{Code=$process.ExitCode;Output=$raw}
    }finally{$process.Dispose()}
}
