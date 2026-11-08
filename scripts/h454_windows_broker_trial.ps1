#requires -Version 5.1
# The caller owns runtime.lock and pins the sources, images and credentials.
function Get-H454BrokerTrialMarker([hashtable]$RestoreArgs,[string]$CandidateId,[string]$CandidateImage) {
    Require-H454 ($CandidateId -cmatch '^[a-f0-9]{64}$' -and $CandidateId -cne $RestoreArgs.AgentId -and
        $CandidateImage -cmatch '^sha256:[a-f0-9]{64}$' -and $CandidateImage -cne $RestoreArgs.AgentImage) 'H454_TRIAL_PINS'
    return [Text.UTF8Encoding]::new($false).GetBytes("H454-BROKER-TRIAL-1`n$($RestoreArgs.AgentId)`n$CandidateId`n$CandidateImage`n$($RestoreArgs.MarkerSha256)`n")
}

function Assert-H454BrokerTrialMarker([hashtable]$RestoreArgs,[string]$CandidateId,[string]$CandidateImage) {
    Assert-H454RecoveryLock $RestoreArgs.StateDir $RestoreArgs.Lock
    $bytes=Get-H454BrokerTrialMarker $RestoreArgs $CandidateId $CandidateImage
    Assert-H454WssTaskFile (Join-Path $RestoreArgs.StateDir 'h454-broker-trial.pending') (Hash-H454Bytes $bytes) 4096
}

function Get-H454BrokerTrialState([hashtable]$RestoreArgs,[string]$CandidateId,[string]$CandidateImage,[switch]$Pending) {
    if($Pending){Assert-H454BrokerTrialMarker $RestoreArgs $CandidateId $CandidateImage}
    $s=@{StateDir=$RestoreArgs.StateDir;Lock=$RestoreArgs.Lock;MarkerSha256=$RestoreArgs.MarkerSha256;
        SafetyCheck=$RestoreArgs.SafetyCheck;Launcher=$RestoreArgs.Launcher;LauncherSha256=$RestoreArgs.LauncherSha256;
        AgentId=$RestoreArgs.AgentId;AgentImage=$RestoreArgs.AgentImage;AgentName=$RestoreArgs.AgentName;
        OldImage=$RestoreArgs.OldImage;BrokerImage=$RestoreArgs.BrokerImage;CaSha256=$RestoreArgs.CaSha256;
        DockerSha256=$RestoreArgs.DockerSha256}
    Assert-H454RecoveryRouteSafety $s.StateDir $s.Lock $s.MarkerSha256 $s.SafetyCheck
    $label=$s.MarkerSha256.Substring(0,32).ToLowerInvariant();$networkName='h454-recovery-'+$label
    $network=Find-H454RecoveryObject 'network' $networkName $s.DockerSha256
    $plan=Assert-H454RecoveryNetwork $network $networkName $label
    $original=Find-H454RecoveryObject 'container' $s.AgentName $s.DockerSha256
    $candidate=Find-H454RecoveryObject 'container' 'hermes-h454-broker-candidate' $s.DockerSha256
    Require-H454 ($null -ne $original -and $original.Id -ceq $s.AgentId -and
        $null -ne $candidate -and $candidate.Id -ceq $CandidateId) 'H454_TRIAL_IDENTITY'
    $base=Get-H454CandidateImage $s.AgentImage $s.DockerSha256
    $image=Get-H454CandidateImage $CandidateImage $s.DockerSha256
    Assert-H454CandidateImage $base $image $s.AgentImage $CandidateImage
    $bridge=Find-H454RecoveryObject 'network' 'bridge' $s.DockerSha256
    Require-H454 ($null -ne $bridge -and $bridge.Driver -ceq 'bridge') 'H454_TRIAL_NETWORK'
    Assert-H454PreparedCandidate $candidate $original $image 'hermes-h454-broker-candidate' `
        $CandidateImage $s.AgentId $label $bridge.Id $networkName $plan.Id
    $names=@($candidate.NetworkSettings.Networks.PSObject.Properties.Name)
    $onPrivate=$names -ccontains $networkName;$onBridge=$names -ccontains 'bridge'
    if($onPrivate){$snapshot=Get-H454OriginalRestoreState @s -AlternateAgentId $CandidateId}
    else{$snapshot=Get-H454OriginalRestoreState @s}
    Require-H454 ($snapshot.Plan.Id -ceq $plan.Id -and $snapshot.Bridge.Id -ceq $bridge.Id) 'H454_TRIAL_NETWORK'
    if($candidate.State.Running){
        $view=[pscustomobject]@{Agent=$candidate;Broker=$snapshot.Broker;Network=$snapshot.Network;Plan=$snapshot.Plan;
            Bridge=$snapshot.Bridge;Label=$snapshot.Label;NetworkName=$snapshot.NetworkName;HostAddress=$snapshot.HostAddress;
            OnPrivate=$onPrivate;OnBridge=$onBridge}
        Assert-H454OriginalLiveRoute $view $CandidateId $s.DockerSha256
    }elseif($snapshot.Agent.State.Running){Assert-H454OriginalLiveRoute $snapshot $s.AgentId $s.DockerSha256}
    return [pscustomobject]@{Original=$snapshot;Candidate=$candidate;OnPrivate=$onPrivate;OnBridge=$onBridge}
}

function Get-H454TrialRecordedOperation([hashtable]$RestoreArgs,[string]$CandidateId,[string]$Phase,
    [string]$Nonce,[string]$Target,[string]$Network,[long]$StartTicks,[long]$EndTicks) {
    $original=@('STOP_ORIGINAL','START_ORIGINAL','CONNECT_ORIGINAL','DISCONNECT_ORIGINAL','STAGE_ORIGINAL')
    $candidate=@('STOP_CANDIDATE','START_CANDIDATE','CONNECT_CANDIDATE','DISCONNECT_CANDIDATE','STAGE_CANDIDATE')
    $networkPhases=@('CONNECT_ORIGINAL','DISCONNECT_ORIGINAL','CONNECT_CANDIDATE','DISCONNECT_CANDIDATE')
    Require-H454 ($CandidateId -cmatch '^[a-f0-9]{64}$' -and $CandidateId -cne $RestoreArgs.AgentId -and
        $Nonce -cmatch '^[a-f0-9]{32}$' -and $Target -cmatch '^[a-f0-9]{64}$' -and
        (($Phase -cin $original -and $Target -ceq $RestoreArgs.AgentId) -or
         ($Phase -cin $candidate -and $Target -ceq $CandidateId) -or
         ($Phase -ceq 'STAGE_BROKER' -and $Target -cne $CandidateId -and $Target -cne $RestoreArgs.AgentId)) -and
        (($Phase -cin $networkPhases -and $Network -cmatch '^[a-f0-9]{64}$') -or
         ($Phase -cnotin $networkPhases -and $Network -ceq '-')) -and
        (($Phase -ceq 'STOP_ORIGINAL' -and $StartTicks -gt 0 -and $StartTicks -lt $EndTicks) -or
         ($Phase -cne 'STOP_ORIGINAL' -and $StartTicks -eq 0 -and $EndTicks -eq 0))) 'H454_TRIAL_RECORDED_INPUT'
    $value="H454-BROKER-TRIAL-INFLIGHT-2`n$Phase`n$Nonce`n$Target`n$Network`n$StartTicks`n$EndTicks`n"
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($value)
    return [pscustomobject]@{Phase=$Phase;Nonce=$Nonce;Target=$Target;Network=$Network;
        StartTicks=$StartTicks;EndTicks=$EndTicks;Bytes=$bytes;Hash=(Hash-H454Bytes $bytes)}
}

function Start-H454TrialRecordedOperation([hashtable]$RestoreArgs,[object]$Operation) {
    Assert-H454BrokerTrialSettled $RestoreArgs
    $path=Join-Path $RestoreArgs.StateDir 'h454-broker-trial.inflight'
    $stream=[IO.FileStream]::new($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
    try{$stream.Write($Operation.Bytes,0,$Operation.Bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    Assert-H454WssTaskFile $path $Operation.Hash 4096
}

function Resolve-H454TrialRecordedOperation([hashtable]$RestoreArgs,[string]$CandidateId,[string]$CandidateImage='') {
    Assert-H454RecoveryLock $RestoreArgs.StateDir $RestoreArgs.Lock
    $path=Join-Path $RestoreArgs.StateDir 'h454-broker-trial.inflight'
    if(-not (Test-Path -LiteralPath $path)){return $null}
    Assert-H454PrivateAcl $path
    $item=Get-Item -LiteralPath $path -Force
    Require-H454 (-not $item.PSIsContainer -and $item.Length -le 1024) 'H454_TRIAL_OPERATION_UNKNOWN'
    $value=[IO.File]::ReadAllText($path)
    if($value -cnotmatch '^H454-BROKER-TRIAL-INFLIGHT-2\n([A-Z_]{1,40})\n([a-f0-9]{32})\n([a-f0-9]{64})\n(-|[a-f0-9]{64})\n([0-9]{1,18})\n([0-9]{1,18})\n$'){return $null}
    $operation=Get-H454TrialRecordedOperation $RestoreArgs $CandidateId $Matches[1] $Matches[2] $Matches[3] $Matches[4] ([long]$Matches[5]) ([long]$Matches[6])
    Assert-H454WssTaskFile $path $operation.Hash 4096
    $receipt=Join-Path $RestoreArgs.StateDir ('h454-broker-op-'+$operation.Nonce+'.receipt')
    if(-not (Test-Path -LiteralPath $receipt)){return $null}
    Assert-H454PrivateAcl $receipt
    $item=Get-Item -LiteralPath $receipt -Force
    Require-H454 (-not $item.PSIsContainer -and $item.Length -le 256) 'H454_TRIAL_RECEIPT_INVALID'
    $actual=[IO.File]::ReadAllText($receipt)
    $prefix="H454-BROKER-TRIAL-RECEIPT-1`n$($operation.Hash)`n"
    $status=if($actual -ceq ($prefix+"HTTP_OK`n")){'HTTP_OK'}
        elseif($operation.Phase -ceq 'STOP_ORIGINAL' -and $actual -ceq ($prefix+"WINDOW_EXPIRED`n")){'WINDOW_EXPIRED'}
        elseif($operation.Phase -cin @('STAGE_ORIGINAL','STAGE_CANDIDATE','STAGE_BROKER') -and $actual -ceq ($prefix+"INPUT_INCOMPLETE`n")){'INPUT_INCOMPLETE'}
        else{throw 'H454_TRIAL_RECEIPT_INVALID'}
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes($actual)
    Assert-H454WssTaskFile $receipt (Hash-H454Bytes $bytes) 256
    Assert-H454WssTaskFile $path $operation.Hash 4096
    if($operation.Phase -ceq 'STAGE_BROKER'){
        Require-H454 ($CandidateImage -cmatch '^sha256:[a-f0-9]{64}$') 'H454_TRIAL_RECEIPT_BROKER'
        $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
        Require-H454 ($state.Original.Broker.Id -ceq $operation.Target) 'H454_TRIAL_RECEIPT_BROKER'
    }
    [IO.File]::Delete($path)
    Require-H454 (-not (Test-Path -LiteralPath $path)) 'H454_TRIAL_OPERATION_UNKNOWN'
    try{[IO.File]::Delete($receipt)}catch{}
    return $status
}

function Start-H454TrialReceiptWorker([hashtable]$RestoreArgs,[object]$Operation,[byte[]]$InputBytes=$null) {
    Assert-H454RecoveryLock $RestoreArgs.StateDir $RestoreArgs.Lock
    $isStage=$Operation.Phase -cin @('STAGE_ORIGINAL','STAGE_CANDIDATE','STAGE_BROKER')
    Require-H454 (($isStage -and $null -ne $InputBytes -and $InputBytes.Length -gt 0 -and $InputBytes.Length -le 16384 -and
        $RestoreArgs.DockerSha256 -cmatch '^[A-F0-9]{64}$') -or (-not $isStage -and $null -eq $InputBytes)) 'H454_TRIAL_WORKER_INPUT'
    $powershell=Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe'
    $item=Get-Item -LiteralPath $powershell -Force -ErrorAction Stop
    $current=[Diagnostics.Process]::GetCurrentProcess()
    try{$currentPath=$current.MainModule.FileName}finally{$current.Dispose()}
    Require-H454 ($PSVersionTable.PSVersion.Major -eq 5 -and -not $item.PSIsContainer -and
        -not ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -and
        [IO.Path]::GetFullPath($currentPath) -ieq [IO.Path]::GetFullPath($powershell)) 'H454_TRIAL_WORKER_BINARY'
    Require-H454 ($RestoreArgs.StateDir.Length -le 1024 -and $RestoreArgs.StateDir -cnotmatch '[\x00-\x1f]') 'H454_TRIAL_WORKER_PATH'
    $sha=[Security.Cryptography.SHA256]::Create();$hashStream=[IO.File]::OpenRead($powershell)
    try{$workerHash=[BitConverter]::ToString($sha.ComputeHash($hashStream)).Replace('-','')}finally{$hashStream.Dispose();$sha.Dispose()}
    $inputLength=if($isStage){$InputBytes.Length}else{0}
    $dockerHash=if($isStage){$RestoreArgs.DockerSha256}else{'-'}
    $payload=@($RestoreArgs.StateDir,$Operation.Phase,$Operation.Nonce,$Operation.Target,$Operation.Network,
        [string]$Operation.StartTicks,[string]$Operation.EndTicks,$Operation.Hash,$workerHash,[string]$inputLength,$dockerHash) -join "`n"
    $data=[Convert]::ToBase64String([Text.UTF8Encoding]::new($false).GetBytes($payload))
    $source=@'
$ErrorActionPreference='Stop'
$pipe=$null;$secret=$null;$client=$null
try {
    $parts=([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('__PAYLOAD__'))).Split([char]10)
    if($parts.Count -ne 11){throw 'INPUT'}
    $p=[pscustomobject]@{state=$parts[0];phase=$parts[1];nonce=$parts[2];target=$parts[3];network=$parts[4];
        start=$parts[5];end=$parts[6];hash=$parts[7];workerHash=$parts[8];inputLength=$parts[9];dockerHash=$parts[10]}
    if($p.nonce -cnotmatch '^[a-f0-9]{32}$' -or $p.target -cnotmatch '^[a-f0-9]{64}$' -or
       $p.hash -cnotmatch '^[A-F0-9]{64}$' -or $p.workerHash -cnotmatch '^[A-F0-9]{64}$' -or
       -not [IO.Path]::IsPathRooted($p.state)){throw 'INPUT'}
    $self=[Diagnostics.Process]::GetCurrentProcess()
    try{$selfPath=$self.MainModule.FileName}finally{$self.Dispose()}
    $sha=[Security.Cryptography.SHA256]::Create();$hashStream=[IO.File]::OpenRead($selfPath)
    try{$actual=[BitConverter]::ToString($sha.ComputeHash($hashStream)).Replace('-','')}finally{$hashStream.Dispose();$sha.Dispose()}
    if($actual -cne $p.workerHash){throw 'WORKER_DRIFT'}
    $body='';$expected=204;$isStage=$false
    switch -CaseSensitive ($p.phase) {
        'STOP_ORIGINAL' {$uri='/v1.56/containers/'+$p.target+'/stop?t=10'}
        'STOP_CANDIDATE' {$uri='/v1.56/containers/'+$p.target+'/stop?t=10'}
        'START_ORIGINAL' {$uri='/v1.56/containers/'+$p.target+'/start'}
        'START_CANDIDATE' {$uri='/v1.56/containers/'+$p.target+'/start'}
        {$_ -cin @('STAGE_ORIGINAL','STAGE_CANDIDATE','STAGE_BROKER')} {$isStage=$true}
        {$_ -cin @('CONNECT_ORIGINAL','CONNECT_CANDIDATE','DISCONNECT_ORIGINAL','DISCONNECT_CANDIDATE')} {
            if($p.network -cnotmatch '^[a-f0-9]{64}$'){throw 'NETWORK'}
            $connect=$p.phase.StartsWith('CONNECT_', [StringComparison]::Ordinal)
            $action=if($connect){'connect'}else{'disconnect'}
            $uri='/v1.56/networks/'+$p.network+'/'+$action
            $body=if($connect){'{"Container":"'+$p.target+'"}'}else{'{"Container":"'+$p.target+'","Force":false}'}
            $expected=200
        }
        default {throw 'PHASE'}
    }
    $status='HTTP_OK'
    if($isStage){
        if($p.inputLength -cnotmatch '^[1-9][0-9]{0,4}$' -or [int]$p.inputLength -gt 16384 -or
            $p.dockerHash -cnotmatch '^[A-F0-9]{64}$'){throw 'STAGE_INPUT'}
        $secret=New-Object byte[] ([int]$p.inputLength);$offset=0;$stdin=[Console]::OpenStandardInput()
        try{
            while($offset -lt $secret.Length){
                $read=$stdin.ReadAsync($secret,$offset,$secret.Length-$offset)
                if(-not $read.Wait(5000)){$status='INPUT_INCOMPLETE';break}
                $count=$read.GetAwaiter().GetResult();if($count -le 0){$status='INPUT_INCOMPLETE';break}
                $offset+=$count
            }
        }finally{$stdin.Dispose()}
        if($status -ceq 'HTTP_OK'){
            foreach($name in @('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH','DOCKER_CONFIG','DOCKER_API_VERSION')){
                if(-not [string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name,'Process'))){throw 'DOCKER_ENV'}
            }
            $docker=Join-Path ([Environment]::GetFolderPath('ProgramFiles')) 'Docker\Docker\resources\bin\docker.exe'
            $item=Get-Item -LiteralPath $docker -Force
            while($null -ne $item){
                if($item.Attributes -band [IO.FileAttributes]::ReparsePoint){throw 'DOCKER_BINARY'}
                if($item -is [IO.FileInfo]){$item=$item.Directory}else{$item=$item.Parent}
            }
            $sha=[Security.Cryptography.SHA256]::Create();$hashStream=[IO.File]::OpenRead($docker)
            try{$actual=[BitConverter]::ToString($sha.ComputeHash($hashStream)).Replace('-','')}finally{$hashStream.Dispose();$sha.Dispose()}
            if($actual -cne $p.dockerHash -or (Get-AuthenticodeSignature -LiteralPath $docker).Status -ne 'Valid'){throw 'DOCKER_BINARY'}
            $bootstrap="eval(Buffer.from(process.argv[1],'base64').toString())"
            if($p.phase -cin @('STAGE_ORIGINAL','STAGE_CANDIDATE')){
                $script="const c=require('node:child_process');const p=c.spawn('/bin/sh',['/usr/local/bin/h15-stage.sh'],{stdio:['pipe','ignore','ignore']});process.stdin.pipe(p.stdin);p.on('error',()=>process.exit(2));p.on('close',x=>{if(x!==0)process.exit(2);process.stdout.write('H454_AGENT_STAGE_COMPLETE',()=>process.exit(0))})"
                $script64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($script))
                $command='node -e '+$bootstrap+' '+$script64;$expectedText='H454_AGENT_STAGE_COMPLETE'
            }else{$command='node /opt/hermes-rollback/stage.cjs';$expectedText='H454_BROKER_TOKEN_STAGED'}
            $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$docker
            $info.Arguments='--host npipe:////./pipe/dockerDesktopLinuxEngine exec --interactive --user 65534:65534 '+$p.target+' '+$command
            $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
            $info.RedirectStandardInput=$true;$info.RedirectStandardOutput=$true;$info.RedirectStandardError=$true
            $client=[Diagnostics.Process]::new();$client.StartInfo=$info
            if(-not $client.Start()){throw 'CLIENT_START'}
            $discard=$client.StandardError.BaseStream.CopyToAsync([IO.Stream]::Null)
            try{
                $write=$client.StandardInput.BaseStream.WriteAsync($secret,0,$secret.Length)
                if(-not $write.Wait(5000)){throw 'CLIENT_INPUT_TIMEOUT'}
                $null=$write.GetAwaiter().GetResult()
            }finally{$client.StandardInput.Close()}
            $buffer=New-Object byte[] 128;$output=[IO.MemoryStream]::new();$deadline=[DateTime]::UtcNow.AddSeconds(45)
            try{
                while($true){
                    $remaining=[int][Math]::Max(1,($deadline-[DateTime]::UtcNow).TotalMilliseconds)
                    if([DateTime]::UtcNow -ge $deadline){throw 'CLIENT_OUTPUT_TIMEOUT'}
                    $read=$client.StandardOutput.BaseStream.ReadAsync($buffer,0,$buffer.Length)
                    if(-not $read.Wait($remaining)){throw 'CLIENT_OUTPUT_TIMEOUT'}
                    $count=$read.GetAwaiter().GetResult();if($count -le 0){break}
                    $output.Write($buffer,0,$count);if($output.Length -gt 128){throw 'CLIENT_OUTPUT_OVERSIZED'}
                }
                $remaining=[int][Math]::Max(1,($deadline-[DateTime]::UtcNow).TotalMilliseconds)
                if(-not $client.WaitForExit($remaining) -or $client.ExitCode -ne 0 -or
                    [Text.Encoding]::ASCII.GetString($output.ToArray()) -cne $expectedText){throw 'CLIENT_RESULT'}
            }finally{$output.Dispose()}
        }
    } else {
        $pipe=[IO.Pipes.NamedPipeClientStream]::new('.','dockerDesktopLinuxEngine',[IO.Pipes.PipeDirection]::InOut,[IO.Pipes.PipeOptions]::Asynchronous)
        $pipe.Connect(5000)
        $now=[DateTime]::UtcNow.Ticks
        if($p.phase -ceq 'STOP_ORIGINAL' -and
           ($now -lt [long]$p.start -or $now+[TimeSpan]::FromSeconds(20).Ticks -gt [long]$p.end)) {
            $status='WINDOW_EXPIRED'
        } else {
        $request=[Text.Encoding]::ASCII.GetBytes("POST $uri HTTP/1.1`r`nHost: docker`r`nContent-Type: application/json`r`nContent-Length: $($body.Length)`r`nConnection: close`r`n`r`n$body")
        $write=$pipe.WriteAsync($request,0,$request.Length)
        if(-not $write.Wait(5000)){throw 'WRITE_TIMEOUT'}
        $null=$write.GetAwaiter().GetResult()
        $buffer=New-Object byte[] 4096;$received=[IO.MemoryStream]::new();$deadline=[DateTime]::UtcNow.AddSeconds(45)
        try {
            $header=''
            while(-not $header.Contains("`r`n`r`n")) {
                $remaining=[int][Math]::Max(1,($deadline-[DateTime]::UtcNow).TotalMilliseconds)
                if([DateTime]::UtcNow -ge $deadline){throw 'RESPONSE_TIMEOUT'}
                $read=$pipe.ReadAsync($buffer,0,$buffer.Length)
                if(-not $read.Wait($remaining)){throw 'RESPONSE_TIMEOUT'}
                $count=$read.GetAwaiter().GetResult();if($count -le 0){throw 'RESPONSE_CLOSED'}
                $received.Write($buffer,0,$count);if($received.Length -gt 16384){throw 'RESPONSE_OVERSIZED'}
                $header=[Text.Encoding]::ASCII.GetString($received.ToArray())
            }
            if($header -cnotmatch ('^HTTP/1\.[01] '+$expected+'(?: [^\r\n]*)?\r\n')){throw 'RESPONSE_STATUS'}
        } finally {$received.Dispose()}
        }
    }
    $receipt=Join-Path $p.state ('h454-broker-op-'+$p.nonce+'.receipt')
    $bytes=[Text.UTF8Encoding]::new($false).GetBytes("H454-BROKER-TRIAL-RECEIPT-1`n$($p.hash)`n$status`n")
    $stream=[IO.FileStream]::new($receipt,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
} catch {exit 2} finally {
    if($null -ne $secret){[Array]::Clear($secret,0,$secret.Length)}
    if($null -ne $client){$client.Dispose()}
    if($null -ne $pipe){$pipe.Dispose()}
}
'@
    Require-H454 ($source.Split(@('__PAYLOAD__'),[StringSplitOptions]::None).Length -eq 2) 'H454_TRIAL_WORKER_SOURCE'
    $source=$source.Replace('__PAYLOAD__',$data)
    $encoded=[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($source))
    $info=[Diagnostics.ProcessStartInfo]::new();$info.FileName=$powershell
    $info.Arguments='-NoProfile -NonInteractive -EncodedCommand '+$encoded
    $info.UseShellExecute=$false;$info.CreateNoWindow=$true;$info.WindowStyle=[Diagnostics.ProcessWindowStyle]::Hidden
    $info.EnvironmentVariables['PSModulePath']=Join-Path $PSHOME 'Modules'
    if($isStage){$info.RedirectStandardInput=$true}
    $process=[Diagnostics.Process]::new();$process.StartInfo=$info
    try{
        Require-H454 $process.Start() 'H454_TRIAL_WORKER_START'
        if($isStage){
            try{
                $write=$process.StandardInput.BaseStream.WriteAsync($InputBytes,0,$InputBytes.Length)
                if(-not $write.Wait(5000)){throw 'H454_TRIAL_WORKER_INPUT_TIMEOUT'}
                $null=$write.GetAwaiter().GetResult()
            }finally{$process.StandardInput.Close()}
        }
        $null=$process.WaitForExit(30000)
    }finally{$process.Dispose()}
}

function Assert-H454BrokerTrialSettled([hashtable]$RestoreArgs) {
    Assert-H454RecoveryLock $RestoreArgs.StateDir $RestoreArgs.Lock
    $path=Join-Path $RestoreArgs.StateDir 'h454-broker-trial.inflight'
    if(Test-Path -LiteralPath $path){
        $phase='OPERATION'
        try{
            Assert-H454PrivateAcl $path
            if((Get-Item -LiteralPath $path).Length -le 1024){
                $value=[IO.File]::ReadAllText($path)
                if($value -cmatch '^H454-BROKER-TRIAL-INFLIGHT-(?:1|2)\n([A-Z_]{1,40})\n'){$phase=$Matches[1]}
            }
        }catch{}
        throw ('H454_TRIAL_UNKNOWN_'+$phase)
    }
}

function Start-H454BrokerTrialOperation([hashtable]$RestoreArgs,[string]$Phase) {
    Assert-H454BrokerTrialSettled $RestoreArgs
    Require-H454 ($Phase -cin @('STOP_ORIGINAL','STOP_CANDIDATE','START_CANDIDATE','CONNECT_ORIGINAL','DISCONNECT_ORIGINAL',
        'CONNECT_CANDIDATE','DISCONNECT_CANDIDATE','CHECK_CANDIDATE','STAGE_CANDIDATE','VERIFY_CANDIDATE',
        'STAGE_BROKER','RESTORE_ORIGINAL','ACKNOWLEDGE_ORIGINAL')) 'H454_TRIAL_PHASE'
    $path=Join-Path $RestoreArgs.StateDir 'h454-broker-trial.inflight'
    $bytes=[Text.Encoding]::UTF8.GetBytes("H454-BROKER-TRIAL-INFLIGHT-1`n$Phase`n")
    $stream=[IO.FileStream]::new($path,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    Assert-H454WssTaskFile $path (Hash-H454Bytes $bytes) 4096
}

function Complete-H454BrokerTrialOperation([hashtable]$RestoreArgs,[string]$Phase) {
    Assert-H454RecoveryLock $RestoreArgs.StateDir $RestoreArgs.Lock
    $path=Join-Path $RestoreArgs.StateDir 'h454-broker-trial.inflight'
    $bytes=[Text.Encoding]::UTF8.GetBytes("H454-BROKER-TRIAL-INFLIGHT-1`n$Phase`n")
    Assert-H454WssTaskFile $path (Hash-H454Bytes $bytes) 4096
    [IO.File]::Delete($path)
    Require-H454 (-not (Test-Path -LiteralPath $path)) 'H454_TRIAL_OPERATION_UNKNOWN'
}

function Invoke-H454BrokerTrialDocker([hashtable]$RestoreArgs,[string[]]$Arguments,[byte[]]$InputBytes=$null,
    [datetime]$WindowStartUtc,[datetime]$WindowEndUtc,[string]$CandidateId,[string]$CandidateImage='',[string]$BrokerId='') {
    $phase=switch($Arguments[0]){
        'stop'{if($Arguments[-1] -ceq $RestoreArgs.AgentId){'STOP_ORIGINAL'}else{'STOP_CANDIDATE'}}
        'start'{if($Arguments[-1] -ceq $RestoreArgs.AgentId){'START_ORIGINAL'}else{'START_CANDIDATE'}}
        'network'{
            $target=if($Arguments[-1] -ceq $RestoreArgs.AgentId){'ORIGINAL'}else{'CANDIDATE'}
            if($Arguments[1] -ceq 'connect'){'CONNECT_'+$target}elseif($Arguments[1] -ceq 'disconnect'){'DISCONNECT_'+$target}else{'INVALID'}
        }
        'exec'{
            if($Arguments -ccontains '/usr/local/bin/h15-stage.sh'){
                if($Arguments[4] -ceq $RestoreArgs.AgentId){'STAGE_ORIGINAL'}else{'STAGE_CANDIDATE'}
            }
            elseif($Arguments -ccontains '/opt/hermes-rollback/stage.cjs'){'STAGE_BROKER'}
            elseif($Arguments -ccontains '--interactive'){'VERIFY_CANDIDATE'}else{'CHECK_CANDIDATE'}
        }
        default{'INVALID'}
    }
    $recorded=@('STOP_ORIGINAL','STOP_CANDIDATE','START_ORIGINAL','START_CANDIDATE','CONNECT_ORIGINAL','DISCONNECT_ORIGINAL',
        'CONNECT_CANDIDATE','DISCONNECT_CANDIDATE','STAGE_ORIGINAL','STAGE_CANDIDATE','STAGE_BROKER')
    if($phase -cin $recorded){
        $isStage=$phase -cin @('STAGE_ORIGINAL','STAGE_CANDIDATE','STAGE_BROKER')
        if($isStage){
            Require-H454 ($null -ne $InputBytes -and $InputBytes.Length -gt 0 -and $InputBytes.Length -le 16384 -and
                $Arguments.Count -eq 7 -and $Arguments[1] -ceq '--interactive' -and $Arguments[2] -ceq '--user' -and
                $Arguments[3] -ceq '65534:65534' -and
                (((($phase -ceq 'STAGE_CANDIDATE' -and $Arguments[4] -ceq $CandidateId) -or
                   ($phase -ceq 'STAGE_ORIGINAL' -and $Arguments[4] -ceq $RestoreArgs.AgentId)) -and
                  $Arguments[5] -ceq '/bin/sh' -and $Arguments[6] -ceq '/usr/local/bin/h15-stage.sh') -or
                 ($phase -ceq 'STAGE_BROKER' -and $BrokerId -cmatch '^[a-f0-9]{64}$' -and $Arguments[4] -ceq $BrokerId -and
                  $Arguments[5] -ceq 'node' -and $Arguments[6] -ceq '/opt/hermes-rollback/stage.cjs'))) 'H454_TRIAL_RECORDED_INPUT'
            foreach($name in @('DOCKER_HOST','DOCKER_CONTEXT','DOCKER_TLS_VERIFY','DOCKER_CERT_PATH','DOCKER_CONFIG','DOCKER_API_VERSION')){
                Require-H454 ([string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable($name,'Process'))) 'H454_DOCKER_ENV'
            }
        }else{
            Require-H454 ($null -eq $InputBytes -and
                (($Arguments[0] -ceq 'stop' -and $Arguments.Count -eq 4 -and $Arguments[1] -ceq '--time' -and $Arguments[2] -ceq '10') -or
                 ($Arguments[0] -ceq 'start' -and $Arguments.Count -eq 2) -or
                 ($Arguments[0] -ceq 'network' -and $Arguments.Count -eq 4))) 'H454_TRIAL_RECORDED_INPUT'
        }
        $network=if($Arguments[0] -ceq 'network'){$Arguments[2]}else{'-'}
        $startTicks=0L;$endTicks=0L
        if($phase -ceq 'STOP_ORIGINAL'){
            $now=[DateTime]::UtcNow
            Require-H454 ($WindowStartUtc.Kind -eq [DateTimeKind]::Utc -and $WindowEndUtc.Kind -eq [DateTimeKind]::Utc -and
                $now -ge $WindowStartUtc -and $now.AddSeconds(20) -le $WindowEndUtc) 'H454_TRIAL_WINDOW'
            $startTicks=$WindowStartUtc.Ticks;$endTicks=$WindowEndUtc.Ticks
        }
        $target=if($isStage){$Arguments[4]}else{$Arguments[-1]}
        $operation=Get-H454TrialRecordedOperation $RestoreArgs $CandidateId $phase ([Guid]::NewGuid().ToString('N')) `
            $target $network $startTicks $endTicks
        Start-H454TrialRecordedOperation $RestoreArgs $operation
        Start-H454TrialReceiptWorker $RestoreArgs $operation $InputBytes
        $status=Resolve-H454TrialRecordedOperation $RestoreArgs $CandidateId $CandidateImage
        Require-H454 ($null -ne $status) 'H454_TRIAL_DOCKER_HOLD'
        if($status -ceq 'WINDOW_EXPIRED'){throw 'H454_TRIAL_WINDOW'}
        Require-H454 ($status -ceq 'HTTP_OK') 'H454_TRIAL_WORKER_INPUT_INCOMPLETE'
        if($phase -ceq 'STAGE_BROKER'){return 'H454_BROKER_TOKEN_STAGED'}
        return ''
    }
    Start-H454BrokerTrialOperation $RestoreArgs $phase
    $result=Invoke-H454RecoveryDocker -Arguments $Arguments -DockerSha256 $RestoreArgs.DockerSha256 -InputBytes $InputBytes
    Require-H454 ($result.Code -eq 0) 'H454_TRIAL_DOCKER_HOLD'
    Complete-H454BrokerTrialOperation $RestoreArgs $phase
    return $result.Output
}

function Assert-H454BrokerTrialCredential([hashtable]$RestoreArgs,[byte[]]$TokenBytes,[byte[]]$AgentBytes) {
    Require-H454 ($null -ne $TokenBytes -and $TokenBytes.Length -ge 48 -and $TokenBytes.Length -le 264 -and
        $null -ne $AgentBytes -and $AgentBytes.Length -gt 0 -and $AgentBytes.Length -le 16384) 'H454_TRIAL_CREDENTIAL'
    $utf8=[Text.UTF8Encoding]::new($false,$true)
    $token=$utf8.GetString($TokenBytes);$agentText=$utf8.GetString($AgentBytes);$surrogate='brc_dev_'+('s'*43)
    $agent=ConvertFrom-Json -InputObject $agentText -ErrorAction Stop
    Require-H454 ($token -cmatch '^brc_dev_[A-Za-z0-9_-]{40,256}$' -and $token -cne $surrogate -and
        $agentText.IndexOf($token,[StringComparison]::Ordinal) -lt 0 -and $agent.pairedAt -ceq 'manual' -and
        $agent.deviceToken -ceq $surrogate) 'H454_TRIAL_CREDENTIAL'
    $null=Convert-H454SecureCredential $agentText $RestoreArgs.DeviceId 'http://host.docker.internal:38180'
}

function Start-H454BrokerTrial([hashtable]$RestoreArgs,[string]$CandidateId,[string]$CandidateImage,
    [byte[]]$TokenBytes=$null,[byte[]]$AgentBytes=$null,[datetime]$WindowStartUtc,[datetime]$WindowEndUtc,
    [switch]$Apply,[switch]$OwnerApproved) {
    Require-H454 (-not $Apply -or $OwnerApproved) 'H454_TRIAL_APPROVAL'
    Assert-H454BrokerTrialSettled $RestoreArgs
    $marker=Join-Path $RestoreArgs.StateDir 'h454-broker-trial.pending'
    Require-H454 (-not (Test-Path -LiteralPath $marker)) 'H454_TRIAL_PENDING'
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage
    Require-H454 ($state.Original.Agent.State.Running -and $state.Original.OnPrivate -and -not $state.Original.OnBridge -and
        -not $state.Candidate.State.Running -and $state.Candidate.State.Status -ceq 'created' -and
        $state.OnBridge -and -not $state.OnPrivate) 'H454_TRIAL_START_STATE'
    if(-not $Apply){return [pscustomobject]@{Status='PREFLIGHT';CandidateId=$CandidateId}}
    $now=[DateTime]::UtcNow
    Require-H454 ($WindowStartUtc.Kind -eq [DateTimeKind]::Utc -and $WindowEndUtc.Kind -eq [DateTimeKind]::Utc -and
        $WindowStartUtc -lt $WindowEndUtc -and $now -ge $WindowStartUtc -and $now.AddSeconds(20) -le $WindowEndUtc) 'H454_TRIAL_WINDOW'
    Assert-H454BrokerTrialCredential $RestoreArgs $TokenBytes $AgentBytes
    $verifier=Read-H454PinnedBytes $RestoreArgs.VerifierPath $RestoreArgs.VerifierSha256
    $bytes=Get-H454BrokerTrialMarker $RestoreArgs $CandidateId $CandidateImage
    Assert-H454RecoveryLock $RestoreArgs.StateDir $RestoreArgs.Lock
    $stream=[IO.FileStream]::new($marker,[IO.FileMode]::CreateNew,[IO.FileAccess]::Write,[IO.FileShare]::None,4096,[IO.FileOptions]::WriteThrough)
    try{$stream.Write($bytes,0,$bytes.Length);$stream.Flush($true)}finally{$stream.Dispose()}
    Assert-H454BrokerTrialMarker $RestoreArgs $CandidateId $CandidateImage
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    $now=[DateTime]::UtcNow
    Require-H454 ($now -ge $WindowStartUtc -and $now.AddSeconds(20) -le $WindowEndUtc -and $state.Original.Agent.State.Running -and
        $state.Original.OnPrivate -and -not $state.Original.OnBridge -and $state.OnBridge -and -not $state.OnPrivate -and
        $state.Candidate.State.Status -ceq 'created') 'H454_TRIAL_STOP_GATE'
    $null=Invoke-H454BrokerTrialDocker $RestoreArgs @('stop','--time','10',$RestoreArgs.AgentId) -WindowStartUtc $WindowStartUtc -WindowEndUtc $WindowEndUtc -CandidateId $CandidateId
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    Require-H454 (-not $state.Original.Agent.State.Running -and $state.Original.OnPrivate -and -not $state.Original.OnBridge) 'H454_TRIAL_ORIGINAL_STOP'
    $null=Invoke-H454BrokerTrialDocker $RestoreArgs @('network','connect',$state.Original.Bridge.Id,$RestoreArgs.AgentId) -CandidateId $CandidateId
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    Require-H454 (-not $state.Original.Agent.State.Running -and $state.Original.OnPrivate -and $state.Original.OnBridge) 'H454_TRIAL_ORIGINAL_ROUTE'
    $null=Invoke-H454BrokerTrialDocker $RestoreArgs @('network','disconnect',$state.Original.Plan.Id,$RestoreArgs.AgentId) -CandidateId $CandidateId
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    Require-H454 (-not $state.Original.Agent.State.Running -and -not $state.Original.OnPrivate -and $state.Original.OnBridge -and
        $state.OnBridge -and -not $state.OnPrivate) 'H454_TRIAL_ORIGINAL_ROUTE'
    $null=Invoke-H454BrokerTrialDocker $RestoreArgs @('network','connect',$state.Original.Plan.Id,$CandidateId) -CandidateId $CandidateId
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    Require-H454 (-not $state.Candidate.State.Running -and $state.OnBridge -and $state.OnPrivate) 'H454_TRIAL_CANDIDATE_ROUTE'
    $null=Invoke-H454BrokerTrialDocker $RestoreArgs @('network','disconnect',$state.Original.Bridge.Id,$CandidateId) -CandidateId $CandidateId
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    Require-H454 (-not $state.Candidate.State.Running -and -not $state.OnBridge -and $state.OnPrivate) 'H454_TRIAL_CANDIDATE_ROUTE'
    $null=Invoke-H454BrokerTrialDocker $RestoreArgs @('start',$CandidateId) -CandidateId $CandidateId
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    Require-H454 ($state.Candidate.State.Running -and $state.OnPrivate -and -not $state.OnBridge) 'H454_TRIAL_CANDIDATE_START'
    $bootstrap="eval(Buffer.from(process.argv[1],'base64').toString())"
    $empty="const f=require('node:fs');try{const d=f.lstatSync('/run/brc');if(!d.isDirectory()||d.isSymbolicLink()||d.uid!==65534||(d.mode&511)!==448)throw 0;for(const p of ['ready','device.json','config.json']){try{f.lstatSync('/run/brc/'+p);throw 0}catch(e){if(e.code!=='ENOENT')throw 0}}process.stdout.write('H454_STAGE_EMPTY')}catch{process.exit(2)}"
    $empty64=[Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($empty))
    Require-H454 ((Invoke-H454BrokerTrialDocker $RestoreArgs @('exec','--user','65534:65534',$CandidateId,'node','-e',$bootstrap,$empty64)) -ceq 'H454_STAGE_EMPTY') 'H454_TRIAL_STAGE_DRIFT'
    $null=Invoke-H454BrokerTrialDocker $RestoreArgs @('exec','--interactive','--user','65534:65534',$CandidateId,'/bin/sh','/usr/local/bin/h15-stage.sh') $AgentBytes -CandidateId $CandidateId
    $verifier64=[Convert]::ToBase64String($verifier)
    Require-H454 ((Invoke-H454BrokerTrialDocker $RestoreArgs @('exec','--interactive','--user','65534:65534',$CandidateId,'node','-e',$bootstrap,$verifier64) $AgentBytes) -ceq 'H454_STAGED_CREDENTIAL_MATCH') 'H454_TRIAL_STAGE_VERIFY'
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    Require-H454 ((Get-FileHash -LiteralPath $RestoreArgs.VerifierPath -Algorithm SHA256).Hash -ceq $RestoreArgs.VerifierSha256) 'H454_TRIAL_VERIFIER'
    Require-H454 ((Invoke-H454BrokerTrialDocker $RestoreArgs @('exec','--interactive','--user','65534:65534',$state.Original.Broker.Id,'node','/opt/hermes-rollback/stage.cjs') $TokenBytes -CandidateId $CandidateId -CandidateImage $CandidateImage -BrokerId $state.Original.Broker.Id) -ceq 'H454_BROKER_TOKEN_STAGED') 'H454_TRIAL_STAGE_BROKER'
    $null=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    return [pscustomobject]@{Status='CANDIDATE_STAGED_MCP_REQUIRED';CandidateId=$CandidateId}
}

function New-H454TrialRestoreMutation {
    # The callback runs synchronously within the recovery call that holds the pinned IDs.
    return {
        param([string[]]$Arguments,[byte[]]$InputBytes)
        $output=Invoke-H454BrokerTrialDocker $RestoreArgs $Arguments $InputBytes -CandidateId $CandidateId -CandidateImage $CandidateImage -BrokerId $trialBrokerId
        return [pscustomobject]@{Code=0;Output=$output}
    }
}

function Restore-H454BrokerTrial([hashtable]$RestoreArgs,[string]$CandidateId,[string]$CandidateImage,
    [byte[]]$TokenBytes=$null,[byte[]]$AgentBytes=$null,[switch]$Apply,[switch]$OwnerApproved) {
    Require-H454 (-not $Apply -or $OwnerApproved) 'H454_TRIAL_APPROVAL'
    Assert-H454BrokerTrialMarker $RestoreArgs $CandidateId $CandidateImage
    if($Apply){$null=Resolve-H454TrialRecordedOperation $RestoreArgs $CandidateId $CandidateImage}
    Assert-H454BrokerTrialSettled $RestoreArgs
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    if(-not $Apply){return [pscustomobject]@{Status='RECOVERY_PREFLIGHT';CandidateRunning=$state.Candidate.State.Running}}
    Assert-H454BrokerTrialCredential $RestoreArgs $TokenBytes $AgentBytes
    $null=Read-H454PinnedBytes $RestoreArgs.VerifierPath $RestoreArgs.VerifierSha256
    if($state.Candidate.State.Running){
        Require-H454 (-not $state.Original.Agent.State.Running -and $state.OnPrivate -and -not $state.OnBridge) 'H454_TRIAL_RECOVERY_STATE'
        $null=Invoke-H454BrokerTrialDocker $RestoreArgs @('stop','--time','10',$CandidateId) -CandidateId $CandidateId
        $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    }
    Require-H454 (-not $state.Candidate.State.Running) 'H454_TRIAL_RECOVERY_STATE'
    if($state.OnPrivate -and -not $state.OnBridge){
        $null=Invoke-H454BrokerTrialDocker $RestoreArgs @('network','connect',$state.Original.Bridge.Id,$CandidateId) -CandidateId $CandidateId
        $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    }
    if($state.OnPrivate -and $state.OnBridge){
        Require-H454 (-not $state.Original.Agent.State.Running) 'H454_TRIAL_RECOVERY_STATE'
        $null=Invoke-H454BrokerTrialDocker $RestoreArgs @('network','disconnect',$state.Original.Plan.Id,$CandidateId) -CandidateId $CandidateId
        $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    }
    Require-H454 ($state.OnBridge -and -not $state.OnPrivate -and -not $state.Candidate.State.Running) 'H454_TRIAL_RECOVERY_STATE'
    $trialBrokerId=$state.Original.Broker.Id
    $mutation=New-H454TrialRestoreMutation
    $restored=Restore-H454Original @RestoreArgs -TokenBytes $TokenBytes -AgentBytes $AgentBytes -Apply -OwnerApproved -TrialMutation $mutation
    Require-H454 ($restored.Status -ceq 'ORIGINAL_STAGED' -and $restored.AgentId -ceq $RestoreArgs.AgentId) 'H454_TRIAL_RESTORE'
    Assert-H454BrokerTrialMarker $RestoreArgs $CandidateId $CandidateImage
    return [pscustomobject]@{Status='ORIGINAL_STAGED_MCP_REQUIRED';AgentId=$restored.AgentId}
}

function Complete-H454BrokerTrial([hashtable]$RestoreArgs,[string]$CandidateId,[string]$CandidateImage,
    [byte[]]$TokenBytes=$null,[byte[]]$AgentBytes=$null,[switch]$OriginalMcpObserved,[switch]$Apply,[switch]$OwnerApproved) {
    Require-H454 (-not $Apply -or ($OwnerApproved -and $OriginalMcpObserved)) 'H454_TRIAL_MCP_ACKNOWLEDGMENT'
    Assert-H454BrokerTrialMarker $RestoreArgs $CandidateId $CandidateImage
    if($Apply){$null=Resolve-H454TrialRecordedOperation $RestoreArgs $CandidateId $CandidateImage}
    Assert-H454BrokerTrialSettled $RestoreArgs
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    Require-H454 ($state.Original.Agent.State.Running -and $state.Original.OnPrivate -and -not $state.Original.OnBridge -and
        -not $state.Candidate.State.Running -and $state.OnBridge -and -not $state.OnPrivate) 'H454_TRIAL_RECOVERY_STATE'
    if(-not $Apply){return [pscustomobject]@{Status='ACKNOWLEDGMENT_PREFLIGHT'}}
    Assert-H454BrokerTrialCredential $RestoreArgs $TokenBytes $AgentBytes
    $trialBrokerId=$state.Original.Broker.Id
    $mutation=New-H454TrialRestoreMutation
    $restored=Restore-H454Original @RestoreArgs -TokenBytes $TokenBytes -AgentBytes $AgentBytes -Apply -OwnerApproved -RestageOnly -TrialMutation $mutation
    Require-H454 ($restored.Status -ceq 'ORIGINAL_STAGED' -and $restored.AgentId -ceq $RestoreArgs.AgentId) 'H454_TRIAL_RESTORE'
    $state=Get-H454BrokerTrialState $RestoreArgs $CandidateId $CandidateImage -Pending
    Require-H454 ($state.Original.Agent.State.Running -and -not $state.Candidate.State.Running -and
        $state.Original.OnPrivate -and -not $state.Original.OnBridge -and $state.OnBridge -and -not $state.OnPrivate) 'H454_TRIAL_RECOVERY_STATE'
    $marker=Join-Path $RestoreArgs.StateDir 'h454-broker-trial.pending'
    Assert-H454BrokerTrialMarker $RestoreArgs $CandidateId $CandidateImage
    [IO.File]::Delete($marker)
    Require-H454 (-not (Test-Path -LiteralPath $marker)) 'H454_TRIAL_MARKER'
    return [pscustomobject]@{Status='RECOVERY_ACKNOWLEDGED';AgentId=$RestoreArgs.AgentId}
}
