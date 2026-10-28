#requires -Version 5.1
<#
H445: no-device disposable Docker reaper test. Preflight is read-only.
Test creates one temporary --rm container only with -OwnerApproved.
Does not authorize maintenance or test BRC tool process-tree termination.
#>
[CmdletBinding()]
param([ValidateSet('Preflight','Test')][string]$Mode='Preflight',
      [switch]$OwnerApproved)
Set-StrictMode -Version Latest
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$cid='571a1e2bede31a07638b896e3ef2de677dafa1c000e4a7975e7996257f8ea162'
$image='sha256:8d28b0e1158b01c179ae1e6e1e399acaf3f502675522136d931ce08f2851a5a3'
function Deny([string]$Code) {
    Write-Output 'H445_DISPOSABLE_INIT=HOLD'
    Write-Output ('H445_REASON=' + $Code)
    exit 2
}
try {
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) { Deny 'WINDOWS_REQUIRED' }
    $docker=Join-Path $env:ProgramFiles 'Docker\Docker\resources\bin\docker.exe'
    $binary=Get-Item -LiteralPath $docker -Force -ErrorAction Stop
    if ($binary.PSIsContainer -or ($binary.Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        Deny 'UNTRUSTED_DOCKER_BINARY'
    }
    $fmt='{{.Id}}|{{.Name}}|{{.Image}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.Memory}}|{{.Config.User}}|{{.State.Running}}'
    $observed=@(& $docker container inspect --format $fmt $cid 2>$null)
    $expected="$cid|/hermes-h15-windows-permanent|$image|96|536870912|65534:65534|true"
    if ($LASTEXITCODE -ne 0 -or $observed.Count -ne 1 -or $observed[0] -cne $expected) {
        Deny 'EXACT_ORIGINAL_CONTAINER_DRIFT'
    }
    $installed=@(& $docker image inspect --format '{{.Id}}' $image 2>$null)
    if ($LASTEXITCODE -ne 0 -or $installed.Count -ne 1 -or $installed[0] -cne $image) {
        Deny 'PINNED_IMAGE_MISSING'
    }
    if ($Mode -eq 'Preflight') {
        if ($OwnerApproved) { Deny 'TEST_APPROVAL_ON_READONLY_PREFLIGHT' }
        Write-Output 'H445_DISPOSABLE_INIT=PREFLIGHT_PASS'
        Write-Output 'H445_DOCKER_IMAGE_PIN=PASS'
        Write-Output 'H445_TEST_CONTAINER_CREATED=FALSE'
        Write-Output 'H445_ROLLBACK_VERIFIED=FALSE'
        exit 0
    }
    if (-not $OwnerApproved) { Deny 'EXPLICIT_TEST_APPROVAL_REQUIRED' }
    # Force Node entrypoint, not the actual BRC agent. No device token,
    # mounts, network, Docker socket, host environment or ports.
    $js=@'
const fs=require('node:fs');
const {spawn}=require('node:child_process');
const delay=ms=>new Promise(r=>setTimeout(r,ms));
async function main(){
 const uid=process.getuid();
 const init=fs.readFileSync('/proc/1/comm','utf8').trim();
 if(uid!==65534 || !/^(tini|docker-init)$/.test(init)) throw Error('ISOLATION');
 for(let i=0;i<3;i++){
   const child=spawn('/bin/sh',['-c','sleep 0.1 & exit 0'],{stdio:'ignore'});
   await new Promise((resolve,reject)=>{
     child.once('error',reject);
     child.once('exit',code=>code===0?resolve():reject(Error('CHILD')));
   });
 }
 await delay(500);
 let zombies=0;
 for(const dir of fs.readdirSync('/proc')){
   if(!/^\d+$/.test(dir)) continue;
   let s;
   try{s=fs.readFileSync('/proc/'+dir+'/status','utf8');}
   catch(e){if(e.code==='ENOENT'||e.code==='ESRCH')continue;throw e;}
   const parent=/^PPid:\s*(\d+)/m.exec(s);
   const state=/^State:\s*([A-Z])/m.exec(s);
   if(parent?.[1]==='1'&&state?.[1]==='Z')zombies++;
 }
 const pids=Number(fs.readFileSync('/sys/fs/cgroup/pids.current','utf8').trim());
 const max=Number(fs.readFileSync('/sys/fs/cgroup/pids.max','utf8').trim());
 if(zombies!==0 || max!==96 || !Number.isSafeInteger(pids) || max-pids<24)
   throw Error('REAPER_OR_RESOURCE_HOLD');
 console.log('H445_REAPER_PROBE=PASS');
 console.log('H445_TEST_ZOMBIES=0');
 console.log('H445_TEST_PIDS_HEADROOM_GE_24=TRUE');
}
setTimeout(()=>process.exit(2),5000).unref();
main().catch(()=>{console.log('H445_REAPER_PROBE=HOLD');process.exitCode=2;});
'@
    # One disposable instance, auto-remove, no BRC state or project binds.
    $result=@(& $docker run --rm --pull=never --init --platform linux/amd64 --network none --read-only --user 65534:65534 --cap-drop ALL --security-opt no-new-privileges --pids-limit 96 --cpus 0.5 --memory 512m --tmpfs /tmp:rw,nosuid,nodev,size=16m --entrypoint node $image -e $js 2>$null)
    if ($LASTEXITCODE -ne 0 -or $result.Count -ne 3 -or
        $result[0] -cne 'H445_REAPER_PROBE=PASS' -or
        $result[1] -cne 'H445_TEST_ZOMBIES=0' -or
        $result[2] -cne 'H445_TEST_PIDS_HEADROOM_GE_24=TRUE') {
        Deny 'DISPOSABLE_REAPER_TRIAL_FAILED'
    }
    Write-Output 'H445_DISPOSABLE_INIT=PASS'
    Write-Output 'H445_TEST_NETWORK=NONE'
    Write-Output 'H445_TEST_MOUNTS=NONE'
    Write-Output 'H445_DOCKER_AUTO_REMOVE=REQUESTED'
    Write-Output 'H445_PRODUCTION_CUTOVER=NOT_AUTHORIZED'
    Write-Output 'H445_PROCESS_TREE_TERMINATION=NOT_TESTED'
    exit 0
} catch {
    Deny 'DIAGNOSTIC_UNAVAILABLE'
}
