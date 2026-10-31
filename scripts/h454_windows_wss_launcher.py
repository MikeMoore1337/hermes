"""Prepare a pinned Run-only WSS launcher; never install or run it."""
from __future__ import annotations

import hashlib
from pathlib import Path
import re

from scripts.h15_remote_commander_candidate_audit import AuditError
from scripts.h454_windows_launcher_guard import GUARD

CREDENTIAL_SOURCE_SHA256 = "4ec857e4b91f6f29191b1931c20d874948a80e4b8abcbf2a221d2847686ca48b"
ERROR_POLICY = "$ErrorActionPreference = 'Stop'\n"
RUN = "if ($Mode -eq 'Run') {\n"
LISTENER = "-LocalAddress '127.0.0.1' -LocalPort 38180 -State Listen"
DEVICE = "        Require ($json.deviceId -ceq $state.deviceId) 'DPAPI_DEVICE_ID_MISMATCH'\n"

IDENTITY = """    $script:h454WssIdentity = Join-Path ([IO.Path]::GetDirectoryName($STATE_PATH)) 'wss-ssh-identity.pub'
    function Assert-H454WssIdentity {
        Require ([string]::IsNullOrEmpty([Environment]::GetEnvironmentVariable('SSH_AUTH_SOCK', 'Process'))) 'H454_SSH_AGENT_OVERRIDE'
        Assert-H454PrivateState $script:h454WssIdentity
        $h454IdentityItem = Get-Item -LiteralPath $script:h454WssIdentity -Force
        Require (-not $h454IdentityItem.PSIsContainer -and $h454IdentityItem.Length -gt 0 -and
            $h454IdentityItem.Length -le 4096) 'H454_SSH_IDENTITY_FORMAT'
        Require ((Get-FileHash -LiteralPath $script:h454WssIdentity -Algorithm SHA256).Hash -ceq '__IDENTITY_SHA256__') 'H454_SSH_IDENTITY_DRIFT'
    }
"""

VERIFY_STAGED_JS = (
    "const f=require('node:fs'),c=require('node:crypto');try{"
    "const e=JSON.parse(f.readFileSync(0,'utf8'));"
    "const r=f.lstatSync('/run/brc/ready',{bigint:true});"
    "if(!r.isFile()||r.uid!==65534n||r.gid!==65534n||(r.mode&0o777n)!==0o600n||r.nlink!==1n)throw 0;"
    "const d=f.openSync('/run/brc/device.json',f.constants.O_RDONLY|f.constants.O_NOFOLLOW);"
    "const x=f.fstatSync(d,{bigint:true});"
    "if(!x.isFile()||x.uid!==65534n||x.gid!==65534n||(x.mode&0o777n)!==0o600n||x.nlink!==1n||x.size>65536n)throw 0;"
    "const raw=f.readFileSync(d),y=f.fstatSync(d,{bigint:true});f.closeSync(d);"
    "if(x.dev!==y.dev||x.ino!==y.ino||x.size!==y.size||x.mtimeNs!==y.mtimeNs||x.ctimeNs!==y.ctimeNs||y.nlink!==1n)throw 0;"
    "const a=JSON.parse(raw.toString('utf8')),k=['deviceId','deviceToken','name','pairedAt','relayUrl'];"
    "const valid=o=>o&&typeof o==='object'&&!Array.isArray(o)&&Object.keys(o).sort().join(',')===k.join(',')&&k.every(p=>typeof o[p]==='string');"
    "if(!valid(a)||!valid(e)||k.some(p=>p!=='deviceToken'&&a[p]!==e[p]))throw 0;"
    "const t=Buffer.from(a.deviceToken),u=Buffer.from(e.deviceToken);"
    "if(t.length!==u.length||!c.timingSafeEqual(t,u))throw 0;"
    "process.stdout.write('H454_STAGED_CREDENTIAL_MATCH')}catch{process.exit(2)}"
)

STAGED_HELPER = """    function Assert-H454StagedCredential([string]$ContainerId,[string]$Credential) {
        Require ($ContainerId -cmatch '^[a-f0-9]{64}$' -and -not [string]::IsNullOrEmpty($Credential)) 'H454_STAGED_INPUT'
        $h454OutputEncoding = $OutputEncoding; $h454Exit = -1
        try {
            $OutputEncoding = [Text.UTF8Encoding]::new($false)
            $h454Result = @($Credential | & $script:h454Docker --host $script:h454DockerHost exec --interactive --user '65534:65534' $ContainerId node -e "__VERIFY_STAGED_JS__" 2>$null)
            $h454Exit = $LASTEXITCODE
        } finally { $OutputEncoding = $h454OutputEncoding }
        Require ($h454Exit -eq 0 -and $h454Result.Count -eq 1 -and $h454Result[0] -ceq 'H454_STAGED_CREDENTIAL_MATCH') 'H454_STAGED_CREDENTIAL_DRIFT'
    }
"""

HEALTH = """function Test-LocalHealth {
    try {
        $h454Ca = Join-Path ([IO.Path]::GetDirectoryName($STATE_PATH)) 'wss-relay-ca.pem'
        if (-not (Test-Path -LiteralPath $h454Ca -PathType Leaf)) { return $false }
        $h454CaItem = Get-Item -LiteralPath $h454Ca -Force
        if (($h454CaItem.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $h454CaItem.Length -le 0 -or $h454CaItem.Length -gt 65536) { return $false }
        $h454Sha = [Security.Cryptography.SHA256]::Create()
        try { $h454Hash = [BitConverter]::ToString($h454Sha.ComputeHash([IO.File]::ReadAllBytes($h454Ca))).Replace('-', '') }
        finally { $h454Sha.Dispose() }
        if ($h454Hash -cne '__CA_SHA256__') { return $false }
        $h454Curl = Join-Path ([Environment]::GetFolderPath('System')) 'curl.exe'
        if (-not (Test-Path -LiteralPath $h454Curl -PathType Leaf)) { return $false }
        $h454Resolve = 'brc-agent.internal:{0}:127.0.0.1' -f $PORT
        $h454Url = 'https://brc-agent.internal:{0}/' -f $PORT
        $h454Result = & $h454Curl -q --proto '=https' --noproxy '*' --ssl-revoke-best-effort --silent --connect-timeout 2 --max-time 4 `
            --cacert $h454Ca --resolve $h454Resolve --output NUL --write-out '%{http_code}' $h454Url
        return ($LASTEXITCODE -eq 0 -and $h454Result -ceq '404')
    } catch { return $false }
}
"""

RECONNECT = """    function Restart-H454WssTunnel([object]$Previous, [string[]]$Arguments) {
        Stop-H454TunnelHandle $Previous
        Assert-H454WssIdentity
        Start-Sleep -Seconds 5
        $h454Next = $null; $h454Ready = $false
        try {
            $h454Next = Start-Process -FilePath $script:h454SshExe -ArgumentList $Arguments -PassThru -WindowStyle Hidden
            $null = $h454Next.Handle
            for ($h454Attempt = 0; $h454Attempt -lt 15; $h454Attempt++) {
                if ($h454Next.HasExited) { break }
                if (Test-LocalHealth) {
                    Assert-H454StartedTunnel $h454Next
                    $h454Ready = $true; break
                }
                Start-Sleep -Seconds 1
            }
        } catch { $h454Ready = $false }
        finally { if (-not $h454Ready -and $null -ne $h454Next) { Stop-H454TunnelHandle $h454Next } }
        if ($h454Ready) {
            if ($script:h454WssRetryReported) { Write-Host 'H454_WSS_TUNNEL_RESTORED' }
            $script:h454WssRetryReported = $false
            return $h454Next
        }
        if (-not $script:h454WssRetryReported) { Write-Warning 'H454_WSS_TUNNEL_RETRY' }
        $script:h454WssRetryReported = $true
        return $null
    }
"""

MONITOR = """if ($null -eq $SSH_PROCESS -or $SSH_PROCESS.HasExited) {
    $h454Previous = $SSH_PROCESS; $SSH_PROCESS = $null
    $SSH_PROCESS = Restart-H454WssTunnel $h454Previous $sshArgs
    if ($null -eq $SSH_PROCESS) { continue }
    $state.tunnelPid = $SSH_PROCESS.Id
    $state | Add-Member -MemberType NoteProperty -Name tunnelCreatedUtcTicks -Value ([long]$SSH_PROCESS.StartTime.ToUniversalTime().Ticks) -Force
    $h454StateHash = Save-H454State $h454StateHash $state
}
$h454Healthy = $false
try { Assert-H454StartedTunnel $SSH_PROCESS; $h454Healthy = Test-LocalHealth } catch {}
if (-not $h454Healthy) {
    $h454Previous = $SSH_PROCESS; $SSH_PROCESS = $null
    Stop-H454TunnelHandle $h454Previous
    continue
}"""


def prepare(source: bytes, *, source_sha256: str, ca_sha256: str, identity_sha256: str) -> bytes:
    if (not isinstance(source, bytes) or len(source) > 200_000 or
        not isinstance(source_sha256, str) or not isinstance(ca_sha256, str) or not isinstance(identity_sha256, str) or
        not re.fullmatch(r"[a-f0-9]{64}", source_sha256) or
        hashlib.sha256(source).hexdigest() != source_sha256 or
        not re.fullmatch(r"[A-Fa-f0-9]{64}", ca_sha256) or not re.fullmatch(r"[A-Fa-f0-9]{64}", identity_sha256)):
        raise AuditError("unreviewed_wss_launcher_input")
    credential_file = Path(__file__).with_name("h454_windows_secure_credential.ps1")
    if credential_file.is_symlink() or not credential_file.is_file():
        raise AuditError("unsafe_credential_source")
    credential = credential_file.read_bytes().replace(b"\r\n", b"\n")
    if hashlib.sha256(credential).hexdigest() != CREDENTIAL_SOURCE_SHA256:
        raise AuditError("unreviewed_credential_source")
    bom = source.startswith(b"\xef\xbb\xbf")
    try:
        text = source.decode("utf-8-sig")
    except UnicodeError as exc:
        raise AuditError("unreviewed_wss_launcher_source") from exc
    newline = "\r\n" if "\r\n" in text else "\n"
    text = text.replace("\r\n", "\n")
    if (text.count(ERROR_POLICY) != 1 or text.count(RUN) != 1 or text.count(GUARD) != 1 or
        text.count(LISTENER) != 3 or text.count(DEVICE) != 1 or
        text.count("Assert-H454StartedTunnel $SSH_PROCESS") < 3 or
        "Convert-H454SecureCredential" in text):
        raise AuditError("unreviewed_wss_launcher_source")
    monitor = re.compile(r"(?m)^(?P<indent> +)Assert-H454StartedTunnel \$SSH_PROCESS\n"
                         r"(?P=indent)if \(-not \(Test-LocalHealth\)\) \{ throw 'TUNNEL_HEALTH_LOST' \}$")
    cleanup = re.compile(r"(?m)^(?P<indent> +)try \{ Stop-H454PreservedContainer \} catch \{\}$")
    state_end = "    }\n    function Assert-H454ExistingTunnel {"
    state_save = "Save-H454State $h454StateHash $state"
    claim_check = "        $h454Item = Get-H454PreservedContainer\n        if ($null -eq $h454Item) {"
    loop = "while (-not $SSH_PROCESS.HasExited) {"
    claim = re.compile(r"(?m)^(?P<indent> +)Assert-H454ExistingTunnel\n"
                       r"(?P=indent)Stop-H454PreservedContainer -Claim\n"
                       r"(?P=indent)Stop-H454ExistingTunnel$")
    startup = re.compile(r"(?m)^(?P<indent> +)\$SSH_PROCESS = Start-Process -FilePath \$script:h454SshExe "
                         r"-ArgumentList \$sshArgs -PassThru -WindowStyle Hidden\n"
                         r"(?P=indent)\$null = \$SSH_PROCESS.Handle\n"
                         r"(?P=indent)\$ready=\$false\n"
                         r"(?P=indent)for \(\$i=0; \$i -lt 30; \$i\+\+\) \{\n"
                         r"(?P=indent)    if \(\$SSH_PROCESS.HasExited\) \{ throw 'SSH_TUNNEL_EXITED' \}\n"
                         r"(?P=indent)    if \(Test-LocalHealth\) \{ Assert-H454StartedTunnel \$SSH_PROCESS; \$ready=\$true; break \}\n"
                         r"(?P=indent)    Start-Sleep -Seconds 1\n(?P=indent)\}\n"
                         r"(?P=indent)Require \$ready 'SSH_TUNNEL_NOT_READY'$")
    if (len(monitor.findall(text)) != 1 or len(cleanup.findall(text)) != 1 or
        len(claim.findall(text)) != 1 or len(startup.findall(text)) != 1 or
        text.count(state_end) != 1 or text.count(state_save) != 1 or text.count(loop) != 1 or
        text.count(claim_check) != 1):
        raise AuditError("unreviewed_wss_launcher_source")
    before_start = text[:startup.search(text).start()]
    argument_blocks = list(re.finditer(r"(?ms)^(?P<indent> +)\$sshArgs = @\((?P<body>.*?)\)\n", before_start))
    if len(argument_blocks) != 1:
        raise AuditError("unreviewed_wss_ssh_arguments")
    args = argument_blocks[0]
    body = args.group("body")
    if (body.count("'-i'") != 1 or body.count("$KEY") != 1 or
        not re.search(r"'-i'\s*,[^\n]{0,80}\$KEY", body) or
        any(body.count(option) != 1 for option in ("'IdentitiesOnly=yes'", "'BatchMode=yes'",
            "'StrictHostKeyChecking=yes'", "'ExitOnForwardFailure=yes'", "$TUNNEL_TARGET", "$RELAY")) or
        "'-F'" in body or re.search(r"(?i)\b(?:identityfile|identityagent|proxycommand|proxyjump|hostkeyalias)=", body)):
        raise AuditError("unreviewed_wss_ssh_arguments")
    text = (text[:args.start()] + args.group("indent") + "$KEY = $script:h454WssIdentity\n" +
        args.group("indent") + "$sshArgs = @('-F','NUL'," + body + ")\n" + text[args.end():])
    text = claim.sub(lambda match: match.group("indent") + "Assert-H454ExistingTunnel\n" +
                     match.group("indent") + "Assert-H454WssIdentity\n" +
                     match.group("indent") + "$h454Preflight = Get-H454PreservedContainer\n" +
                     match.group("indent") + "$script:h454PreflightContainerId = if ($null -eq $h454Preflight) { $null } else { [string]$h454Preflight.Id }\n" +
                     match.group("indent") + "$script:h454PreflightWasRunning = ($null -ne $h454Preflight -and $h454Preflight.State.Running)\n" +
                     match.group("indent") + "Stop-H454ExistingTunnel", text, count=1)
    text = text.replace(claim_check, "        $h454Item = Get-H454PreservedContainer\n"
        "        if ($Claim) {\n"
        "            Require (($null -eq $h454Item -and $null -eq $script:h454PreflightContainerId) -or\n"
        "                ($null -ne $h454Item -and $h454Item.Id -ceq $script:h454PreflightContainerId)) 'H454_CONTAINER_PREFLIGHT_DRIFT'\n"
        "            if ($null -ne $h454Item) { Require (-not $h454Item.State.Running) 'H454_RUNNING_CONTAINER_CLAIM_REFUSED' }\n"
        "        }\n        if ($null -eq $h454Item) {", 1)
    text = startup.sub(lambda match: match.group("indent") + "$SSH_PROCESS = Restart-H454WssTunnel $null $sshArgs\n" +
                       match.group("indent") + "while ($null -eq $SSH_PROCESS) { $SSH_PROCESS = Restart-H454WssTunnel $null $sshArgs }\n" +
                       match.group("indent") + "Stop-H454PreservedContainer -Claim", text, count=1)
    text = text.replace(state_end, "        return $h454NewHash\n" + state_end, 1)
    text = text.replace(state_save, "$h454StateHash = " + state_save + "\n        $h454KeepContainer = $true", 1)
    text = text.replace(loop, "while ($true) {", 1)
    text = monitor.sub(lambda match: "\n".join(match.group("indent") + line for line in MONITOR.splitlines()), text, count=1)
    text = cleanup.sub(lambda match: match.group("indent") +
                       "if (-not $h454KeepContainer) { try { Stop-H454PreservedContainer } catch {} }", text, count=1)
    identities = list(re.finditer(r"(?m)^    \$script:h454TunnelNeedle = '127\.0\.0\.1:38180:[A-Za-z0-9._-]+:3000'\n", text))
    if len(identities) != 1:
        raise AuditError("unreviewed_wss_launcher_source")
    health_start = text.find("function Test-LocalHealth {\n")
    health_end = text.find("\n}\n", health_start)
    if health_start < 0 or health_end < 0 or text.count("function Test-LocalHealth {") != 1:
        raise AuditError("unreviewed_wss_launcher_source")
    original_health = text[health_start:health_end + 3]
    if "curl.exe" not in original_health or "--noproxy '*'" not in original_health or "'200'" not in original_health:
        raise AuditError("unreviewed_wss_launcher_source")
    text = text.replace(ERROR_POLICY, ERROR_POLICY + "if ($Mode -ne 'Run') { throw 'H454_OWNER_OPERATOR_REQUIRED' }\n", 1)
    text = text.replace(RUN, RUN + "    Require ($PORT -eq 38180 -and $RELAY -cmatch '^[A-Za-z0-9._-]+:3000$') 'H454_RELAY_PIN'\n"
        "    $PORT = 38184\n    $RELAY = $RELAY.Substring(0, $RELAY.Length - 4) + '3001'\n"
        "    $h454KeepContainer = $false; $script:h454WssRetryReported = $false\n" +
        IDENTITY.replace("__IDENTITY_SHA256__", identity_sha256.upper()) +
        STAGED_HELPER.replace("__VERIFY_STAGED_JS__", VERIFY_STAGED_JS) + RECONNECT, 1)
    text = re.sub(r"(?m)^    \$script:h454TunnelNeedle = '127\.0\.0\.1:38180:[A-Za-z0-9._-]+:3000'\n",
                  lambda _: '    $script:h454TunnelNeedle = "127.0.0.1:${PORT}:$RELAY"\n', text, count=1)
    text = text.replace(LISTENER, "-LocalAddress '127.0.0.1' -LocalPort $PORT -State Listen")
    text = text.replace(original_health, HEALTH.replace("__CA_SHA256__", ca_sha256.upper()) +
                        credential.decode("utf-8").replace("#requires -Version 5.1\n", "", 1), 1)
    text = text.replace(DEVICE, DEVICE + "        $credentials = Convert-H454SecureCredential $credentials $state.deviceId 'http://host.docker.internal:38180'\n", 1)
    stage_pipe = re.compile(r"(?m)^(?P<indent> +)(?P<pipe>\$credentials \| & \$script:h454Docker[^\n]*/usr/local/bin/h15-stage\.sh[^\n]*)\n"
                            r"(?P=indent)Require \(\$LASTEXITCODE -eq 0\) (?P<reason>'[^'\n]+')$")
    if len(stage_pipe.findall(text)) != 1:
        raise AuditError("unreviewed_wss_staging_source")
    text = stage_pipe.sub(lambda match: match.group("indent") + "$h454OutputEncoding = $OutputEncoding; $h454StageExit = -1\n" +
        match.group("indent") + "try {\n" + match.group("indent") + "    $OutputEncoding = [Text.UTF8Encoding]::new($false)\n" +
        match.group("indent") + "    " + match.group("pipe") + "\n" + match.group("indent") + "    $h454StageExit = $LASTEXITCODE\n" +
        match.group("indent") + "} finally { $OutputEncoding = $h454OutputEncoding }\n" +
        match.group("indent") + "Require ($h454StageExit -eq 0) " + match.group("reason"), text, count=1)
    stage_start = "        Stop-H454PreservedContainer -Claim\n"
    stage_end = "        $credentials = $null; $json = $null\n"
    decrypt_start = "        $encrypted = Get-Content -LiteralPath $CRED_PATH -Raw\n"
    decrypt_end = "        Assert-H454StartedTunnel $SSH_PROCESS\n        $h454OutputEncoding = $OutputEncoding; $h454StageExit = -1\n"
    if (text.count(stage_start) != 1 or text.count(stage_end) != 1 or
        text.count(decrypt_start) != 1 or text.count(decrypt_end) != 1):
        raise AuditError("unreviewed_wss_staging_source")
    start = text.index(stage_start)
    end = text.index(stage_end, start) + len(stage_end)
    normal = text[start:end]
    decrypt = normal[normal.index(decrypt_start):normal.index(decrypt_end)]
    indent = lambda value: "".join("    " + line if line.strip() else line for line in value.splitlines(keepends=True))
    adoption = ("        if ($script:h454PreflightWasRunning) {\n"
        "            $h454Running = Get-H454PreservedContainer\n"
        "            Require ($null -ne $h454Running -and $h454Running.Id -ceq $script:h454PreflightContainerId -and $h454Running.State.Running) 'H454_RUNNING_CONTAINER_DRIFT'\n"
        "            Assert-H454StartedTunnel $SSH_PROCESS\n"
        "            $credentials = $null; $json = $null\n"
        "            try {\n" + indent(indent(decrypt)) +
        "                Assert-H454StagedCredential $h454Running.Id $credentials\n"
        "            } finally { $credentials = $null; $json = $null; $encrypted = $null }\n"
        "            $h454Rechecked = Get-H454PreservedContainer\n"
        "            Require ($null -ne $h454Rechecked -and $h454Rechecked.Id -ceq $h454Running.Id -and $h454Rechecked.State.Running) 'H454_RUNNING_CONTAINER_DRIFT'\n"
        "            $script:h454ContainerId = [string]$h454Running.Id; $h454KeepContainer = $true\n"
        "        } else {\n" + indent(normal) + "        }\n")
    text = text[:start] + adoption + text[end:]
    result = text.replace("\n", newline).encode("utf-8")
    return (b"\xef\xbb\xbf" if bom else b"") + result
