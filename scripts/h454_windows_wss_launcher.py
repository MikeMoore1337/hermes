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


def prepare(source: bytes, *, source_sha256: str, ca_sha256: str) -> bytes:
    if (not isinstance(source, bytes) or len(source) > 200_000 or
        not isinstance(source_sha256, str) or not isinstance(ca_sha256, str) or
        not re.fullmatch(r"[a-f0-9]{64}", source_sha256) or
        hashlib.sha256(source).hexdigest() != source_sha256 or
        not re.fullmatch(r"[A-Fa-f0-9]{64}", ca_sha256)):
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
        "    $PORT = 38184\n    $RELAY = $RELAY.Substring(0, $RELAY.Length - 4) + '3001'\n", 1)
    text = re.sub(r"(?m)^    \$script:h454TunnelNeedle = '127\.0\.0\.1:38180:[A-Za-z0-9._-]+:3000'\n",
                  lambda _: '    $script:h454TunnelNeedle = "127.0.0.1:${PORT}:$RELAY"\n', text, count=1)
    text = text.replace(LISTENER, "-LocalAddress '127.0.0.1' -LocalPort $PORT -State Listen")
    text = text.replace(original_health, HEALTH.replace("__CA_SHA256__", ca_sha256.upper()) +
                        credential.decode("utf-8").replace("#requires -Version 5.1\n", "", 1), 1)
    text = text.replace(DEVICE, DEVICE + "        $credentials = Convert-H454SecureCredential $credentials $state.deviceId 'http://host.docker.internal:38180'\n", 1)
    result = text.replace("\n", newline).encode("utf-8")
    return (b"\xef\xbb\xbf" if bom else b"") + result
