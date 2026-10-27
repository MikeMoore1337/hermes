# H454 — bounded owner-session recovery for original Windows read-only SSH loopback

**STATUS: source-only operator. NOT installed or enabled on the owner's PC.**
This is not an unattended service, full Desktop Commander parity, native file
authorization, or reboot recovery. The three permanent Linux/Docker sandbox
agents and their independent presence transport remain untouched.

## Why

The original Win32 native read-only bridge was repeatedly unavailable to
Codex Desktop after the **separate** local SSH forward on 127.0.0.1:38183
exited. A literal H454_READONLY_HEALTH=PASS printed after a PowerShell
exception previously created false evidence. The new guard emits PASS only
after the expected listener PID and live private relay health agree.

## Security and lifecycle

- **Fixed local path**: 127.0.0.1:38183 to 172.29.251.2:3000 via the
  existing dedicated forward-only SSH identity at port 25566; verified
  known_hosts and strict host-key checks; no password authentication,
  forwarding to additional hosts, public listener, or SSH agent forwarding.
- Run in an interactive PowerShell owned by **Mike**, using the existing
  private key. No new token, credentials, permissions, ACLs or folders.
- Inspect checks existing local listener process identity and actual relay
  HTTP 200 with known JSON fields; it does not launch or stop SSH.
- Run is deliberately owner-gated with -OwnerApproved, a default 20-minute
  maximum, two bounded reconnects, and only a child-process handle for
  cleanup. An occupied port causes refusal; no other process is killed.
- Encrypted-key SSH passphrase prompts may be required again after a
  reconnect. This is **not** unattended, silent recovery.
- Native Hermes Win32 device remains revoked (offline/paused) until a
  separate owner-authorized, private pairing and agent start are performed.
  A live SSH tunnel alone never provides original-file access.

## Operator (NOT YET INSTALLED ON THE OWNER PC)

Only after the exact reviewed source is securely staged on Windows, the
existing key ACL and verified known_hosts are confirmed, and a **new** owner
approval is granted for an interactive tunnel session, from Mike PowerShell:

~~~powershell
# Read-only, refuses and returns non-zero if no healthy pinned tunnel.
& powershell.exe -NoProfile -File 'C:\ProgramData\HermesBRC\source\scripts\h454_native_ssh_tunnel_guard.ps1' -Mode Inspect

# Limited SSH session, NOT a service/autostart. Keeps console occupied.
& powershell.exe -NoProfile -File 'C:\ProgramData\HermesBRC\source\scripts\h454_native_ssh_tunnel_guard.ps1' -Mode Run -OwnerApproved -MaxMinutes 20 -Reconnects 2
~~~

The path is **illustrative**, not proof of owner-host deployment. Do not
run this helper on the owner host until the Windows script and security
assumptions are accepted by the owner. The loopback is not equivalent to
authenticated TLS end-to-end.

To open the restricted user PowerShell for a future **separately approved**
read-only-agent session, use this command under Mike (not for the SSH key):

~~~powershell
runas.exe /user:"$env:COMPUTERNAME\hermes-brc-readonly" "powershell.exe -NoProfile -NoExit"
~~~

## Acceptance / rollback

- Local Python static-contract tests cover exact pinning, owner gate before
  filesystem access, limited budget, real health check, and own-PID cleanup.
- Windows CI checks PowerShell parser and denies Run without owner approval.
- NOT YET VERIFIED: real Windows key prompt, real PID/tunnel behavior,
  disconnect/reconnect, locked desktop, logout, reboot, credential lifecycle.
- Stop a manually approved Run with Ctrl+C, then verify only its SSH child
  terminated. Never terminate unrelated SSH processes.
- If the original Windows bridge was separately activated, stop the restricted
  agent and revoke its bearer with the existing verified owner-only VPS
  operator; verify offline, paused and native_file_* refusal.
- Roll back dormant changes by reverting their PR; none of the active
  Hermes production relay, three sandbox devices, Windows startup, OAuth or
  original-project ACLs were changed.

Future true unattended self-heal and reboot recovery require an additional
owner authorization, safe credential handling and genuine host/reboot
acceptance. Keep Hermes #454 OPEN.
