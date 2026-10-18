# Hermes #276 / #297: persistent, read-only Windows + YFC VPS presence

**Scope approved by owner 2026-10-18:** after reboot, each device independently starts
its outbound restricted SSH/WSS `--watch` agent; the existing 10-minute Ops Watch
collector reports sustained connection failures and recovery via the **existing**
private Telegram delivery/outbox. No device remote commands, public WSS listener,
root SSH privileges, H-01 shell, task replay or credential rotation.

This is an explicit owner-run runtime activation after immutable source release,
**not an automatic effect of GitHub merge/CD**. A successful source deploy alone
does not prove either device's scheduled startup. Keep both registration IDs/tokens
intact; do NOT revoke. The name `linux-vps` corresponds to owner YFC VPS
`vps1789630393` and `windows-pc` to the Windows computer.

## Architecture and operational choices

| Mechanism | Selected | Why |
| --- | --- | --- |
| Linux | dedicated unprivileged systemd service, `Restart=always` (30s) | survives reboot, restarts on crash, no root agent process |
| Windows | Task Scheduler at system boot, `LocalService` account | does not depend on interactive login or storing a user password |
| Network | existing `ssh -F none -N -T -L` with pinned `known_hosts` + certificate-checked WSS | no inbound endpoint/extra relay quota |
| Connection | existing agent `--watch` with retry and SSH keepalive | no command queue or stale command replay |
| Outage detection | **independent** owner-enabled server-side registry observation in Ops Watch | client cannot reliably report its own network disconnection |
| Alerts | fixed incident codes via Ops Watch's existing SQLite outbox and Telegram sender | deduplication + recovery event, no new API token |

We do **not** use Windows S4U here: Microsoft documents its lack of network
access. We do **not** run the task as SYSTEM or require an owner's login.
`LocalService` has access only to an explicitly ACL-protected ProgramData
copy of the Python client, WSS bundle and SSH key. Administrative rights are
required only to install/remove the scheduled task. The installer copies only CPython 3.14's runtime components from the already
installed owner Python (including per-user AppData installs) into ACL-protected
ProgramData. The new venv points only to this private local runtime, **not**
to the user profile. No second/all-users Python install is necessary.

## Prerequisites - do not enable yet

- Hermes VPS: WSS service `hermes-device-fabric-pilot.service` remains active
  and bound only to `127.0.0.1:38177`, restricted SSH on port 25566.
- Both original device agent `--watch` interactive sessions are stopped
  **just before enabling** the persistent services; otherwise local ports
  38178/38179 can conflict.
- On YFC VPS as root: working `/root/.hermes-device` with `device_fabric`,
  private `linux-vps.json`, isolated `.venv` with `websockets==16.0`;
  verified separate `/root/.ssh/hermes_presence_ed25519` and
  `hermes_presence_known_hosts`.
- On Windows: the same owner-approved `$HOME\.hermes-device` for
  `windows-pc`; private SSH identity and pinned host key in `$HOME\.ssh`.
  Existing owner Python 3.14 with `venv` and `pip` installed is enough.
  No sensitive contents transferred to chat/GitHub.
- Use scripts **only from a verified GitHub Actions delivered main SHA**.
  Copy source-only install scripts over the existing trusted administrator
  channel. Review those scripts before elevated execution.

## YFC VPS (second Linux host, not the Hermes VPS)

As root, from the approved release's `deploy` files copied onto **YFC** VPS:

```bash
sudo bash deploy/h15-device-fabric-yfc-autostart.sh prepare
sudo bash deploy/h15-device-fabric-yfc-autostart.sh status
```

`prepare` validates the original client, refuses to overwrite an already
existing deployment, creates `hermes-presence-agent` (non-login, no sudo),
copies the client and its existing private config/key into
`/var/lib/hermes-presence-agent` (0700 / 0600), creates a hardened systemd
unit **without enabling it**. Owner manually confirms no extra process owns
`127.0.0.1:38179`, then:

```bash
sudo bash deploy/h15-device-fabric-yfc-autostart.sh enable
sudo systemctl show hermes-device-agent.service -p ActiveState -p Result -p UnitFileState
sudo journalctl -u hermes-device-agent.service -n 30 --no-pager
```

Do **not** execute this script on `vps1777112993` (Hermes VPS). Install
`python3.14-venv` on YFC first if required; do not use global pip or
disable TLS checks. The service starts at boot and retries a failed agent
process every 30s. Ordinary SSH/WSS drops are retried inside `--watch`.

Rollback without revoking the WSS token or SSH key:
```bash
sudo bash deploy/h15-device-fabric-yfc-autostart.sh rollback
```
It preserves the private state for audit and manual reactivation.

## Windows (elevated PowerShell)

Use the verified source-only `deploy/h15-device-fabric-windows-autostart.ps1`
copied locally over a trusted channel. Use the path to the owner's **already
installed Python 3.14**, including its per-user AppData installation. Installers may require
network access to fetch the pinned `websockets==16.0` wheel only during
`Prepare`, never from the scheduled runtime task.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\h15-device-fabric-windows-autostart.ps1 -Mode Prepare -MachinePython 'C:\Users\Mike\AppData\Local\Programs\Python\Python314\python.exe'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\h15-device-fabric-windows-autostart.ps1 -Mode Status
```

`Prepare` refuses existing installations, creates
`%ProgramData%\HermesDevicePresence`, copies the approved source, device
bundle and SSH materials, stages only the existing CPython base runtime (not
user site-packages) under a private ProgramData subtree, creates its venv from
that local runtime, validates `websockets==16.0`,
removes inherited ACLs and grants access only to SYSTEM, Administrators and
read/execute to LocalService via language-neutral SIDs. It registers a disabled
**AtStartup** task running the exact pinned binary as
`NT AUTHORITY\LOCAL SERVICE` and restarts failures up to 999 times at
two-minute intervals (the agent itself retries indefinitely while running).
It does not store a Windows password or use SYSTEM for agent execution.

### Windows interrupted Prepare recovery (PowerShell 5.1 native quotes)

The initial installer compared `websockets.__version__` to `"16.0"` through
`python -c`; PowerShell 5.1 removed the inner double quotes when invoking
a native executable, so the assertion falsely compared a string to float
`16.0` and aborted. In that old release, the private JSON and SSH key had
already been copied to ProgramData **before the ACL hardening step**.
Fix: the installer now uses a version assertion that requires no embedded
native double quotes, applies protected ACLs **before** secrets are copied,
and provides an explicit conservative `Repair` for an interrupted stage.

**If the old prepare already failed**, as owner in elevated PowerShell,
**immediately** restrict the staged private files even before installing
the repaired release:

```powershell
$state = Join-Path $env:ProgramData 'HermesDevicePresence'
if (Test-Path -LiteralPath $state) {
    & icacls.exe $state /inheritance:r `
        /grant:r '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' `
                 '*S-1-5-19:(OI)(CI)RX' /T
    if ($LASTEXITCODE -ne 0) { throw 'PRIVATE_ACL_FAILED' }
}
```

Use the corrected installer from an **immutable, verified new main SHA**,
never the first release with the quoting bug. Existing staged files are not
re-enrolled, reset or sent to GitHub. After a machine-wide Python has been
installed in `$env:ProgramFiles`, run:

```powershell
$script = Join-Path $HOME '.hermes-device\h15-device-fabric-windows-autostart.ps1'
& $script -Mode Repair -MachinePython 'C:\Users\Mike\AppData\Local\Programs\Python\Python314\python.exe'
& $script -Mode Status
```

`Repair` refuses to overwrite a registered task, rejects symlinked staging,
checks private staged config/key/host file/source hashes against the working
originals, copies only the base CPython runtime excluding user site-packages,
recreates the isolated venv pointing at that runtime, and
registers a task **disabled by default**. A mismatch requires manual review,
not `Remove-Item -Recurse` of the working source or revocation of the live
registration. A Python installed under owner AppData is supported **as a
source for the private ProgramData copy**, rather than being used directly
by LocalService at startup. Unexpected Python directories (such as Temp or
Downloads), mismatched Python versions and reparse points are refused. Never call `Enable` before `WINDOWS_PERSISTENCE=PREPARED`
and credential ACL verification.

### Windows prepared-task SSH binary migration (no re-enrollment)

The October 18 pilot prepared a disabled Windows scheduled task using an
absolute `--ssh-bin C:\\Windows\\System32\\OpenSSH\\ssh.exe` value. The
already-enrolled `device_agent.py` and `ssh_tunnel.py` explicitly accept only
`ssh` or `ssh.exe`, so enabling that task would fail before establishing SSH.

After downloading the exact reviewed installer containing `FixTask`, from
elevated PowerShell **while the task remains Disabled**:

```powershell
$script = Join-Path $HOME '.hermes-device\\h15-device-fabric-windows-autostart.ps1'
& $script -Mode FixTask
& $script -Mode Status
```

The migration checks there is exactly one task action, the known
`LOCAL SERVICE` principal, correct private ProgramData Python/working directory,
and exact old or new read-only SSH arguments. It replaces only the approved
`--ssh-bin` spelling; it does not touch the credentials, SSH host key, or
enrollment and does not enable the task. Expected result:
`WINDOWS_TASK_SSH_ARGS=FIXED` and `AUTOSTART=NOT_ENABLED`.
The `Enable` command now refuses mismatched task actions.

The literal `ssh.exe` is resolved using Windows' normal system PATH.
If the task fails to establish a tunnel as LocalService, verify OpenSSH
discovery and its local account key permissions before altering privileges.
Do not switch to SYSTEM, weaken ACLs or bypass TLS verification.

Stop the interactive `--watch` Windows process before activation, then:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\h15-device-fabric-windows-autostart.ps1 -Mode Enable
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\h15-device-fabric-windows-autostart.ps1 -Mode Status
```

Check `Get-ScheduledTask -TaskName HermesDevicePresence`,
`Get-ScheduledTaskInfo -TaskName HermesDevicePresence` and the **server**
registry. A task in `Running` state is not evidence of a successful WSS
heartbeat. Reboot and test while logged **out** (if feasible) to verify the
LocalService boot path. If the host's enterprise policy blocks LocalService
OpenSSH access, STOP and diagnose: do not switch to SYSTEM or store passwords
without a separate owner decision.

Rollback (does not delete secrets, revoke pairing or alter sshd):
```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\deploy\h15-device-fabric-windows-autostart.ps1 -Mode Rollback
```

## Ops Watch: explicit owner opt-in AFTER both boots are verified

On **Hermes VPS only**, root-owned marker enables these two exact device IDs,
not arbitrary/auto-discovered clients. Create it **once** and only after both
persistent services have produced authenticated heartbeat evidence:

```bash
python3 - <<'PY'
from datetime import datetime, timezone
import json
import os
from pathlib import Path

p = Path("/var/lib/hermes-device-fabric/ops-watch-presence.json")
if p.exists() or p.is_symlink():
    raise SystemExit("PRESENCE_OPT_IN_ALREADY_EXISTS")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
fd = os.open(p, flags, 0o600)
with os.fdopen(fd, "w", encoding="utf-8") as f:
    json.dump({"schema": 1, "devices": ["windows-pc", "linux-vps"],
               "enabled_at": datetime.now(timezone.utc).isoformat()}, f)
    f.write("\n")
print("PRESENCE_OPS_WATCH=ENABLED")
PY

sudo systemctl start hermes-ops-watch.service
sudo systemctl show hermes-ops-watch.service -p Result -p ExecMainStatus
```

No marker -> no incident for these devices. Missing or malformed registry
after enable -> `unknown`, which **cannot clear an existing incident**.
After sustained lack of fresh heartbeat, Ops Watch produces allowlisted codes:

- `device_linux_vps_unavailable`: Linux down at least **10 minutes**,
  critical.
- `device_windows_pc_unavailable`: Windows down at least **20 minutes**,
  warning.
- `device_tls_expiring`: existing 7-day pilot TLS certificate has
  **48 hours or less** remaining, warning.
- `device_tls_expired`: pilot TLS identity expired, critical.

Collection runs on the existing **10-minute** timer; Telegram delivery is on
its separate existing **10-minute** timer. The alert is **not instantaneous**:
expect delay up to roughly 20 minutes *after* the offline threshold (depending
on timer phase and queued messages). Alerting fails closed if Hermes VPS,
collector or Telegram sender is itself unavailable. Incident transitions are
stored locally for eventual delivery; this is not an independent out-of-band
monitor of Hermes VPS.

**Expected shutdowns:** server cannot distinguish Windows intentionally
powered off from an unintended link failure. Stop notifications by disabling
the owner marker via a controlled maintenance procedure (move the marker to
root-private storage and document the window); an already active incident
remains recorded until a verified Online heartbeat, rather than silently
reporting recovery. Better future change: explicit time-bounded owner
maintenance windows/availability schedule.

**TLS rotation is mandatory**: the initial 7-day pilot cert cannot provide
unattended access indefinitely. A separate coordinated CA/cert rollout must
update BOTH owner bundles and the relay before expiry while preserving
validation; never set `ssl.CERT_NONE`, disable hostname checking or widen the
public listener. The above monitoring gives early warning but does not itself
automatically rotate certificates.

## Acceptance criteria and no-overclaim

1. Both processes start automatically after Windows/YFC VPS reboot,
   without an owner session. Verify actual server-side Online heartbeat
   advancement at 20-second intervals.
2. Kill only one process; demonstrate OS service/task restarts and reconnects,
   leaving the other device Online. Do NOT revoke either production identity.
3. Block outbound SSH 25566 temporarily only by a scoped local safe test (or
   disconnect network under controlled window), restore and verify Online.
4. Keep the SSH negative acceptance from #276:
   remote shell DENIED, forbidden forwarding PASS; command execution DISABLED.
5. With marker enabled, prove one synthetic/offline test of Ops Watch's
   `new` and `resolved` outbox transitions and one actual owner-delivered
   Telegram notification without printing secret values.
6. Verify certificate-expiry alarm, rollback, source SHA and OS unit status.
7. Record actual evidence in #276, then decide closure of the child. Parent
   #297 still needs owner-only Control Center UI/API and owner-gated operations.

**Deployment rules:** CI green -> exact-head PR -> merge -> exact-main CI/CD
-> manual YFC/Windows OS installation -> real reboot/recovery/alerts acceptance.
Do not equate source deployed with persistent devices enabled.
