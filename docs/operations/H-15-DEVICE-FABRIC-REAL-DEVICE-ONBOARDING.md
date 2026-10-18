# Hermes #297 / #276: owner-approved Windows and Linux device presence

**Scope:** one Windows PC + one remote Linux VPS, Online/Offline/last_seen only. No remote file/command tools, public WSS ingress, H-01 OS rights or device autostart. Current VPS relay `hermes-device-fabric-pilot.service` remains on 127.0.0.1:38177.

## Architecture

Both devices establish outbound SSH to the existing Hermes VPS port **25566** and use `ssh -N -T -L 127.0.0.1:<LOCAL>:127.0.0.1:38177`. WSS is authenticated again inside the SSH tunnel using a pinned localhost test certificate. Windows local port 38178; second Linux VPS local port 38179. No Caddy/DNS/firewall changes are required. A client never accepts commands or uploads files.

## 1. Prepare independent device bundles on owner Hermes VPS

Use the latest **verified production-delivered SHA**, set `RELEASE=/opt/hermes-agent-owner/releases/main-<EXACT_SHA>`, then:

```bash
cd "$RELEASE"
STATE=/var/lib/hermes-device-fabric
sudo systemctl is-active hermes-device-fabric-pilot.service
sudo ss -lntp '( sport = :38177 )'
sudo openssl x509 -in "$STATE/tls/cert.pem" -noout -enddate
sudo -u hermes-device-fabric env HOME="$STATE" PYTHONPATH="$PWD" "$STATE/venv/bin/python" -m device_fabric.owner_enrollment enroll --db "$STATE/devices.sqlite3" --bundle-dir "$STATE/enrollments" --ca "$STATE/tls/cert.pem" --device-id windows-pc --name 'Windows PC' --port 38178
sudo -u hermes-device-fabric env HOME="$STATE" PYTHONPATH="$PWD" "$STATE/venv/bin/python" -m device_fabric.owner_enrollment enroll --db "$STATE/devices.sqlite3" --bundle-dir "$STATE/enrollments" --ca "$STATE/tls/cert.pem" --device-id linux-vps --name 'Linux VPS' --port 38179
sudo -u hermes-device-fabric env HOME="$STATE" PYTHONPATH="$PWD" "$STATE/venv/bin/python" -m device_fabric.package_client --output "$STATE/exports/hermes-device-client.zip"
```

Bundle files `enrollments/windows-pc.json` and `enrollments/linux-vps.json` have distinct 0600 tokens plus the **public** CA certificate. Do not print their contents in chat, logs or GitHub. The portable ZIP is public Python **source only** with no credentials; it is reproducible and reports a SHA-256 digest. Enrollment refuses overwrites. The current localhost self-signed cert was valid for only **7 days** when provisioned: verify its expiry and rotate/re-distribute credentials/trust before it expires, not by disabling TLS validation.

## 2. SSH identity and restriction

The owner has already generated two separate ED25519 public keys and supplied
the authoritative **ED25519 host-key fingerprint** from Hermes VPS.
Never commit the per-device keys or any enrollment credentials to this repository.

### Owner-scoped SSH forward account (no change to SSHD configuration)

The checked-in `deploy/h15-device-fabric-ssh-forward-setup.sh` is invoked
manually on the Hermes VPS from a successfully deployed immutable release.
It accepts two public key **files** and the expected three public SHA-256
fingerprints. The fingerprints must be provided with the `SHA256:` prefix:

```bash
sudo bash deploy/h15-device-fabric-ssh-forward-setup.sh prepare \
  /root/hermes-presence-keys/windows.pub \
  /root/hermes-presence-keys/linux.pub \
  'SHA256:<VERIFIED_HERMES_ED25519_HOST_FINGERPRINT>' \
  'SHA256:<VERIFIED_WINDOWS_ED25519_KEY_FINGERPRINT>' \
  'SHA256:<VERIFIED_LINUX_ED25519_KEY_FINGERPRINT>'
sudo bash deploy/h15-device-fabric-ssh-forward-setup.sh status
```

Create the root-only input directory with `install -d -m 0700 /root/hermes-presence-keys`
and one **exactly single-line**, newline-terminated public key per file.
Do not write private keys or device JSON secrets to this directory. A wrong key,
fingerprint, SSHD preflight failure or existing account mismatch **fails closed**.
The installer creates a dedicated system account `hermes-presence-tunnel`,
with a non-interactive `/usr/sbin/nologin` shell and an invalid password hash
(key-only). Its two `authorized_keys` entries are independently restricted
by `command="/usr/sbin/nologin",restrict,port-forwarding,permitopen="127.0.0.1:38177"`.
`-N -T` requests **no SSH session**; the forced command rejects any attempted
interactive shell/remote command. SSH authentication uses each owner's distinct
private key; the device's WSS pairing token is an additional independent gate.
The account has no supplementary groups or root/sudo permissions.

The installer validates the SSH host-key fingerprint from
`/etc/ssh/ssh_host_ed25519_key.pub`, validates both device fingerprints using
`ssh-keygen -lf ... -E sha256`, checks `sshd -t`, and neither edits nor
restarts global SSHD configuration. Do not modify administrators' SSH keys,
root login, `/etc/ssh/sshd_config` or firewall settings.

**Important:** existing `AllowUsers` / `DenyUsers`, `AuthorizedKeysFile`,
`Match` blocks or `AllowTcpForwarding` restrictions may still prevent tunnel
authentication. Verify with the actual Windows/Linux key-based connection.
Never weaken a global SSHD rule to make this pilot work; a different scoped
owner-approved transport can be considered if policy blocks the account.

Rollback (disables *only* the two managed device keys; preserves the account
and the existing root/admin SSH configuration):

```bash
sudo bash deploy/h15-device-fabric-ssh-forward-setup.sh rollback
```

### Device-side host-key trust


Generate a distinct `ssh-keygen -t ed25519` key pair on *each device*. Keep the private key on that device. Install its public key using an already trusted owner shell on Hermes VPS under a **dedicated unprivileged forwarding identity**, with one authorized_keys line per device:

```text
command="/usr/sbin/nologin",restrict,port-forwarding,permitopen="127.0.0.1:38177" ssh-ed25519 AAAA... device-one
```

`restrict` disables PTY and agent/X11 forwarding; **it does not by itself forbid remote command execution**. The forced `command="/usr/sbin/nologin"` refuses SSH session commands, while `ssh -N -T` requests no session and may still use the restricted forwarding. `port-forwarding` allows only the specified destination, subject to SSHD policy. The tunnel account must not have a usable interactive shell or broad administrative permissions. Verify SSHD forwarding support for the chosen account without globally weakening SSH security. Pin the VPS server SSH host key in each device's independent `known_hosts`: never trust raw ssh-keyscan output without comparing the fingerprint to the authoritative VPS `/etc/ssh/ssh_host_ed25519_key.pub` through your existing trusted root session.

## 3. Transfer only to corresponding device

Over an owner-controlled SFTP/SCP session, copy `exports/hermes-device-client.zip` and the correct enrollment bundle to each device. Never send private files in this chat. Windows: protect its JSON using NTFS ACL so only the owner's account can read it. Linux: its JSON must be 0600 in a 0700 directory.

Windows PowerShell (Python 3 and OpenSSH Client required):

```powershell
$base = Join-Path $HOME '.hermes-device'
New-Item -ItemType Directory -Force -Path $base | Out-Null
Expand-Archive -Path "$base\hermes-device-client.zip" -DestinationPath $base
py -3 -m venv "$base\.venv"
& "$base\.venv\Scripts\python.exe" -m pip install --only-binary=:all: 'websockets==16.0'
Set-Location $base
& "$base\.venv\Scripts\python.exe" -m device_fabric.device_agent --config "$base\windows-pc.json" --once-seconds 15 --ssh-host '<HERMES_VPS_IP_OR_DNS>' --ssh-user '<TUNNEL_USER>' --ssh-key "$HOME\.ssh\hermes_presence_ed25519" --known-hosts "$HOME\.ssh\hermes_presence_known_hosts" --ssh-bin ssh.exe
```

Linux VPS (Python venv/OpenSSH client installed; client archive expanded under ~/.hermes-device):

```bash
cd "$HOME/.hermes-device"
python3 -m venv .venv
.venv/bin/python -m pip install --only-binary=:all: 'websockets==16.0'
chmod 700 "$HOME/.hermes-device" && chmod 600 linux-vps.json
.venv/bin/python -m device_fabric.device_agent --config "$HOME/.hermes-device/linux-vps.json" --once-seconds 15 --ssh-host '<HERMES_VPS_IP_OR_DNS>' --ssh-user '<TUNNEL_USER>' --ssh-key "$HOME/.ssh/hermes_presence_ed25519" --known-hosts "$HOME/.ssh/hermes_presence_known_hosts"
```

Both use a TLS-verified wss://localhost inside a reconnecting outbound SSH forward. The `--once-seconds` probe returns `DEVICE_AGENT_HEARTBEAT=PASS` **only after a confirmed welcome and heartbeat reply**. When ready to watch presence continuously, replace `--once-seconds 15` with `--watch`, keeping the process running interactively. This stage does not install Windows Task Scheduler tasks or remote Linux systemd autorun.

## 4. Owner live acceptance

While both remote agent processes run under `--watch`, on Hermes VPS:

```bash
STATE=/var/lib/hermes-device-fabric
sudo -u hermes-device-fabric env HOME="$STATE" PYTHONPATH="$RELEASE" "$STATE/venv/bin/python" -m device_fabric.owner_enrollment list --db "$STATE/devices.sqlite3"
sudo ss -lntp '( sport = :38177 )'
```

Require two **different** authenticated identities `windows-pc` and `linux-vps` Online with fresh LAST_SEEN, Offline after intentional client stop/network loss and restored Online on reconnect. `pilot-sim` is a test identity and should stay Offline. Validate that revoke blocks reconnection. For rollback, stop agent and tunnel and revoke each device with `python -m device_fabric.owner_enrollment revoke --db ... --device-id windows-pc` or `linux-vps`. Do not stop the accepted local WSS pilot or alter hosted Desktop Commander #275.

Remaining #297 gates: own Control Center read-only UI/API, persistent agent setup subject to owner approval, device-scoped operations subject to a separate explicit grant. H-01 remains without broad shell/MCP execution.
