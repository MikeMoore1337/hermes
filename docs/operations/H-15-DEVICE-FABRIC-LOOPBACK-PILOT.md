# #297 — owner-approved loopback WSS pilot on Hermes VPS

Approval: owner explicitly authorized **isolated loopback-only WSS presence service** on Hermes VPS with a test identity, no public port, no remote shell/files or real Windows/Linux pairing. This runbook implements exactly that scope. Prerequisite: exact-main production release delivered; deployment alone does not enable this service.

## What is installed

- Dedicated non-login OS identity `hermes-device-fabric`, private `/var/lib/hermes-device-fabric` (0700). No root service, no Docker daemon, no H-01/Control Center modifications.
- Independent venv with pinned `websockets==16.0`, installed as the service identity. The regular system Python remains unchanged.
- 7-day **test-only** self-signed TLS certificate for localhost (never use it for public ingress), 0600 key, SQLite per-device registry (0600), separate 0600 test token. No secret is printed or checked into Git.
- systemd unit `hermes-device-fabric-pilot.service`: `127.0.0.1:38177` only; IP restrictions to loopback; CPU 25%, memory 192 MiB, 32 tasks, no new privileges, bounded restart. **No timer and no shell/process/file tools.**
- The only emulated device is `pilot-sim`: it connects for the one-shot owner smoke, sends a heartbeat and disconnects. When smoke ends it must be `offline` with nonempty last-seen. No other devices paired.

## Production activation procedure — explicit owner step

Use the approved production release SHA **actually present on the VPS** (do not guess the latest from GitHub alone). Example `cd /opt/hermes-agent-owner/releases/main-<EXACT_DEPLOYED_SHA>`.

```bash
sudo bash deploy/h15-device-fabric-pilot-setup.sh prepare
sudo bash deploy/h15-device-fabric-pilot-setup.sh enable
sudo bash deploy/h15-device-fabric-pilot-setup.sh smoke
sudo bash deploy/h15-device-fabric-pilot-setup.sh status
ss -lntp '( sport = :38177 )'
systemctl show hermes-device-fabric-pilot.service -p Result -p ExecMainStatus -p ActiveState
```

`prepare` installs only on the owner VPS and does NOT start the service. `enable` starts the service, `smoke` verifies an actual TLS connection + heartbeat + offline transition. If any operation fails, do not claim live success and review *sanitized* exit diagnostics; never post tokens, cert private keys or OAuth callbacks to Issues or chat.

Expected proof: `PILOT_PREPARED=YES`, `PILOT_SERVICE=ACTIVE`, `WSS_TLS_HANDSHAKE=PASS`, `PILOT_HEARTBEAT=PASS`, `PILOT_OFFLINE_AFTER_DISCONNECT=PASS`, `REMOTE_COMMAND_EXECUTION=NOT_IMPLEMENTED`; `ss` must show only `127.0.0.1:38177` and **must not** show a public `0.0.0.0` listener. Agent can be Offline after one-shot smoke: this is intentional.

Owner may rerun `prepare` without replacing existing cert/key/token/registry; certificate expires in seven days and needs scoped renewal for any longer pilot. The backend's code is pinned to the selected immutable release SHA; a later merge/production release does not silently restart or reconfigure it.

## Rollback

```bash
sudo bash deploy/h15-device-fabric-pilot-setup.sh rollback
sudo systemctl is-active hermes-device-fabric-pilot.service || true
ss -lntp '( sport = :38177 )'
```

Rollback stops/disables and removes the dedicated unit, retaining the private test registry/key for operator diagnostics; remove it only with separate approval. Existing #275 Desktop Commander and H-01 timers/services must remain unaffected.

## Remaining gates

- This is **not** an Internet-facing remote MCP service; no public WSS route, no ChatGPT remote connector and no Windows/VPS live agent yet.
- Read-only `DeviceStatusMCP` is an in-process adapter; there is no new Control Center UI or owner-only GET API for self-hosted devices.
- To make Windows/Linux truly available across networks (#276), request separate authorization for named devices and a narrow TLS route or VPN. Do not add broad H-01 OS/MCP tools. File reads, writes and processes require separate approval.
- #275 cloud-quota monitor continues independently; no attempt to evade or modify a commercial service's metering.

Testing: `python3 -m unittest discover -s tests -p 'test_device_fabric_pilot_contract.py' -v` and existing pinned WSS CI and quality suites. Tests assert **contract only**, not proof of a live VPS unit; the latter requires the owner-run smoke results above.
