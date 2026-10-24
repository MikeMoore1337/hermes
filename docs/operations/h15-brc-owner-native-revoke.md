# H454 — завершение временной Windows native read-сессии

This runbook is an owner-only **one-off** native credential revocation; it does not finish broad Desktop Commander parity #454.

**Status:** source-only until verified main CI and production *source* deployment; no automatic production actions.

## Preconditions

- Separate ChatGPT and Codex positive/negative original Win32 native read E2E have PASS receipts.
- Owner has ended the restricted Windows native agent session (Ctrl+C in its dedicated non-admin console) and checked via `list_devices` that `h454-win-01335a1f6e6705b4` is offline. Keep SSH forwarding and unrelated sandbox agents intact.
- Active release on real VPS `vps1777112993` is verified; `scripts/h15_brc_owner_native_revoke.py` matches the approved Git blob and source CI/deploy checks.
- Owner approves exactly one operation: **pause and invalidate the previously paired native Win32 bearer hash only**, preserving this device ID, all other three sandbox devices, historical rollback containers, and relay service.
- Never print/read raw bearer, token hash, original Windows files or other credentials in the operator report.

## Operator: interactive VPS terminal

```bash
cd "/opt/hermes-agent-owner/releases/main-$(cat /var/lib/hermes-main-deploy/last-success.sha)"
python3 -B -m scripts.h15_brc_owner_native_revoke
```

After exact private owner confirmation the operator drops root to `hermes-brc-relay` before SQLite open and checks owner, device identity, old hash shape, pending pairing absence, and at least three unrelated devices. It opens a bounded transaction and atomically performs `UPDATE devices SET paused=1, token_hash=<unrecoverable random SHA256 digest>` **for the single exact device ID**. It then compares unrelated device rows before/after and commits; mismatch fails closed and rolls back. The digest is *not* a new bearer, so the old token cannot authenticate a new socket.

**Limit:** changing the stored bearer hash does not close a pre-existing WebSocket by itself. Ending the native agent process before revocation is required; additionally the relay's native tool eligibility gate rejects `paused=1`, even if a prior session lingers.

## Verification

1. `list_devices` — original 3 sandbox agents still online, native win32 row remains present, `online=false` and `paused=true`.
2. `native_file_stat(project="hermes", relative="README.md")` — refused with native_read_unavailable.
3. `native_file_read(project="hermes", relative="README.md")` — same refusal.
4. Owner-only bounded SQLite **read-only** check — one native device with `paused=1` and no pending pairing codes; do not disclose stored hash.
5. Retain shutdown, refusal and sandbox preservation receipts in #454; mark native original-folder **temporary E2E ACCEPTED AND CLOSED**, while broad #454 remains OPEN for full Desktop Commander parity, onboarding and recovery.

No Docker/restart, public WebSocket, CLI Codex, paid providers, or ad-hoc SQL mutation.
