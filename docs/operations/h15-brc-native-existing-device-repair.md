# H454 — Owner-only re-pair of the existing native Windows device

Status: **source only** until exact-main CI and deployment have passed. No running agent, token, SQLite, relay, or Docker is changed by this document.

## Why a separate operator

The prior temporary native Windows process has exited and its bearer was held only in process memory. The existing device remains owner-bound, enabled and registered as `h454-win-01335a1f6e6705b4`; `h15_brc_owner_private_pair.py` correctly rejects duplicate registrations. The pinned BRC relay's `/device/poll` issues a fresh token for a **provided existing device ID**. Its `issueDeviceToken` replaces the stored hash, invalidating the old bearer. The new helper approves only a fresh pending code for that **same** owner-bound Win32 device, without changing the existing device record or making a bearer visible on the VPS.

## Fail-closed operator gates

1. **Preconditions:** real interactive root TTY on `vps1777112993`; active release with `scripts/h15_brc_owner_private_repair.py` deployed and exact source SHA verified; existing read-only production relay image/rollback retained. Owner must explicitly approve the scoped re-pair before invoking the helper.
2. **Windows source:** previously approved dedicated nonadministrator `hermes-brc-readonly` with Win32 read-allowed/write-denied original project roots, trusted localhost SSH tunnel on `127.0.0.1:38183`, and the source-verified read-only Python adapter. New short pairing code is generated via private `POST /device/start`; never reuse an old code. Agent must poll using **exact** `device_id=h454-win-01335a1f6e6705b4`, name `H15 Windows native read-only`, platform `win32`, and never a generic BRC agent.
3. **VPS interactive only:**
   ```bash
   cd "/opt/hermes-agent-owner/releases/main-$(cat /var/lib/hermes-main-deploy/last-success.sha)"
   python3 -B -m scripts.h15_brc_owner_private_repair
   ```
   Type the fresh Windows short code only in the host TTY. Check operator prints matching device, owner and TTL. Enter exactly the prompted `APPROVE H454 REKEY <fresh-code>` phrase. Never share the code, device_code or bearer with ChatGPT/GitHub.
4. Helper reads live SQLite only **after** dropping root to `hermes-brc-relay`. Under `BEGIN IMMEDIATE` it checks exactly one owner/device/name/platform/paused/64-hex-token-hash match, an unexpired unapproved code and compare-and-set. It updates only `device_codes`. Refuse/rollback on any mismatch. No device row, existing bearer hash, token, listener, OAuth issuer or Docker change at this step.
5. Windows restricted process privately calls `POST /device/poll` with the same device_id and current device_code. The relay replaces the **same** device row's token hash, returning new bearer once. Keep bearer only in memory for a single `--single-session --tunneled-loopback` of `scripts.h15_native_windows_outbound`. No service/autostart/shell/write privileges, and never open public `/ws`.
6. **Live acceptance:** ChatGPT and Codex each perform `native_file_stat` and `native_file_read` of one real allowed original Windows README, verify size/SHA, deny traversal and vault/secret targets. Confirm original three sandbox devices still work.
7. **Credential lifecycle:** promptly revoke the new token through a separately approved owner-scoped operation. Do not silently `DELETE` the device record or mutate its token hash by ad hoc SQL. Mark revocation `NOT_VERIFIED` until independently checked.

**Important:** This helper does not start an agent, construct a token, reconfigure a tunnel, or prove E2E. If the process has already exited, do not presume a previous bearer is recoverable. No Codex CLI or paid providers.
