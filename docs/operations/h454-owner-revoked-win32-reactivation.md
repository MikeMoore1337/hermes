# H454 — re-activate a *revoked and paused* native Win32 device

This operator is **not** the existing `h15_brc_owner_private_repair.py`.
The original helper correctly refuses devices in `paused=1`. A prior,
explicit owner-approved revocation completed in #454 and changed the native
device to `paused=1`, replacing its bearer hash with a dead random digest.
Therefore trying the original helper without this deliberate reactivation
gate is guaranteed to fail. Never patch out its safety checks.

`scripts/h15_brc_owner_native_reactivate.py` is a separately approved
owner-only operator. The source and test release do not automatically
unpause any device.

## Scope

- The EXACT existing `win32` device
  `h454-win-01335a1f6e6705b4` named
  `H15 Windows native read-only`, owned by `admin`.
- Must start `paused=1` with 64-character revoked token hash and
  exactly one unique owner-bound device row.
- Must have a NEW unexpired pending pairing `device_code` from the
  restricted Windows owner-agent through previously verified private
  SSH loopback `127.0.0.1:38183`. No other active native pairing code.
- Before transaction, real root TTY on EXACT `vps1777112993`.
  Drop privileges to `hermes-brc-relay` before opening the live SQLite WAL.
  Under `BEGIN IMMEDIATE` with compare-and-set, approve precisely that
  fresh code for the *existing device ID* and simultaneously set that
  device to `paused=0` with a new RANDOM **dead-end** token hash.
  This is not a bearer. Old bearer NEVER becomes valid.
- Only the existing `/device/poll` authenticated relay logic may
  subsequently mint a fresh bearer, directly to the restricted owner
  Windows process, once. No token in argv, terminal output, disk,
  GitHub or ChatGPT.
- All three sandbox records are compared before and after and must be
  unchanged. No device duplication/deletion, other owner, SSHD config,
  other relays, public `/ws`, OS ACL, startup or project data changes.
- Abort/rollback if any identity, pending code, TTL, hash shape, owner,
  uniqueness or device baseline check fails. Never retry the same code.

## Operator instructions (only AFTER Windows pending code and owner consent)

On the real VPS in a ROOT interactive terminal, after verifying current
release/source and the owner-visible operation:

```bash
cd "/opt/hermes-agent-owner/releases/main-$(cat /var/lib/hermes-main-deploy/last-success.sha)"
python3 -B -m scripts.h15_brc_owner_native_reactivate
```

Type the fresh short code PRIVATELY into the VPS terminal, then the
literal requested confirmation `REACTIVATE H454 <code>`.
Never paste any code/token into a chat, ticket or CI log. On success,
the only expected outcome is `H454_NATIVE_REACTIVATION=PASS` and
`WINDOWS_PRIVATE_POLL=READY`. The Windows process completes the
existing `/device/poll`, stores the new bearer in process memory and
connects via the already authenticated private forward with only three
native READ tools. The old `native_file_stat/read` ChatGPT path should
then be accepted only for four approved original Windows project roots.

## Required negative and shutdown checks

- ChatGPT Hermes Agent, NOT a Docker sandbox: original
  `native_file_stat(hermes,README.md)` and `native_file_read`,
  verify actual original-size and SHA256.
- While the same Windows session is online, deny `..\\`, `.env`,
  `.git`, private vault and impersonated project owner.
- Ensure other three sandbox devices still online, native tool catalog
  contains only the expected read-only tools.
- End the native Windows agent with Ctrl+C and confirm offline; revoke
  the NEW bearer again via the existing owner-only
  `scripts/h15_brc_owner_native_revoke.py` with separate explicit
  owner confirmation; verify `paused=true` and read unavailable.
- Keep parent #454 OPEN until native ChatGPT parity and authenticated
  Windows process/file mutations are independently implemented,
  tested and authorized.

No Codex CLI, no extra paid APIs, no original Windows filesystem edits.

A green CI of the synthetic temporary SQLite fixtures does NOT prove
the original Windows host is paired, the new bearer was revoked or
the private relay allows it.
