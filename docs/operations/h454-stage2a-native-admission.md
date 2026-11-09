# H454 Stage 2A: native signed-effect admission + durable replay

**SOURCE ONLY / NO OS EFFECT / NO DEPLOY.**

This increment extends the existing Windows-only
`scripts/h15_native_effect_receipts.py` ledger with an **optional trusted
local device/project profile**. The legacy default device ID and four-project
allowlist remain unchanged; an MCP client cannot elevate them by passing an
approval flag. A future host-owned Linux service may supply its unique native
device identity and owner-verified project list through protected local
configuration, **not** from a remote request.

`device_fabric/native_effect_admission.py` combines the already reviewed
HMAC-SHA256 effect envelope with the durable SQLite ledger. It does not
issue an owner grant and executes no operations. This is the sequence:

1. Check current device revocation through a trusted, fail-closed callable.
   A callback that fails or returns non-boolean is a denial.
2. Verify HMAC, exact device, approved project, one UUIDv4 effect,
   operation, relative path, payload SHA-256, expiry up to 600 seconds.
3. Durably reserve the UUID in the protected SQLite ledger with
   `BEGIN IMMEDIATE`, full sync and no receipt pruning. Never retry an
   ambiguous effect. Wrong device/identity/scope/collision is denied.
4. Recheck revocation. If revoked while reserving, deny execution and
   **leave the committed UUID consumed**.
5. Return a metadata-only receipt. The host must independently verify the
   owner authorization, local revocation and OS rights again immediately
   **before** executing anything. The receipt alone is not permission.
6. `complete(..., success=True/False)` records an outcome; it never makes
   the UUID eligible for re-execution. A crash after reservation remains
   permanently ambiguous until a fresh exact-action owner approval.

Trusted local `LocalAdmissionConfig` requires the protected ledger
directory, per-device secret HMAC key, device ID and exact approved project
names. No new secret/key files, OAuth endpoints, HTTP listeners, MCP
methods, Win32 privilege, Linux service, host process or tool catalog
are created by this change. The old Win32 `claim` default profile remains
pinned and excludes the fifth project; **the new locally provisioned
profile can explicitly name Financial Horizon** after owner permission.

## Tests

```sh
python -B -m unittest -v tests.test_h15_native_effect_receipts
python -B -m unittest -v tests.test_h454_native_effect_admission
```

The tests use synthetic HMAC keys/payloads and temporary SQLite databases,
including 16 competing operations with one UUID, wrong device/project/key,
revocation before and after reservation, invalid scope, corrupted database,
expired signature, crash/reconnect replay, exact-byte process command digest
and the legacy pinned Win32 behavior. They run in GitHub Linux/Windows CI
and cannot establish the real host's uid/ACL or ChatGPT MCP E2E.

## Mandatory remaining gates

- A relay-side trusted owner grant issuer and review UI still must be
  implemented with owner-authenticated, exact-operation approval, audit and
  revocation. **No MCP parameter or client boolean can issue a grant.**
- State directory/ancestor and SQLite WAL/SHM files must be provisioned and
  defended by actual OS access controls; legacy ledger's path validation is
  **not equivalent to a complete OS security boundary**. The Linux agent must
  use a restricted account and a reviewed systemd sandbox.
- Native write and process handlers must perform exact path/command checks,
  local OS confinement, device revocation, resource limits and journal
  hygiene. No original directories or production services may be changed
  without scoped owner approvals.
- Runtime integration must reuse the existing authenticated Hermes MCP
  relay, retain the paired BRC/WSS recovery pins, and never reactivate
  the revoked Win32 device without owner repair.

`NATIVE_HOST_PASS=NOT_RUN` on Windows, Hermes VPS and YFC VPS.
No production SHA approval or installation is implied by a source merge.

Related [#454](https://github.com/MikeMoore1337/hermes/issues/454),
[Stage 2A grant contract](h454-stage2a-native-grant-contract.md),
[existing Windows replay ledger](h454-native-effect-replay-ledger.md).
