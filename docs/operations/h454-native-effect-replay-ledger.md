# H454 — durable effect receipts for future ChatGPT → native Windows writes

**Current status:** source + disposable Linux/Windows CI fixtures only. The
owner's original Windows Host remains **offline/paused**. No new native write
or process MCP tool is advertised by this change, and the existing read-only
`native_file_stat/read/list` contract is unchanged.

## Why this is needed

A Cloud/relay retry after a network failure cannot safely assume a prior
`write`, `edit` or `process_run` was never executed. A session-local
deduplication set is lost after Windows restart. A remote client must NOT
send the same effect to a revived agent and have it run twice.

`scripts/h15_native_effect_receipts.py` creates a **durable one-use ledger**
for a future authenticated Win32 host agent, using Python's stdlib SQLite:

- Only four explicitly known original-project identifiers, a pinned
  existing `win32` device ID, and four effect categories. The caller must
  provide one UUIDv4 operation ID, SHA-256 scope hash and a bounded
  expiration (no older than now, no later than 10 minutes).
- Reserve with `BEGIN IMMEDIATE`, durable WAL + `synchronous=FULL`,
  committing a receipt **before** an effect can begin. No receipt may be
  removed or automatically requeued, including after a timeout, crash
  or reboot.
- Subsequent requests with the same operation ID are `ALREADY_RESERVED`;
  a colliding request may never reuse its ID even for another project or
  command. If an effect is ambiguous, manual inspection and a **fresh
  separately approved grant** with a new ID are required.
- Records store ONLY UUID, existing device ID, project name, operation
  type, SHA-256 scope fingerprint, bounded expiration and state.
  Original file paths, args, stdout/stderr, tokens, secrets and contents
  are **not** stored.
- The state directory must be separately provisioned in protected native
  Windows storage. It cannot be a symlink/junction or an arbitrary remote
  path, and schema/locking/IO errors are denial conditions.
- Receipt storage caps at 50,000 operations, refuses additions at
  capacity and deliberately never prunes historical IDs. Replaying an
  old UUID after expiration is denied even though ledger status can
  still be read. Planned retention compaction requires its own new
  cryptographic epoch/protocol; it is **not** part of this change.

## Explicit host authorization gate — NOT IMPLEMENTED HERE

The ledger **does not authorize anything**. It is a replay-fencing
mechanism only. A future process must independently verify a signed,
owner-issued **one-operation, one-project, one-exact-path/command**
authorization from the authenticated relay, the native OS account's
ACL, the private state directory ACL, revoked grants and exact content
hashes. Calling `claim()` with a client boolean such as
`owner_approved=true` is not a privilege grant; the library intentionally
does not accept that argument.

Never expose `claim` as an MCP tool. Enforcing the database receipt is
necessary but **not sufficient** for file-write/process safety. Opening
the native Windows Host to ChatGPT for writes must wait for actual
authorized original-Windows tests, native Win32 handle-bound write
implementation, granular one-use signed authorization, and auditable
owner revocation. No public `/ws`, no generic shell, no Docker host
mount, no Codex CLI or paid AI.

## CI / acceptance evidence

```sh
python -B -m unittest -v tests.test_h15_native_effect_receipts
```

Disposable state-only CI tests prove that only one of many competing
simultaneous requests can claim one ID, old IDs stay consumed after
`completed`, `failed` and simulated crash, data secrecy,
scope collisions, invalid grants, symlink denial, malformed database
and capacity refusal. The H15 native-Windows read workflow executes
these tests on a real Win32 GitHub runner's temporary directory, but
**not on the owner's PC**. Full ChatGPT native acceptance remains
blocked until the existing `win32` device is privately re-paired
and the owner approves the exact original project operations.

Related: [Hermes #454](https://github.com/MikeMoore1337/hermes/issues/454),
[#276](https://github.com/MikeMoore1337/hermes/issues/276),
[#445](https://github.com/MikeMoore1337/hermes/issues/445).
