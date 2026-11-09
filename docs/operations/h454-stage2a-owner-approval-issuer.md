# H454 Stage 2A - owner-decision ticket and one-use native grant issuer

**State: DORMANT SOURCE ONLY.** No owner login, consent UI, MCP route,
WSS changes, actual host agents, secrets, OS effects or production deploy.
The code **cannot prove owner approval** without an independently
authenticated approval authority.

## Contract

The new module device_fabric/native_owner_issuer.py connects a verified
owner decision to the existing signed native-effect contract.

1. An **independent owner-authenticated service** confirms the specific
   device, project, action, relative file path (or exact command),
   operation UUIDv4, payload SHA-256, approval time and expiration. Only
   this authority may create a canonical, HMAC-SHA256 decision ticket
   with a domain-separated **authority secret**.
2. A **separate Linux issuer** verifies that ticket using its protected
   authority verification secret. It checks the configured owner, device,
   project, action, time and the exact payload digest. Any request
   boolean such as owner_approved=true is ignored/rejected.
3. The issuer atomically reserves the operation UUID in the existing
   durable SQLite replay ledger before issuing any native grant.
   Concurrent requests, retries after timeout and crashes cannot
   issue a second grant for the same UUID.
4. After reservation it checks revocation/time again and signs the exact
   effect using an **independent per-device signing key**. A successful
   signature is recorded as completed; on failure the UUID is consumed.
5. A future native agent **independently** verifies device grant,
   original project root, OS privileges, current revocation and
   its own one-time replay ledger before performing any effect.

Ticket fields are schema=h454-owner-decision-v1, owner_id, approved_at,
and nested effect. The signed native effect has the already reviewed
schema/device_id/project/operation_id/action/relative/payload_sha256/
expires_at contract. Tickets have exact canonical sorted ASCII JSON,
a separate MAC domain, strict types, no duplicate or extra fields,
and a maximum length of 4096 bytes. Decisions older than 600 seconds,
expired native effects and wrong owner/device/project/content are denied.

Only identifiers and cryptographic hashes are stored in SQLite. No
original project paths, source contents, raw approval tickets, passwords,
API keys or unredacted terminal output are recorded.

## Runtime gates that remain NOT_DONE

- The helper seal_owner_decision is only pure HMAC serialization. It
  does **not** authenticate a real owner or produce consent evidence.
  Never expose it to an LLM/MCP request or public API. Owner login,
  step-up authentication, CSRF protection, exact operation review,
  explicit approval recording and immutable audit must be separately
  implemented and physically accepted.
- The issuer is Linux-only and requires a dedicated unprivileged identity
  with a private, owned 0700 state directory. Source validation checks
  symlink ancestors and owner/mode; it does not provision OS ACLs,
  fully protect SQLite WAL/SHM from a privileged attacker or solve
  concurrent ancestor replacement. A protected hierarchy is mandatory.
- Distinct 32-128-byte HMAC authority and device keys require protected
  provisioning, rotation, revocation and independent operational QA.
  Do not commit secrets, generate host keys in CI or share them with MCP.
- Actual owner login, relay routing, original Windows/Linux host service,
  Windows native identity reactivation, device keys and end-to-end
  ChatGPT/Codex 3-host verification remain BLOCKED/NOT_RUN.
- No production deployment is authorized by merging a source-only PR.
  Preserve pinned BRC/WSS rollback artifacts and the paused Win32 device.

## Synthetic quality gate

Run:

    python3 -B -m unittest -v tests.test_h454_native_owner_issuer

Linux CI tests use synthetic secrets, disposable directories, SQLite
WAL and concurrent threads. They cover one issuance, native grant
verification, replay after restart, wrong signer/owner/device/project,
forged booleans, malformed or duplicate JSON, stale timestamps,
exact payload binding, unsafe state, revocation before and after
reservation, and absence of stored secret values.

A green CI run is **not** an actual owner consent and cannot satisfy
NATIVE_HOST_PASS on Windows/Hermes VPS/YFC VPS.

Related: Hermes Issue #454, docs/operations/h454-stage2a-native-grant-contract.md,
docs/operations/h454-native-effect-replay-ledger.md, and
docs/operations/h454-stage2a-linux-native-process.md.
