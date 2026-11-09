# H454 Stage 2A: native effect approval envelope (source-only)

## Delivery scope

The shared Python module `device_fabric/native_effect_grants.py` implements
**only** a strict, platform-independent signed request contract for a later
Windows/Linux native agent and the existing Hermes MCP relay. It does not
start an agent, register an MCP tool, mount a host folder, create a network
listener, execute a command, or grant OS permissions. The existing
`device_fabric` heartbeat-only pilot and the Windows
`native_file_stat/read/list` prototype stay unchanged.

`SCHEMA=h454-native-effect-v1` has exactly eight signed fields:
`schema,device_id,project,operation_id,action,relative,payload_sha256,expires_at`.
One envelope contains `effect` and `mac`, with canonical sorted-key compact
JSON encoded as ASCII, and HMAC-SHA256 over the domain-separated byte string
`hermes-native-effect-v1\\0 + canonical_effect`. A separate opaque payload
is SHA-256 checked *byte-for-byte*. Limits: envelope 4096 bytes; payload
256 KiB; grant TTL at most 600 seconds; UUIDv4 operation ID. Both the
issuer and verifier use exact field/type checks. Unknown/duplicate fields,
invalid Unicode, noncanonical relative paths, protected credential-like names,
wrong project/device, altered payload, malformed MAC, expired grants and
oversize input fail closed with a sanitized error.

The effect types are currently `file_write`, `file_edit`, `file_delete`
and `process_run`; extension to terminal sessions, move, rename, etc. needs
an explicit new contract and tests. All file paths are project-relative
forward-slash strings; commands use an empty `relative` for the approved
project root and bind their **exact canonical argv + environment/working
directory policy** in the opaque payload digest. Signing this digest by itself
does not allow arbitrary subprocess invocation.

## Mandatory runtime sequence (not implemented by this module)

1. **Existing authenticated Hermes MCP relay:** authenticate the owner and
   device, check a live device-revocation state, match the exact requested
   action/path/command to an explicit, current owner approval, and log that
   approval in trusted storage. Never accept `owner_approved=true` from MCP.
2. **Trusted issuer:** use a protected, distinct per-device HMAC key and call
   `sign_envelope` only after step 1. No arbitrary browser-to-sign endpoint.
   Key material must never be returned to a client or logged.
3. **Native host agent:** authenticate the existing outbound relay channel,
   independently check the device identity and revocations, verify the signed
   envelope with `verify_envelope`, then compare its scope to the requested
   OS operation and exact bytes. The project registry and allowed roots MUST
   be loaded from trusted local configuration, never from MCP parameters.
4. **Before side effects:** atomically reserve the UUID in a durable one-use
   replay ledger. The current `scripts/h15_native_effect_receipts.py` is
   pinned to a dormant Windows identity; it must be adapted and independently
   reviewed before use by Linux agents and the fifth Financial Horizon
   project. `ALREADY_RESERVED`, state corruption, indeterminate outcomes,
   expired/revoked authorization and failed I/O all deny execution. No
   automatic retry after reconnect, crash or reboot.
5. **OS security boundary:** use restricted Windows service ACL/token and
   no-follow Win32 file handles, or Linux unprivileged user + kernel-enforced
   directory/file access; refuse reparse points, symlinks, hardlink escape,
   traversal, bind mount escape and subprocess rights escalation. Validate
   actual file handles after resolution. Lexical path validation and HMAC
   are *not* an OS sandbox. Bound PID, CPU, RAM, time and output size.
6. **Audit:** record operation ID, device, project, decision and sanitized
   completion; do not store passwords, signed grants, file contents,
   unredacted terminal output or private root paths. For an ambiguous result,
   require a new owner approval and a new operation ID.

The protected original Windows roots remain read-only owner-approved.
A future Windows host write or even read-only native shell command requires
separate approval identifying the concrete project/path/command. Production
source delivery, relay/WSS OCI replacement, private-CA changes, Win32
reactivation and both Linux host agent installations each have independent
owner gates. Existing BRC/WSS retained recovery evidence must not be reset.

## Test evidence and limitations

Run `python -B -m unittest -v tests.test_native_effect_grants` on Linux
and Windows runners; local isolated Linux execution is not proof of native
host installation. Tests cover positive signatures, exact data binding,
cross-platform deterministic encoding, wrong device/key/project, tampering,
expiration, duplicate JSON keys, invalid path and limits.

**Not delivered by this PR:** native read/write/process handlers, owner
approval UI/issuer service, protected key provisioning, Linux durable replay
ledger, authenticated WSS routing, real-device installation and
`NATIVE_HOST_PASS` on any of the three owner hosts. The module must stay
unregistered and dormant until all these protections are implemented and
verified.

See [Issue #454](https://github.com/MikeMoore1337/hermes/issues/454),
[original Windows approval](h15-native-windows-approval.md) and
[existing replay ledger](h454-native-effect-replay-ledger.md).
