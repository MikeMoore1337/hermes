# H454 Stage 2A - native Linux read-only outbound BRC bridge

**State: SOURCE ONLY. NOT INSTALLED, NOT PAIRED, NOT REGISTERED IN MCP.**
This component is a **future** bridge from the real Linux original-host
read dispatcher to the existing authenticated Hermes BRC device WebSocket
protocol. It creates **no second MCP server, public listener, device
registration, SSH tunnel, login, service, filesystem write, or process**.

Source: `device_fabric/linux_native_outbound.py`, supplementing
[Linux original read dispatcher](h454-linux-native-read-dispatch.md)
and [approved installation gate](h454-native-host-install-approval-plan.md).

## Existing relay, NOT a presumed working native route

The wire contract intentionally reuses the existing BRC version-1
device `hello/welcome/ping/pong/call/result` messages and
`X-BRC-Protocol: 1` plus `Authorization: Bearer` headers.
Only the pinned HTTPS/TLS origin `wss://hermes.mikemoore.top/ws`
is accepted. No plaintext, arbitrary host, proxy, query token or
redirect. The connector disables compression and environment proxies.

**Important:** an older independent owner probe found the public
`/ws` route **CLOSED (404)**; the existence of this client does
not reopen it or prove that an authenticated original-host connection
will work. Existing BRC/WSS network namespace pins and fail-closed joint
cutover rules must not be changed until a separately approved plan exists.
No fallback via `ws://localhost` is provided: a bare loopback socket
cannot prove the identity of an SSH tunnel's remote peer.

The native Linux IDs are intentionally different from the existing
`linux/docker` sandbox device IDs and from the paused Win32 identity.
The future protected local enrollment must assign one
`h454-linux-hermes-<hex>` or `h454-linux-yfc-<hex>` identity
and short-lived, revocable owner-paired bearer. Regex/credential-length
checks alone do **not** authenticate the device or owner.

## Allowed tools

The only advertised names are `native_file_stat`,
`native_file_read`, `native_file_list` and
`native_file_search`. Their input schemas contain
only approved `project`/project-relative paths (or search pattern),
with `readOnlyHint=true`, `destructiveHint=false`.
There are **no** write, edit, delete, shell, Git, process, root path
or token-management tools in this bridge.

Every valid call passes to
`LinuxOriginalReadDispatcher`, which already requires:
- a protected *locally* configured project-to-original-root
  `LinuxNativeFiles` mapping, pinned to real Linux `openat2` FDs;
- device identity matching local protected enrollment;
- a live revocation callback before and after reads;
- strictly bounded individual file data/SHA-256, directory listing,
  source search and aggregate scan budgets.

Remote arguments cannot supply a host path, device identity, alternate
workspace, approval flag, shell command or OS capability. Calls have
strict duplicate-key rejection, a bounded UTF-8 JSON envelope, sanitized
refusals, and at most 16 completed call responses within a session.
The local dispatcher additionally enforces 64 total unique IDs,
16 file reads and 4 content/name searches. No automatic reconnect
or call replay occurs.

## Wire lifecycle and limitations

A session attempts one authenticated outbound TLS connection using
an injected `websockets.sync.client.connect`-compatible connector,
with `open_timeout=10`, `proxy=None`, and bounded receive
frames. The program does not import or install `websockets` at
module import time, and exposes no enabled CLI or service.

The bridge sends a read-only `hello`, requires the exact expected
`welcome` before processing a call, responds to valid pings, and
sends a BRC `result` wrapping the verified JSON source result.
Unsupported tools never reach the local OS. A valid but denied
read receives a constant sanitized refusal without host paths,
environment variables, credentials or private source material.
Malformed welcomes and fatal relay errors stop immediately.
Hard limits: 8 KiB inbound frame, 4096-byte local dispatcher request,
512 KiB outbound response, 80 receive messages, 240 seconds session
lifetime, 15-second idle receive window, 16 tool-call responses.
No background daemon/retry or persistent queue.

**This is not an authentication boundary.** The real relay must first
authenticate the owner, pair the device, verify the native tool catalog
and bind an exact host/project identity. Only the owner-approved OS
service identity with protected roots and outbound egress restrictions
may construct a real dispatcher. Serving `native_file_search`
requires a separately reviewed and installed relay tool catalog.
The current BRC deployment does **not** acquire those tools merely
because the module appears in `main`.

## Synthetic verification (NO production endpoints)

```sh
python3 -B -m unittest -v tests.test_h454_native_linux_outbound
```

Offline fixtures simulate the upstream BRC WebSocket protocol;
Linux test runners also use **actual kernel openat2** on disposable
directories for SHA-valid read/stat/list/search. Negatives cover:
pre-welcome calls, forged devices/URLs/bearers, duplicate frames,
foreign projects, credential/secret paths, symlink and traversal,
write/shell tools, caller-injected owner-approval, concurrent/replayed
IDs, revocation, session budgets, malformed replies, corrupt outputs
and absence of spawned processes. No network is contacted.

Passing fixture CI is **not** an actual owner-host WSS pairing,
original VPS filesystem access or ChatGPT/Codex 2x3 acceptance.

## Blockers and next permission gates

1. A checked, owner-approved native Linux service UID + exact original
   project directories on Hermes VPS and YFC VPS (not Docker clones),
   proven kernel ACL/mount/egress and cgroup isolation.
2. A separately authorized installation mechanism for both VPS,
   with a read-only first start and rollback; current
   `.github/workflows/production-deploy.yml` only supports
   SHA-scoped source delivery and cannot install systemd services.
3. A verified working existing BRC/WSS private transport + approved
   native-only pairing and tool advertisement; preserve the older
   relay/WSS pair and forensic snapshots. Never open an unprotected
   public shell/WebSocket endpoint to make a smoke test pass.
4. Actual owner-authenticated confirmation screen/one-use grants
   for future write/execute features; these are **not** enabled here.
5. Independent ChatGPT and Codex native original-host E2E, including
   denied sensitive paths and controlled restart/rollback, before
   Issue #454 may close.

`NATIVE_HOST_PASS=NOT_RUN`,
`PRODUCTION_NATIVE_DEPLOY=NOT_RUN`,
`OWNER_AUTH_UI=NOT_IMPLEMENTED`.
