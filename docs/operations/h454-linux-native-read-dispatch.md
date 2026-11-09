# H454 Stage 2A - original Linux read dispatcher (dormant)

**Status: SOURCE ONLY, NOT REGISTERED IN HERMES MCP.** This module does
not start a native agent, open a network listener, SSH tunnel, socket or
command process; it installs no service and does not read the owner's
actual Hermes VPS or YFC VPS.

The existing native Linux primitives
[`linux_native_files.py`](../../device_fabric/linux_native_files.py)
and [`linux_native_search.py`](../../device_fabric/linux_native_search.py)
now have a **single bounded, read-only dispatcher**, defined in
[`linux_native_read_dispatch.py`](../../device_fabric/linux_native_read_dispatch.py).
It is a local callable that a future **already authenticated** Hermes
device channel may use, not a second MCP server.

## Trust boundary

The caller constructing `LinuxOriginalReadDispatcher` must supply its
own exact locally configured project-to-root file-descriptor map and a
live device-revocation callback. The remote call cannot specify the
host directory, device identity, access permissions or workspace registry.
The existing authenticated Hermes MCP/relay must independently verify
the owner, device identity and pairing before it ever forwards a call.
The dispatcher is not an owner authorization issuer, OAuth client,
transport, general subprocess tool or OS sandbox.

Supported local tool names (not yet advertised by the live relay):

| Tool | Permitted operation | Source result |
| --- | --- | --- |
| `native_file_stat` | Metadata of one approved project-relative entry | File/directory kind and size |
| `native_file_read` | At most 256 KiB of allowlisted source content | Base64 bytes, SHA-256 and size |
| `native_file_list` | At most 64 safe entries from an approved directory | Relative names and kinds |
| `native_file_search` | Literal filename/content search | Relative names or line numbers, never source snippets |

All project-relative Linux accesses continue through pinned kernel
`openat2` with `RESOLVE_BENEATH`, `RESOLVE_NO_XDEV`,
`RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS`. Deny private vault,
credentials, .git, .env, symlinks, hardlinks, devices and path traversal.
Search maintains existing depth, scanned entries and aggregate-byte
limits; its content mode never transmits matching text.

## Local call contract and resource controls

One read-only call is a UTF-8 JSON object with **exact** top-level
keys `type=call`, `id`, `tool`, `args`. The arguments for
stat/read/list are exactly `project` and `relative`, while search
uses `project`, `query`, `mode`, `relative_root`.
Unknown/duplicate fields, invalid IDs, unexpected tools, malformed
UTF-8 and a client-supplied `approved` or `device_id` are denied
without forwarding or inspecting original paths.

Per transport-session ceilings: 4096-byte request frame, 64 unique
calls, 16 file reads, 4 searches; duplicate request IDs are consumed
and never retried. Every call checks live revocation **before and
after** the local operation. The result is verified against an exact
tool-specific response schema, approved relative path, source-content
SHA-256/base64/byte count and scan budgets. No absolute original
root path, private content or unredacted exception is included in a
denial. The dispatcher retains only counters and IDs in memory,
not an effect or privilege token.

The read call can return permitted source file contents. That is the
explicit owner-approved native Windows read scope, but **Linux host
roots have not been verified or separately approved**. This adapter
must remain dormant until exact Linux roots and OS service identity
are confirmed. It is not connected to any host or BRC MCP method by
this PR.

## Offline and synthetic acceptance

```sh
python3 -B -m unittest -v tests.test_h454_linux_native_read_dispatch
```

On Linux x86_64/aarch64, tests use **actual openat2** and disposable
temporary directories to exercise read/hash/stat/list/search, protected
names, outside-root symlink denial, live revocation before/after reads,
per-session limits, duplicate concurrent IDs, fake approval fields,
malformed native output/sha, no subprocess, and local-root binding.
Non-Linux runners exercise only portable request parsing. Green CI is
not a live native owner-host or ChatGPT/Codex E2E proof.

## Mandatory next integration stages

1. Owner approval for exact read-only Linux original checkout roots,
   verified host OS UID/ACL/mount namespace, and read-only native
   enrollment; no guessed Docker `/workspace/projects` paths.
2. Reviewed authentication and pairing using the **existing** Hermes
   MCP/relay/outbound device channel. Do not expose a second publicly
   reachable MCP server or enable an unauthenticated direct file API.
3. Bounded native device registration and negative host tests for
   unrelated project roots, production databases, secrets, Docker
   socket and private vault.
4. Source/build SHA, two-client x three-original-host live tests,
   reconnect and rollback, with separate owner approval for actual
   service installation and any original-host write/execute effect.

No native Windows service or existing paused Win32 bearer is changed.
No BRC/WSS pair cutover, original Linux host mutation or
production installation is authorized.

Related [Issue #454](https://github.com/MikeMoore1337/hermes/issues/454)
and [installation plan](h454-native-host-install-approval-plan.md).
