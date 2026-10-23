# H-15 #454 — native Windows original-file MCP stdio adapter (dormant)

Related: [Hermes #454](https://github.com/MikeMoore1337/hermes/issues/454), [#455](https://github.com/MikeMoore1337/hermes/issues/455).
Owner original-folder grant: [native Windows approval](h15-native-windows-approval.md).
Win32 exact-handle reader: [native Windows read prototype](h15-native-windows-read-prototype.md).

## Why a separate adapter

Existing H15 BRC Windows agent is **linux/docker** and sees *sandbox copies*
at /workspace/projects. It cannot and must not claim direct reads from the
owner's original D: drive. Giving its generic start_process, edit_file or
write_file tools ambient access to D: would violate the owner's **read-only**
grant and separate **per-command/per-mutation approval** requirement.

The source-only scripts/h15_native_windows_mcp_stdio.py is a small local
MCP stdio JSON-RPC surface around the already tested native Win32
handle-bound reader. It is a separate capability from the generic BRC
remote-shell/file agent.

## Exact contract (protocol 2025-06-18)

- MCP tools/list advertises **only** native_file_stat and native_file_read;
  both readOnlyHint=true, destructiveHint=false and openWorldHint=false.
- tools/call accepts exactly project + relative string, no arbitrary
  root, deviceId, command, shell, approval flag, URL or output path.
- Project allowlist: hermes, your-fitness-coach, ai-development-toolkit,
  second-brain. The Second Brain *parent directory* and vault are excluded.
- Native_file_stat returns limited file/directory metadata, not directory
  contents. Native_file_read returns only a specifically requested source
  file, up to 256 KiB, as base64 with size and SHA-256. Existing Win32
  open-handle checks enforce resolved path containment, reject reparse
  points, hardlink aliases, extensions and secret locations. Adapter
  verifies size and SHA-256 **before emitting the response**.
- JSON-RPC input max 4096 bytes/request, one JSON object per newline, 64
  requests/session and 16 native tool calls/session. Invalid method,
  malformed JSON, unexpected/duplicated fields and unauthenticated tools
  are refused. No shell, subprocess, file creation, git, network call,
  long-running listener, arbitrary device access or access-grant tool.
- For a refused read, MCP only returns a generic denial. Paths, raw
  Windows exception strings, secrets and content are not included in errors.

## Delivery boundaries

This is **dormant source code**, not a connected BRC tool. There is no
native Windows app installation, command execution on the owner's PC,
MCP connector registration, credential, socket, tunnel, bridge service
or change to current BRC OAuth relay. main() refuses on non-Windows,
and starts a local stdio service only with explicit --serve-stdio.
An existing native Windows MCP-capable local client could eventually use
the stdio interface **after** the owner approves its precise start command,
but the ChatGPT cloud cannot consume a local stdio process directly.

The owner demonstrated a **single original Windows host Win32 README
read PASS** on 2026-10-23 (8,403 bytes, SHA256 evidence in issue #454).
This does not prove BRC transport. No persistent OS-native connector has
been installed, and has_native_windows_access() remains False.

## Required gates before live connection

1. Agree a concrete owner-visible **native process installation/start**
   proposal with exact executable and source SHA, operation/project and
   side effects. The owner approved native read *intent*, but native
   command execution must be approved separately.
2. Establish dedicated constrained Windows identity + read-only ACLs for
   the four precise source directories, not ambient owner/admin rights.
   Confirm real ancestry, reparse/junction/8.3 aliases, caller context,
   and negative protected-vault/secret tests on the owner's host.
3. Create and independently review the **authenticated** native-host
   transport into Hermes BRC relay: device identity tied to owner OAuth;
   no generic BRC shell, no host path mounts into Docker, no browser RCE,
   no forwarding across other owners, nonce/replay and response limits.
   Do not expose stdio directly to the network or claim ChatGPT/Codex
   capability until each client's real tool-use E2E passes.
4. Before enabling, demonstrate ChatGPT and Codex each read the same
   approved original file via the new relay without ever granting
   write/execute, and prove all denied paths remain denied. Add rollback
   disabling the native channel without touching sandbox BRC.

## QA

Offline Linux BRC sandbox: targeted unittest of JSON-RPC handshake,
exact tools/list, read/stat responses, injection/duplicate fields,
permission escalation, response hash/size integrity, rate limits,
unknown RPC commands, native policy, and Win32 fake handles.
Real Windows GitHub-hosted isolated runner: the existing synthetic
Win32 test suite now adds end-to-end MCP dispatcher -> real
CreateFileW/ReadFile on **throwaway CI files**, not originals on D:.
The exact CI run IDs and PASS/FAIL should be recorded in Issue #454.

No paid AI services or Codex CLI are necessary.
