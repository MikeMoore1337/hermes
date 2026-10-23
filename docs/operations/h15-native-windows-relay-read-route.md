# H-15 #454 — isolated read-only relay route for original Windows files

Related: https://github.com/MikeMoore1337/hermes/issues/454 and #455.
Owner-granted roots, policy: docs/operations/h15-native-windows-approval.md.

## What was implemented (candidate source only)

The disposable pinned BRC relay patcher scripts/h15_brc_native_read_gateway.py
adds two MCP tool names: native_file_read and native_file_stat. The
TypeScript template deploy/h15/hermes-native-read.template.ts is generated
into the already hardened source-pinned upstream relay after the workspace
registry patch. It is **not** activated on the production BRC relay.

- Both tools accept only the owner-approved project name and relative path;
  they do not take caller-supplied deviceId, absolute Windows paths, shell
  commands or any approval flag.
- Dispatch requires an owner-matched, online/unpaused, uniquely paired
  Windows device with exact name H15 Windows native read-only, win32
  stored/advertised platform, and exactly the two read-only tools.
- Path grammar denies traversal, UNC, ADS, credentials, private-vault
  locations, secret extensions and non-source file reads. The native
  Win32 adapter is separately responsible for final opened-handle bounds.
- The result is checked again at the relay: exact fields, project/path
  identity, canonical base64, size <=256KiB, SHA256 and 8-second deadline.
  Failures respond only with a generic denial, never a raw device error.
- Bounded per-call audit retains hashes/status, not content or secrets.
- The normal sandbox invokeTool and immutable generic tool policy remain
  unchanged. No original Windows mount, resident agent, token, listener,
  paid API, Codex CLI or local Windows command is created.

## Evidence

Offline Python tests verify exact-source preflight, patch placement,
repeat-patch denial, symlinks and fail-closed source drift. The optional
TypeScript runtime QA checks cross-owner rejection, device impersonation,
host-path denial, content integrity and foreign output fields. The
existing H15 pinned candidate CI applies this extra patch to a disposable
real upstream BRC checkout and compiles it via pnpm build. This is not
evidence of a live original-Windows connection.

## Separate owner activation gates

1. Implement a restricted native Windows outbound transport paired through
   the existing owner OAuth; do not extend the general shell-capable agent.
2. Obtain a fresh concise owner approval before Windows install/start,
   commands or mutations. Use least-privilege Windows identity and OS ACLs.
3. Validate private-vault isolation, Windows ACL and reparse negatives,
   authenticated owner routing, stale/replay denial and rollback.
4. Complete independent ChatGPT and Codex native original-file E2E. Until
   then status is NOT_CONNECTED, regardless of source build or green CI.
