# H-15 native Windows original-file reader — source-only prototype

Issues: [#454](https://github.com/MikeMoore1337/hermes/issues/454),
[#455](https://github.com/MikeMoore1337/hermes/issues/455).
Owner read-only decision: [native Windows access rules](h15-native-windows-approval.md).

## Functionality in this delivery

`scripts/h15_native_windows_read.py` is a **one-shot, nonresident** Python
module accepting **exactly one** of the four owner-approved public-code
projects, a relative path and `stat` or `read` as the requested operation.

- Windows-only `CreateFileW` handles; `FILE_FLAG_OPEN_REPARSE_POINT` and
  `FILE_FLAG_BACKUP_SEMANTICS` are used while validating both the original
  approved root and requested file. `GetFileInformationByHandle` rejects
  reparse points and multiply linked files. `GetFinalPathNameByHandleW`
  checks the normalized **opened** object, not just an attacker-provided path.
  Root and target handles stay open through validation; all content reads
  occur on the **same checked target handle**, with no second path open.
- Only predefined source/text extensions can be read. Hidden credential
  locations, private vaults, `.git`, virtual environment, node_modules,
  secret-type extensions, device/UNC paths, traversal and Windows named
  streams are denied. File payloads are capped at **256 KiB**, emitted in
  base64 with byte count and SHA-256. `stat` emits bounded metadata only.
- No write, delete, rename, chmod, subprocess, Git invocation, network,
  tunnel, background service, polling, browser endpoint or MCP tool.
  Directory enumeration is **not implemented**, rather than implementing
  a path-racy traversal.
- No caller-side `approved` parameter can grant a host operation. Owner
  permission covers read-only data *intent*, but actually **executing this
  module on the original Windows host still requires a separate approval
  under the agreed per-command rule**.

## Verified evidence and limits

The exact-source tests in `tests/test_h15_native_windows_read.py` use a
mock Win32 kernel32 handle layer on the already approved **Linux/Docker BRC
sandbox**. They verify fail-closed behavior for lexical path escapes,
symlinks/reparse roots and files, target redirection, hardlinks,
oversized/changing files, Win32 path namespaces, file contents and SHA-256,
consistent cleanup, and generic denials without leaking host paths.
`tests/test_native_windows_policy.py` covers the earlier four-root owner
approval contract.

**Real Windows CI evidence (synthetic only):** an isolated GitHub-hosted
`windows-2022` runner executes `tests.test_h15_native_windows_read_on_win`
with actual `CreateFileW` / `ReadFile` / `GetFinalPathNameByHandleW` against
throwaway temporary files. [Windows run 39903584684](https://github.com/MikeMoore1337/hermes/actions/runs/39903584684)
completed **SUCCESS**. This validates the Win32 handle calls on that runner,
**not access to the owner's PC**. Separately validate native-owner machine
OS identity/ACLs, junction ancestry, 8.3 aliases, concurrent renames and
Windows Defender/file-lock behavior before any installation or MCP exposure.
Do not deploy a resident read service on CI evidence alone.

The current Hermes MCP connected device remains a sandbox:
`platform=linux/docker`, not an original Windows filesystem broker.
The Owner's paths are not mounted, and `has_native_windows_access()`
continues to return `False` in the live Control Center policy. The
prototype is not accessible as an MCP tool, nor does it automatically
read any file from `D:\Pet-projects`.

## Activation gate — a *separate* concrete proposal to owner

Before any native Windows execution/installation, present:
1. Exactly which **local, owner-visible command** will be run and which
   approved repository/code paths it inspects; purpose and bounded data.
2. Whether a dedicated restricted Windows process identity and per-root
   read ACL can be configured without granting general access to
   `D:\Pet-projects` or the private Second Brain vault.
3. The authentication/transport design (e.g., local only, no public TCP
   listener), no arbitrary command tool, no browser-to-shell endpoint.
   Check OS-level restrictions and negative cases first.
4. Rollback/no-resident-service posture; host process will be off by
   default, and modifications or native command execution beyond that
   separately confirmed step remain disabled.

Use a project-specific execution approval even for a read-only host
command. This document is an implementation reference, **not consent**
to launch any Windows process.

Microsoft Win32 references:
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew
- https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-getfinalpathnamebyhandlew


## ChatGPT-first bounded discovery — native_file_list (#454)

The existing read-only **Win32 handle-bound** agent now exposes a third
operation, `native_file_list`, scoped to the **root only** of one
previously approved original source-code repository. Its arguments are
`{"project":"hermes","relative":""}` (or another one of the four
previously approved project identifiers). No deviceId, arbitrary absolute
Windows path, executable, shell, folder crawl or host-wide search is
accepted from ChatGPT. This is deliberately narrower than general
Desktop Commander directory browsing.

Win32 validation opens the approved original root with
`FILE_FLAG_OPEN_REPARSE_POINT` and without
`FILE_SHARE_DELETE` for the enumeration. Its final path must
match the expected original root exactly. Entries are discovered via
bounded `os.scandir` and **each disclosed entry** is independently
opened with Win32 `CreateFileW` and checked against its expected final
path, reparse status and hardlink count. Forbidden names, hidden
credentials, unsupported file extensions, junctions and reparse points
are never returned. At most 256 directory entries are scanned; at most
64 approved entries are disclosed, sorted case-insensitively. No file
contents, full original Windows paths, ACLs, config values or secrets
are returned. If the directory exceeds the scan bound the entire
operation refuses; result `truncated=true` indicates approved entries
exceeded the return bound.

The same exact shape is verified again at the Python MCP boundary and
the pinned TypeScript owner-bound relay: result keys and entry names are
validated, duplicate aliases rejected, and any additional field fails
closed. All three read-only tool names must match the paired `win32`
device catalog; an old two-tool native agent will **not** silently gain
a third tool through a self-reported capability.

**Critical limitations:** This is not a general recursive directory
browser. It does not include write, edit, delete, PowerShell or Git.
The original owner Windows Host remains OFFLINE/PAUSED until a
separately authorized native process bootstrap and private re-pair
are completed. A successful GitHub Windows runner fixture validates
the Win32 API against synthetic files, not real `D:\\Pet-projects`
nor ChatGPT reachability of the owner's PC. Keep #454 OPEN until
an actual owner-host `native_file_list` tool-use E2E succeeds.

Existing native host pairing/revocation and `/ws` private transport
rules remain unchanged. **Do not enable public /ws** or trust
the 3 online linux/docker sandbox agents as Windows Host proof.
