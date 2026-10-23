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
