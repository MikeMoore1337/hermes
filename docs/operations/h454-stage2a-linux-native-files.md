# H454 Stage 2A: Linux native original-file read adapter

**Delivery state: SOURCE_ONLY. NOT INSTALLED on Hermes VPS or YFC VPS.**
This is one incremental component of [Issue #454](https://github.com/MikeMoore1337/hermes/issues/454), NOT an independently deployed MCP server.

## What is implemented

`device_fabric/linux_native_files.py` exposes a narrow read-only Python
capability bound at construction time to **one real Linux directory passed
by a trusted local owner configuration** and a single logical project name.
Nothing derives server filesystem roots from a ChatGPT message, deviceId
or guessed production path. File paths supplied to methods are strictly
validated project-relative paths using the existing shared native-effect
path checker.

File access uses **real Linux kernel** `openat2` relative to a pinned
original-root directory descriptor. Resolution requires
`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
RESOLVE_NO_XDEV`; there is **no** `realpath` or userspace fallback
if the syscall is blocked or unsupported. Original root and its parents
are checked against symlinks during startup; inode/device identity is
checked after opening. A trusted owner-protected root hierarchy and
a separately confined OS account are still prerequisites to installation.
The Linux syscall number 437 is accepted only for x86_64/aarch64; other
architectures fail closed. Only Linux is supported by this adapter.

Methods:
- `stat_file(relative)`: handle-bound metadata for regular single-link
  files/directories; rejects symlinks, devices, hard-linked aliases
  and attempts to cross the root.
- `read_file(relative)`: at most 256 KiB, source-document extensions
  only, binary-safe base64 with byte count and SHA-256, confirms file
  identity, size and timestamps after the read.
- `list_directory(relative="")`: up to 64 safe first-level entries,
  with an upper scan limit of 256; excludes private/secret names, links,
  devices, hard-linked aliases and non-source files.

No write, edit, delete, move, search, subprocess, terminal, Git, Node or
network execution is implemented. Nothing is registered in `tools/list`,
and importing this module does not grant any host permission, launch
a service, or change the existing Docker agents.

## Synthetic acceptance

```sh
python3 -B -m unittest -v tests.test_h454_linux_native_files
```

The tests actually call the Linux kernel on disposable temporary directories,
not a mock, checking positive read/stat/list, binary SHA-256, traversal,
symlink to outside and symlink in the middle, hard-linked outside file,
reserved device names, secrets, file-size and directory-scan ceilings,
restricted root configuration and closed handle behavior.
GitHub's Linux runner proves only this synthetic capability: it is **not**
the owner's Hermes VPS or YFC VPS.

## Explicit gates before connecting a real host

1. Read-only owner inspection identifies the actual canonical source-project
   directory on **each** VPS; never guess from an unrelated Docker
   `/workspace` or from historical runbooks. Production paths and
   secrets are not written into this repository.
2. Provision a separate unprivileged system account whose *OS-level*
   directory and process rights are confined. Define and review systemd
   sandbox settings (such as `ProtectSystem=strict`, `ProtectHome=true`,
   `NoNewPrivileges=true`, precise `ReadOnlyPaths`/mount namespace,
   CPU/RAM/PID limits and no Docker socket); do not treat this adapter's
   lexical checks as complete process isolation.
3. Connect the reviewed native agent via the **existing authenticated
   Hermes MCP -> relay** routing and device identity. Do not expose an
   additional unauthenticated listener. Preserve existing BRC/WSS
   rollback pins and offline/paused Win32 identity.
4. Implement server+agent operation-specific owner approval and active
   device revocation. For writes/commands, verify one-use signed grant,
   reserve it in durable anti-replay storage before any effect and test
   denial of extra paths, symlinks, mount escapes and subprocess escapes.
5. Only after separate explicit owner approval per VPS, run actual native
   tests via ChatGPT MCP against an approved benign original project file;
   compare metadata/content hash, forbidden paths, actual process UID,
   and verify both VPS retain production health and a tested rollback.

**Current receipts:** `NATIVE_HERMES_VPS=NOT_RUN`,
`NATIVE_YFC_VPS=NOT_RUN`, `HOST_INSTALLATION=NOT_RUN`,
`MCP_HOST_INTEGRATION=NOT_RUN`, `PRODUCTION_DEPLOY=NOT_RUN`.

See [source-only signed grants](h454-stage2a-native-grant-contract.md) and
[owner path/approval rules](h15-native-windows-approval.md).
