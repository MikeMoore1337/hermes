# H454 Stage 2A - signed, single-use Linux exclusive file create

**Status:** source and disposable CI fixtures only. **No native host installation,
no new MCP tools, and no production deployment.** Complements
[Linux native read adapter](h454-stage2a-linux-native-files.md) and
[signed-effect admission](h454-stage2a-native-admission.md).

## Narrow operation

`device_fabric/linux_native_create.py` implements one deliberately restricted
file-write operation: **create a previously nonexistent regular source file**.
It does not overwrite, patch, append, rename, unlink or execute commands.
The `file_write` grant currently means *exclusive new file creation* only in
this module; a future replacement/update operation requires a distinct
reviewed handler and explicit owner approval.

Inputs come from the trusted native Linux agent's existing local
`LinuxNativeFiles` project root and `NativeEffectAdmission` identity/key.
The remote caller may supply only a signed envelope and exact file bytes.
The envelope binds device, project, UUIDv4 operation ID, `file_write` action,
project-relative path, SHA-256 of bytes and a lifetime of at most 600 seconds.
It is **not** a way to mint an approval. Only an authenticated owner-side
issuer with an independently recorded one-operation consent may sign it.

1. Verify HMAC, project, action, path and exact bytes, check revocation, then
   reserve the UUID in full-synchronous SQLite before any filesystem effect.
   All replay and invalid credentials fail closed. If an operation outcome is
   uncertain, the UUID remains permanently consumed.
2. Validate the original filename and source-file extension. Resolve the
   parent via Linux `openat2` with `RESOLVE_BENEATH`,
   `RESOLVE_NO_SYMLINKS`, `RESOLVE_NO_MAGICLINKS`, `RESOLVE_NO_XDEV`.
   Check revocation again **immediately before** the kernel create.
3. Invoke `openat2` for the **entire relative file path** with the same
   kernel resolution guarantees and `O_CREAT|O_EXCL|O_NOFOLLOW`, mode
   `0600`. Refuse an existing file, symlink, hardlink alias, outside path
   or denied directory. Never create missing parents or use a userspace
   realpath fallback.
4. Write at most 256 KiB from the signed payload, `fsync` the new file,
   verify bytes and inode using open file descriptors, revalidate the
   parent's identity through the pinned root and sync its directory entry.
   Close all descriptors. Record the durable result without storing content,
   bearer, keys or absolute host paths.
5. On any error, refuse and retain the consumed reservation; partial
   files may remain intentionally. **Do not automatically unlink by name
   or replay after a crash.** The owner must inspect and separately approve
   the next concrete action. No misleading rollback success is claimed.

## Security boundaries

This code is **not an OS sandbox**. Before any real-host execution, the
owner must separately approve the actual agent process, OS account, actual
project roots, filesystem permissions, process/network limits and rollback.
The source path to an original VPS directory must be discovered from
trusted local configuration, **never guessed** from a Docker sandbox path.

A confined Linux systemd identity, protected parent directories, private
HMAC and replay state, revocation channel, authenticated existing
Hermes MCP/relay routing, and independent permission enforcement are still
missing. The code cannot eliminate every concurrent rename/write by another
privileged process; OS-level directory ownership and ACL are mandatory.
The one-use SQLite ledger is not an authorization issuer.

Do not modify live H-01/YFC services, original Windows projects, owner
tokens, paired BRC/WSS images, rollback pins or SQLite production data
as part of source-only development.

## Synthetic QA

```sh
python3 -B -m unittest -v tests.test_h454_linux_native_create
python3 -B -m unittest -v tests.test_h454_native_effect_admission
```

Linux runner tests use **real kernel openat2 and disposable temporary
directories**, including success, binary hash/mode, exclusive-create
collision, symlink and hardlink denial, path/secret denial, wrong signed
project/action/payload, revocation, concurrent UUIDs, simulated partial
write and crash before receipt completion. A passing GitHub CI is
**not** native operations on the owner's Hermes or YFC VPS.

## Acceptance still blocked

`NATIVE_HOST_PASS=NOT_RUN` for Windows PC, Hermes VPS and YFC VPS.
No owner-original paths are mounted or changed. This module will remain
dormant until separately reviewed authenticated relay registration,
owner grant issuance, service installation and real negative/positive
three-host MCP smoke tests are complete.

Related: [#454](https://github.com/MikeMoore1337/hermes/issues/454).
