# #454 — guarded binary updates for the existing Hermes BRC sandbox

## Why

Hermes BRC already supports `write_file`, `edit_block`, `move_file`,
`start_process` and file search on three sandbox devices. A normal
`write_file` does **not** provide a caller-supplied expected content hash.
Two agents writing to one path can silently overwrite each other.

`scripts/h454_guarded_sandbox_write.mjs` provides a bounded
compare-and-swap replacement for cases where stale writes must refuse.
It is a **helper invoked through the existing authenticated BRC
`start_process` tool**, not a new relay MCP endpoint, shell grant,
host mount or Windows-native file service.

## Usage by an authorized agent

All paths below exist **only in the currently selected BRC Linux/Docker
sandbox**, under its previously allowed `/workspace` root.

1. Create a separate staged payload file using existing BRC tools
   (for binary data, produce it via a bounded sandbox process).
2. Calculate SHA-256 of the current target through the existing
   sandbox process or verified file contents. For a new file, use `absent`.
3. Invoke the installed, exact-source helper with **prevalidated and
   shell-quoted absolute paths**. Example:

   ```sh
   node /workspace/commander-tools/guarded_write.mjs \
       --source /workspace/fixtures/next.json \
       --target /workspace/task-worktrees/hermes/issue454-example/config.json \
       --expect absent
   ```

4. Expect `status=created|updated` and SHA-256/size or
   `status=refused` and a bounded reason. If `stale_target`,
   re-read the target and ask for a fresh update; **never bypass
   the guard by retrying `write_file` to the target**.
5. On success, delete the stage file only when it was uniquely
   created for this task and confirmed expendable. Do not remove
   other sessions' stages, locks or worktrees.

Optional `--payload-sha <sha256>` rejects stale staged bytes.
The helper supports arbitrary binary data up to 1 MiB, via the already
allowed local sandbox file path. It logs **hashes and lengths only**,
not file contents.

## Behavior and guarantees

- Independent process calls targeting the same path serialize on an
  exclusive, deterministic per-target lock under the current sandbox
  UID's `/tmp` directory; permission is 0700 and no other project
  path becomes writable. The lock is fail-closed: it is not stolen
  if a process crashes.
- Existing file updates require exact SHA-256 match; new files
  require `--expect absent`. No unconditional overwrite.
- Temporary replacement is created with exclusive create in the same
  directory, fsynced, then renamed. The existing target is unchanged
  after ordinary validation failures. Preserve old mode when updating.
- Symlink components, hardlinks, directories, nested `.git`,
  `.ssh`, `secrets`, `private-vault`, environment files and
  paths outside the sandbox root are rejected.
- Refuses malformed preconditions and inputs over 1 MiB; never
  launches any new interpreter, model, Docker/host shell or network
  request. No JWT, OAuth secret, paid API, credential discovery,
  configuration mutation or production VPS access.

**Limits:** This is only compare-and-swap among callers that use
the same helper/lock. Standard BRC `write_file` or other
uncooperative writers do not participate in the lock protocol.
The final hash recheck narrows their race window but cannot provide
a portable kernel-level atomic conditional rename. It is **not**
a full secure file broker against another malicious same-UID process.
No preexisting directory or path may be authorized solely through
this helper; OS/container boundary remains authoritative.

On Windows-backed sandbox mounts, `/tmp` is used for locks rather
than depending on emulated chmod on the NTFS bind. File metadata and
atomic rename semantics still require device-level verification.

## QA and deployment

The default GitHub quality workflow runs the offline Node test suite
for binary bytes, exact 1 MiB size limit, stale hash, absent-file
collision, symlink/hardlink/path protection, wrong payload hash,
concurrent updates and readback/cleanup:

```sh
node --test tests/h454_guarded_sandbox_write.test.mjs
```

This tests a disposable Linux filesystem on GitHub Actions; it does
**not** itself prove the owner Windows NTFS mount or VPS sandbox runtime.

Each connected device can receive the identical, immutable
SHA-verified JS module under
`/workspace/commander-tools/guarded_write.mjs` through its existing
BRC `write_file` or an approved pinned GitHub source retrieval.
**Never replace an existing differing file automatically.**
After installation, perform a real MCP write/guarded-update/read
with a disposable path and clean only that fixture.

There is no new resident service, privilege escalation, web UI,
Windows host access, model call or Codex CLI.
