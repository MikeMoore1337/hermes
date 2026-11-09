# H454 Stage 2A - bounded Linux original-project search

**State:** SOURCE_ONLY, NOT installed or exposed via ChatGPT/Codex MCP.
This module does not create or authorize a host process, mount a directory,
register an MCP tool or modify any original project.

`device_fabric/linux_native_search.py` is an optional read-only adapter
using a **trusted locally pinned** `LinuxNativeFiles` root. Every
subdirectory and source-file open uses the existing Linux kernel
`openat2` confinement (`RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS |
RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV`), handle identity and restricted
source extension checks. It does **not** use filesystem paths or root IDs
supplied through an MCP tool invocation.

## Operations

- `search(query, mode="names", relative_root="")`: literal, Unicode
  NFC-normalized, case-insensitive filename search. Relative project paths
  and file/directory kind only.
- `search(query, mode="content", relative_root="")`: literal text
  search in permitted source-document extensions. Returns **relative path
  and line number only**, never matching text, credentials or raw snippets.
  Invalid UTF-8 and binary files containing NUL are skipped.
- Limits: up to 96 UTF-8 query bytes, 512 directory entries inspected,
  4 levels below the selected root, 64 results, 256 KiB per file and 2 MiB
  aggregate decoded source bytes. Entries or matches exceeding budgets
  are marked `truncated=true`; the function does not silently claim
  exhaustive coverage.
- Unknown modes, malformed input, protected names, symlink/junction-style
  redirects, hardlinks, device files, parent traversal, absolute paths
  and OS errors fail closed or are excluded from results. No arbitrary
  regular expressions, shell, subprocess, file writes, API calls or network.
- No service-configured timeouts are provided by this code. Native host
  installation additionally requires bounded systemd CPU/memory/PID/time
  and restricted OS identity/permissions before exposing it to clients.

## Test evidence

```sh
python3 -B -m unittest -v tests.test_h454_linux_native_search
```

The synthetic tests use actual Linux `openat2` on disposable temporary
directories. They check nested source search, Unicode matching, line-number
results with no content leakage, secret and symlink/hardlink exclusion,
outside-path denial, bounded scans/matches/depth, binary/oversize files,
invalid patterns, error redaction and no subprocess invocation.
**A successful GitHub Linux runner is not evidence of real owner VPS
access or three-device parity.**

## Runtime boundary

Hermes VPS and YFC VPS currently expose Docker-sandbox agents only.
Neither connects this adapter to authenticated Hermes MCP nor grants
the agent the original VPS filesystem. The actual Linux host roots
must be obtained from protected owner-verified configuration, never
guessed from `/workspace`. Do not open public host file APIs.

Before activation: reviewed device-specific OAuth/relay routing,
restricted Linux service identity, owner-approved exact read roots,
negative UID/path tests and verified rollback. No Windows original-folder
permission is implied by this source work.

Linked: [#454](https://github.com/MikeMoore1337/hermes/issues/454),
[Linux original-file reader](h454-stage2a-linux-native-files.md).
