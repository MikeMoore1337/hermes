# Hermes Commander vs Desktop Commander: evidence-based parity matrix (#454)

**Status:** baseline 2-client × 3-sandbox parity accepted on 2026-10-24; broader Desktop Commander replacement remains open. This is a record of
**observed** MCP calls, not a claim of full Desktop Commander parity.
Hermes BRC is an owner-hosted relay with sandboxed clients. The preexisting
Desktop Commander feature list is the *parity target*; its current backend
and mobile/device behavior were not re-tested in this matrix.

## Live proof legend

- **PASS:** actual named client invoked the capability on the named
  device and returned the expected result.
- **PARTIAL:** related live evidence exists but a required subcase is missing.
- **NOT TESTED:** no client/device live execution trace. CI unit/isolated
  OAuth tests do not substitute for end-user client acceptance.
- **GATED:** requires separate owner approval or an agreed maintenance
  window. Do not attempt in normal acceptance.

Evidence anchors:
[ChatGPT native workspace E2E](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6349129129),
[Codex native workspace + Git E2E](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6349223554),
[three-device ChatGPT acceptance](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6348244002),
[move/metadata tests](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6348279885)
and [isolated OAuth MCP candidate CI](https://github.com/MikeMoore1337/hermes/actions/runs/39821964343).
Production Docker cutover was approved by the owner and returned
`CUTOVER_PENDING_BOTH_CLIENTS_E2E`. Its backup and rollback image are
retained.

## Real clients × devices

| Capability | ChatGPT Windows sandbox | ChatGPT Hermes VPS sandbox | ChatGPT YFC VPS sandbox | Codex Windows sandbox | Codex Hermes VPS sandbox | Codex YFC VPS sandbox |
| --- | --- | --- | --- | --- | --- | --- |
| Paired online device discovery | PASS | PASS | PASS | PASS | PASS | PASS |
| `list_workspaces` + `resolve_workspace(YFC)` | PASS | N/A (routes to Windows) | N/A (routes to Windows) | PASS | N/A (routes to Windows) | N/A (routes to Windows) |
| Read/write/edit one ephemeral sandbox file | PASS | PASS | PASS | PASS | PASS | PASS |
| Content search against ephemeral file | PASS | PASS | PASS | PASS (targeted) | PASS | PASS |
| File move + metadata + cleanup | PASS | PASS | PASS | PASS | PASS | PASS |
| Start isolated process | PASS | PASS | PASS | PASS (Node) | PASS (Node) | PASS (Node) |
| Process output + exit code | PARTIAL | PARTIAL | PARTIAL | PASS (Node exit 0) | PASS (Node exit 0) | PASS (Node exit 0) |
| Git origin, branch, tracked status | PASS (four Windows worktrees) | N/A | N/A | PASS (all four Windows worktrees) | N/A | N/A |
| Negative host private-key read | PASS (EACCES) | PASS (EACCES) | PASS (EACCES) | NOT TESTED | NOT TESTED | NOT TESTED |
| Non-root UID / no host Docker socket | PASS | PASS | PASS | PARTIAL (shared host assurance) | PARTIAL | PARTIAL |
| Protected-path write policy | PARTIAL (platform blocked attempted call) | PARTIAL (platform blocked attempted call) | PARTIAL (platform blocked attempted call) | NOT TESTED | NOT TESTED | NOT TESTED |
| Two simultaneous interactive sessions (Node REPL) | PASS | PASS | PASS | NOT TESTED | NOT TESTED | NOT TESTED |
| Targeted process termination and no residual sessions | PASS | PASS | PASS | NOT TESTED | NOT TESTED | NOT TESTED |
| Binary 128 KiB: create, get_file_info, move, SHA-256, cleanup | PASS (process-backed bytes) | PASS (process-backed bytes) | PASS (process-backed bytes) | NOT TESTED | NOT TESTED | NOT TESTED |
| Arbitrary MCP binary read/write and larger size limits | NOT TESTED | NOT TESTED | NOT TESTED | NOT TESTED | NOT TESTED | NOT TESTED |
| Duplicate edit matching fails closed; unique edit succeeds | PASS | NOT TESTED | NOT TESTED | NOT TESTED | NOT TESTED | NOT TESTED |
| Concurrent writes, stale session replay and timeout | NOT TESTED | NOT TESTED | NOT TESTED | NOT TESTED | NOT TESTED | NOT TESTED |

**Clarifications:** the `list_workspaces` endpoint describes four **projects
on the Windows sandbox**, not four mounted host folders and not separate
workspace catalogs for the two VPS agents. Evidence that a tool was shown
in `tools/list` during CI is not sufficient to mark a live client PASS.
The Codex Git verification was initially refused by Git's `dubious
ownership` protection; using temporary
`git -c safe.directory=/workspace/projects/your-fitness-coach`
allowed read-only verification without changing persistent Git config.
`git fetch` was not run; remotes' latest HEADs remain unknown.

## Advanced post-cutover ChatGPT live evidence (2026-10-22)

These are real owner-connected Hermes MCP calls and isolated temporary files,
not CI emulation. All three devices were online for these tests.

- On each device, started **two independent** `node -i` sessions, used
  `interact_with_process` to obtain separate per-device PASS markers,
  verified two distinct active PIDs via `list_sessions`, exited both
  REPLs with `.exit` and saw `No active sessions` for each device.
- On each device, created a distinct deterministic **131,072-byte binary**
  sandbox file through `node`, verified `get_file_info` reports
  `isBinary=true` and exact size, renamed using the **MCP `move_file`
  tool**, then independently computed SHA-256 before/after the rename
  using Node and removed the fixture. Hashes remained identical, and
  all three workspaces were clean of these temporary files. This does
  **not** validate a dedicated MCP binary payload transfer protocol.
- On each device, ran a bounded synthetic Node process with an active
  event loop. Called **MCP `force_terminate`** using precisely the PID
  returned by its `start_process`; the response confirmed termination
  was initiated, and subsequent `list_sessions` reported no active
  sessions. No other processes were signalled.
- On Windows sandbox, attempted `edit_block` with one expected
  replacement where two instances of the same string existed; the tool
  rejected the edit (2 occurrences) and the full file remained
  unchanged. A **uniquely scoped** replacement succeeded; both
  resulting lines were verified, and the file was removed.
- Runtime binaries are **not uniform**: `sh` and `node` exist on
  all three devices; `git` and `python3` exist on Windows sandbox
  but are **missing** from Hermes VPS and YFC VPS sandbox containers.
  All three devices still run non-root (`UID=65534`) with no Docker
  socket. Do not infer VPS host toolchain access from a sandbox shell.

No production host access, package installation, Git modification,
Codex CLI, paid API, reload or reboot was performed in the earlier tests.
New Codex basic file/search/process E2E on both VPS sandboxes was later
**PASS on 2026-10-24**; larger binary and concurrent-write tests remain NOT TESTED.

## Remaining Desktop Commander replacement gaps

| User goal / parity dimension | Hermes status | Required next acceptance |
| --- | --- | --- |
| Project selection without memorizing `deviceId` | PASS for four allowlisted sandbox clones via native tools in both clients | Expand catalog only through separately approved onboarding |
| Original Windows filesystem / native process access | Native **READ-only** four original project roots PASS from ChatGPT and Codex, then bearer REVOKED and device PAUSED; host commands/write NOT AUTHORIZED without fresh per-operation owner approval | Never auto-enable native access or mount a whole drive/private vault |
| New-project onboarding with safe conflict handling | OPEN (#455) | Design, visual approval, backend authorization, negative E2E |
| Per-device diagnostics and actionable recovery | OPEN (#455) | Freshness, offline/auth/stale distinction; no browser RCE |
| Reboot/reconnect without another registration | OPEN (#445) | Maintenance-window Windows reboot/login evidence |
| Cross-client 2 × 3 complete functional parity | **PASS baseline** file/edit/search/move/process/isolation for both clients; extended binary, concurrency and replay NOT TESTED | Preserve advanced performance and failure-mode checks separately |
| Nonuniform sandbox toolchain | GAP (VPS agents lack Git/Python) | Decide whether these two **sandbox** targets actually need development toolchains; if yes, use pinned image, non-root security gates and separate rollout |
| Cost and isolation | Owner-hosted, no mandatory paid vendor relay | Model usage and host resource limits still apply |


## Live ChatGPT 3-device functional smoke (2026-10-24)

New *actual Hermes MCP calls* (not synthetic upstream CI) were made in ChatGPT
against three distinct existing online/unpaused sandbox devices. Every test
used an isolated temporary file under `/workspace`, outside Git repositories:

| Operation | Windows sandbox | Hermes VPS sandbox | YFC VPS sandbox |
| --- | --- | --- | --- |
| `write_file` + `read_file` exact marker | PASS | PASS | PASS |
| `edit_block` expected one replacement | PASS | PASS | PASS |
| `start_search` / `get_more_search_results` exact content | PASS | PASS | PASS |
| `move_file` / `get_file_info` / read-after-move | PASS | PASS | PASS |
| `start_process` Node isolated byte-level check | PASS | PASS | PASS |
| Temporary file deleted and `get_file_info` returns ENOENT | PASS | PASS | PASS |
| `list_sessions` after process exit: no active sessions | PASS | PASS | PASS |
| `/host-private` not mounted in sandbox (process predicate) | PASS | PASS | PASS |

The marker `needle_before_<device>` was changed uniquely to
`needle_AFTER_<device>` and found through the real content-search APIs.
The process checked the moved file before deleting precisely that single
test path. No arbitrary host paths or project worktrees were changed.
The read/write proof applies only to these **sandbox** roots; it does not
grant native Windows write/execute or VPS production privileges.

**Independent Codex 3-device baseline parity PASS on 2026-10-24.** The owner
ran actual Codex MCP calls on all three devices for write/read, unique edit,
targeted search, move/stat/read, Node process with exit 0, denied
`/host-private` listing, fixture deletion and no active process sessions.
All four Windows sandbox Git origins/branches and tracked status were verified
using per-command `-c safe.directory=<exact resolved root>`; no persistent Git
configuration changes. [Codex acceptance receipt](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6388962086).
Two broad Windows search attempts returned zero matches before a direct exact-file
search succeeded. Completed search-session metadata may remain temporarily even
when no search is running. Binary transfer, concurrent-write/replay and Windows
reboot/login recovery remain outside this accepted baseline.

### Observer compatibility after optional native Windows registration

The owner-paired original Windows read-only device can appear as an additional
fourth row in authenticated `list_devices` even after its temporary bearer
has been revoked. Existing BRC observer output is explicitly limited to
the three permanent sandbox devices and must **not** report the native
device as a fourth workspace or infer owner host permission. The observer
now validates exactly the known optional Win32 identity, refuses unknown
fourth devices and duplicate IDs, and excludes native identity/token data
from the sanitized display-only snapshot. Offline/paused native reader
must not break the ordinary three-sandbox status dashboard.
This is a backend compatibility safeguard, not a Control Center UI activation.

## Release policy

Keep [#454](https://github.com/MikeMoore1337/hermes/issues/454)
**OPEN** until the owner accepts the outstanding full-parity criteria.
No new Docker deployment, CLI authorization, broad host grant, reset,
forceful repository clean-up or unsafe fixture generation is implied by
this document.
