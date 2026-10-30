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
| Binary 128 KiB: create, get_file_info, move, SHA-256, cleanup | PASS (process-backed bytes) | PASS (process-backed bytes) | PASS (process-backed bytes) | PASS (process-backed bytes) | PASS (process-backed bytes) | PASS (process-backed bytes) |
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
**PASS on 2026-10-24**; at that time, 128 KiB binary and concurrent-write
tests were NOT TESTED.

## Codex 128 KiB binary and creation-time observation (2026-10-30)

Real Codex MCP calls on all three existing sandbox devices created a 131,072-byte
binary fixture through Node, confirmed binary type and size with `get_file_info`,
moved it with `move_file` and verified the same SHA-256 afterward. All six
test processes exited 0, the three private test directories were confirmed
absent and no terminal sessions remained. This is process-backed byte handling,
not proof of a dedicated binary MCP payload-transfer protocol. Details are in
the [Issue evidence](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6520858705).

The newly created Windows sandbox fixture reported an epoch-zero birthtime;
the two VPS fixtures reported nonzero values. Node documents that [birthtime
may be unavailable](https://nodejs.org/docs/latest-v24.x/api/fs.html#stat-time-values)
and represented by the Unix epoch or `ctime`. The source candidate now reports
the ambiguous epoch sentinel as `created: null` with
`createdStatus: unavailable_or_epoch`; other values are unchanged. This is an
intentional response change for that sentinel: consumers must accept `null`
and the additional status field. A genuine epoch-zero date is also ambiguous,
and `ctime` fallback cannot be detected reliably. At the time of this initial
observation, source and CI evidence did not establish activation on any device;
see the later Windows rollout below.

## Concurrent MCP mutation boundary (2026-10-30)

In a disposable no-network container using the current agent image, two
`edit_block` calls were held after reading the same synthetic file. Both
reported success while only one replacement remained. This is a controlled
dispatcher reproduction, not evidence of lost user data; see the [Issue
record](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6520977835).

The source candidate fails a concurrent `write_file`, `write_pdf`,
`create_directory`, `move_file` or `edit_block` call with
`HERMES_FILE_MUTATION_BUSY` while any one of those operations is in progress.
The guard covers the entire agent process, including unrelated paths; callers
must retry after the first operation completes. Reads remain available. The
guard is released on success or error, but a stuck operation keeps later
mutations blocked. It does not coordinate shell processes, native agents,
other agent processes or external writers, and it does not make reads atomic.
The regression uses a controlled read barrier and the real dispatcher; it is
not a live-device or cross-client concurrency acceptance.

## Termination result and stale session boundary (2026-10-30)

The current agent returned a `No active session` message without MCP `isError`
for a missing `force_terminate` session in an isolated container. The source
candidate marks an unsuccessful termination request as an error and says it
may have already ended or could not be terminated. Success still means only
that termination was initiated, not that exit was confirmed.

The candidate also escalates a delayed SIGKILL only while the registry still
contains the same session object, and contains a failed escalation without
crashing the dispatcher. Controlled tests use synthetic session objects, not
real processes, to check replacement, normal escalation and failure. This is
not an OS-level process-handle guarantee against PID reuse outside the agent.
At the time of this initial test, live Codex termination acceptance and runtime
rollout were not verified; see the later Windows rollout below.
See the [Issue record](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6521362507).

A later disposable test showed the tracked shell can exit while its child
continues running. The next source candidate treats a false signal result as
an error, logs an unsuccessful escalation, and warns that descendants may
remain. This does not terminate a process tree; the Windows image identified
below predates that candidate. See the [reproduction](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6522596020).

The owner-approved Windows signal window later activated image
`sha256:2d9d7b8a5db7151acf885fdac2858c6dd9d7725e04906697c3d92e534b1824cf`
and installed its pinned preserving launcher. Actual MCP smoke and a
post-commit check passed; the prior container and launcher were retained.
Task Run, login/reboot and process-tree cleanup remain unverified. See the
[window receipt](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6523646903).

The next launcher **source candidate** replaces a direct state rewrite with a
private, flushed temporary file and atomic `File.Replace`. It checks the
previous state hash before replacement, rejects unsafe ACLs/reparse points,
and preserves a backup if a post-replacement check detects drift. This uses the
existing cooperative runtime lock; it is not an OS-wide compare-and-swap
against uncooperative writers. It is not installed by source delivery.

A later launcher source candidate records the SSH process creation time with
its PID in atomic state. If that saved time differs from a currently held
process handle, the guard can leave that process untouched only after observing
no listener twice; matching or legacy state still requires the existing tunnel
identity checks. Synthetic negative cases and a real owned-process fixture do
not prove login or PID reuse across reboot. Same-user state tampering and a
listener appearing after the last check are not OS-level guarantees. If a saved
legacy PID is already occupied, this guard needs a separately approved state
migration to help that recovery. The previously prepared timing-window
launcher does not include it.

The signal image's verbose start timing retained and changed its event array
after returning: an isolated, no-network test grew it from 8 to 40 events.
The next source candidate stops recording on response and caps start/interaction
timing at 128 events with an explicit truncation notice. This is not yet a live
image rollout. On all three sandboxes a 200 ms MCP wait returned a running
process that later completed normally; that parameter does not enforce a process
lifetime limit. Stdout/stderr markers, exit code 7 and a paginated output read
were observed on each; the output is combined, not separately typed by channel.
See the [Issue evidence](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6524107978).

## Follow-up after Windows integrity rollout (2026-10-30)

The owner-approved Windows window switched device `h15-win-05be75515428` to
container `cd9e3d466bcd3adbbffbe0e641c0aaa1a8ab8fb042d33d9fac00b0a370d673cf`
and image `sha256:6c7e8eac8b3b4c527e4d6ca83b1672a538a0d1822f2e6489c6a1d3d063be9f61`.
Under `runtime.lock`, real Codex MCP checked an owned file, epoch-zero creation
metadata, conflict and unique edits, search, and an error for a deliberately
absent termination session. Independent post-checks confirmed state changed only
in imageId, the new container ran, four prior containers remained stopped, the
launcher and Task XML were unchanged, and the lock was released. The first
fixture-cleanup command failed due to test-command escaping; the corrected
cleanup exited 0. No live rollback was needed. See the [window receipt](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6521973212).

The table below records **additional** live Codex evidence. The earlier
ChatGPT baseline remains historical; ChatGPT was not retested after this
Windows image switch. `Process-backed` means a shell/Node operation, not a
dedicated binary, copy or delete MCP protocol.

| Follow-up | Windows sandbox | Hermes VPS sandbox | YFC VPS sandbox |
| --- | --- | --- | --- |
| 4 MiB binary create, MCP metadata/move, hash and cleanup | PASS, process-backed | PASS, process-backed | PASS, process-backed |
| Binary copy, exclusive no-overwrite and delete | PASS, process-backed | PASS, process-backed | PASS, process-backed |
| Two simultaneous bounded processes and isolated output | PASS | PASS | PASS |
| Two simultaneous interactive Node sessions | PASS | PASS | PASS |
| Local Git branch/commit/push/fetch/diff | PASS, local bare fixture only | Previously observed Git missing; not retested | Previously observed Git missing; not retested |
| New created-time and absent-session error contract | PASS, real MCP | NOT DELIVERED | NOT DELIVERED |

Evidence: [4 MiB](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6521476563),
[copy/delete](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6522290597),
[concurrent processes](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6521776491),
[interactive sessions](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6522467341),
[local Git push](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6521728408)
and [local Git fetch](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6522306431).
The bounded process check used Node timers; the separate interactive check used
two REPLs per device, distinct input/output markers and clean `.exit`.
The deterministic write-race barrier and session-replacement tests remained
isolated synthetic tests; shell and external writers are not serialized by the
MCP mutation guard.

The prepared container-preserving launcher was regenerated for this image after
fixing label-order-dependent profile hashes in [#687](https://github.com/MikeMoore1337/hermes/pull/687).
The profile matched in a read-only live check. The ordinary context could not
read the existing SSH command line; a separately approved limited query matched
the system OpenSSH executable, but does not prove tunnel arguments. Therefore
launcher installation, Task Run, login/reboot recovery and live rollback remain
unverified. The ChatGPT web client was reachable, but its plugin list and BRC
conversation failed to load during this attempt; no new ChatGPT PASS is claimed.

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

## Current-state recheck — 2026-10-27 (later than the historical baseline)

The October 24 table is a **historical observed PASS**, not perpetual
availability. In a new **real ChatGPT Hermes MCP** test on October 27:

| Capability | Windows sandbox | Hermes VPS sandbox | YFC VPS sandbox |
| --- | --- | --- | --- |
| Device heartbeat `online` | PASS | PASS | PASS |
| Basic `start_process` now | **FAIL — EAGAIN** | PASS | PASS |
| Ephemeral file write/read/edit/search/move | NOT RE-RUN (shell blocked) | PASS | PASS |
| Ephemeral fixture cleanup | N/A | PASS | PASS |
| Git and Python3 binaries | NOT VERIFIED NOW | NOT PRESENT | NOT PRESENT |

Windows sandbox `h15-win-05be75515428`: repeated simple
`start_process` calls returned `Failed to get process ID`; the live
`list_processes` operation reported `spawn /bin/sh EAGAIN`, while
`list_sessions` exposed one blocked session (PID 7810, runtime over
126000 seconds). This is consistent with the process/PID1 exhaustion
already investigated under #445, but no new cgroup counts or live host
configuration were collected. Do **not** treat `online` as proof of
execution readiness; do not restart or terminate unrelated processes
without a separate narrowly scoped host approval.

Hermes VPS and YFC VPS sandbox: separately created isolated
`/workspace/h454-parity-e2e-20261027-2334` fixtures, verified real
MCP file writes, reads, unique edits, content search and result pagination,
moves, metadata and read-after-move. Both basic terminals started and
both ephemeral fixture directories were removed using exact scoped commands.
Neither VPS sandbox had `git` or `python3`; Node was available.
No project repository files, host files, vault or production data were changed.

Live receipts:
[Hermes #454](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6453041813) and
[PID remediation #445](https://github.com/MikeMoore1337/hermes/issues/445#issuecomment-6453042758).

### Control-plane versus capability readiness

The gateway workspace catalog uses `device_status=online` only for an
owner-authenticated device heartbeat. Since no remote process execution is
performed by the read-only resolver, its response must explicitly carry
`process_execution_verified=false`; consumers must run a narrow authorized
`start_process` preflight before promising terminal/Git work. This boolean
does **not** assert that a host is permanently incapable: it means that
this **response** did not verify the capability. It provides neither native
Windows file rights nor a process authorization. The current production
relay may not expose this new field until a separately approved pinned
OCI candidate is deployed; a source merge is not that deployment.

At this historical checkpoint the Windows sandbox was **BLOCKED** on
runtime process-capacity remediation (#445). The later init window below
verified a short reaping scenario, not long-term capacity. Full 2-client ×
3-device **current** parity remains OPEN despite its historical baseline PASS.

## Codex Desktop live recheck — 2026-10-30 Europe/Moscow

These are actual `mcp__hermes__*` calls, not source inspection or generated
tests. Each device used a distinct marker in an initially absent test file
outside repositories. The date in the fixture filename is its session date;
these calls completed after midnight Moscow time.

| Client / device | File/edit/search/move/stat | 128 KiB binary + hash/move | Two interactive sessions | Git | Recovery |
| --- | --- | --- | --- | --- | --- |
| Codex / Windows sandbox | PASS | PASS, process-backed bytes | PASS; own MCP sessions closed; terminated child observed Z | PASS, disposable local bare remote | NOT VERIFIED |
| Codex / Hermes VPS sandbox | PASS | PASS, process-backed bytes | PASS; own MCP sessions closed; terminated child observed Z | MISSING | NOT VERIFIED |
| Codex / YFC VPS sandbox | PASS | PASS, process-backed bytes | PASS; both exited after explicit tool approval | MISSING | NOT VERIFIED |
| ChatGPT / Windows sandbox | NOT RE-RUN in this Codex session | NOT RE-RUN | NOT RE-RUN | Historical only | NOT VERIFIED |
| ChatGPT / Hermes VPS sandbox | NOT RE-RUN in this Codex session | NOT RE-RUN | NOT RE-RUN | MISSING in live Codex probe | NOT VERIFIED |
| ChatGPT / YFC VPS sandbox | NOT RE-RUN in this Codex session | NOT RE-RUN | NOT RE-RUN | MISSING in live Codex probe | NOT VERIFIED |

- Real write/read, unique edit, targeted content search plus pagination,
  rename/stat/read, process stdout and exit 0 passed on all three devices.
  `/host-private` was refused by the real metadata tool on every device.
- Duplicate-match editing left the file byte-for-byte unchanged on every
  device, but the live handler incorrectly reported `isError=false`.
  The source fix adds the error flag in the pinned no-write conflict branch;
  disposable OCI E2E must verify both refusal and the still-working unique edit.
  The source fix does not repair an existing agent image automatically.
- Deterministic 131,072-byte binary fixtures retained SHA256
  `feb1e4409d009e0ec502eaabe321f86b5197a881e9b765252ec8a75d6957596d`
  through real MCP `move_file`. Exact test files were removed, absence
  checked, and temporary Git repositories cleaned. This is not a dedicated
  binary transfer protocol or a larger-file size-limit test.
- Windows Git exercised status/diff/branch/commit, push and fetch against a
  temporary **local bare repository**. No GitHub credentials or network push
  were used. The registered Hermes clone was read at `924dbed4`; no project
  branch or tracked file was changed. Both VPS sandbox Git probes returned
  MISSING; their host development toolchains were not accessed.
- Two REPLs retained separate markers on every device. `force_terminate`
  stopped the selected Windows/Hermes session, but its child was observed
  in Linux state Z immediately afterward. MCP session removal is therefore
  not proof of kernel reaping or lasting PID capacity. YFC termination was
  refused by tool approvals; after explicit owner permission both owned
  sessions exited normally. No unrelated process was signalled. Other
  Windows client sessions appeared during the run and were preserved.

For Windows snapshot/preflight and the later delivered init evidence see
[H454 native preflight](h454-windows-native-preflight.md). Keep #454 OPEN:
login/reboot and actual rollback have not run, the native reader is
revoked/paused, Control Center onboarding remains disabled, and full GitHub
writes through MCP have no credential proof.

### Windows init delivery — later on 2026-10-30

The owner-approved maintenance window promoted container `bd4bb7c37e55`
with `--init`, both tmpfs, UID/GID 65534, PID limit 128 and 512 MiB memory.
The previous container `571a1e2bede3` is retained stopped for rollback.
The existing launcher was replaced atomically with its prepared init/lock
version; Task Scheduler XML, SSH, state and credentials were unchanged.

Real Codex MCP file/process operations and the same device identity passed
after cutover. PID1 was `docker-init`; two orphaned test children disappeared
from `/proc`, and bounded probes observed zero zombies. This proves the
tested short reaping scenario, not a long burn-in or login/reboot recovery.
Exact fixtures were removed and no active test sessions remained.

At this init-only checkpoint the image was still `8d28b0e`. The later
separately approved [derived-image activation](h454-agent-edit-image.md)
promoted `ac9f8ce0` in container `194e06ea9584`; real Codex MCP conflict-error
and unchanged-byte checks passed, then only the persistent imageId changed.
Both older containers were retained stopped for rollback. Exact-file content
search passed at that checkpoint; a directory search with exact filePattern
returned no matches. The later diagnosis and live fix are recorded below.
Login/reboot and ChatGPT acceptance remain unverified.
Initial init delivery receipt:
[#454 comment](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6515625089).

### Directory-search timeout reporting — 2026-10-30

Real Codex MCP searches found a fresh plain/hidden test file from its own
directory and found the plain filename. Searching `/workspace` for that same
plain file returned zero matches with `COMPLETED` and `isError=false`.
A direct ripgrep probe with the same arguments timed out; this is not proof
of a completed no-match scan. Exact owned fixtures were removed and sessions
stopped. Narrowing the search root is verified; a broad search is not a PASS.

The pinned source adapter now marks its deadline as an error/incomplete state,
keeps partial results, and propagates that state through both search responses.
Disposable CI exercised real child termination plus partial-result retention,
and a real ripgrep success/no-match control. The source release did not itself
update any paired agent image; the two VPS images have not been updated.

In a later separately approved Windows window, container `46e61e432c84`
on image `sha256:da3d042c75bc74ebd5d0ab0191e1123d630bd4915a8e711e12b2ae4ead002da1`
became active for the same device. Real Codex MCP returned `isError=true`
and `HERMES_SEARCH_TIMEOUT` for a bounded broad search; a narrow match and
a genuine no-match succeeded. UTF-8 file/edit, conflict with unchanged bytes,
process output/exit, UID/PID1/limits and denied host-private path also passed.
The partial-result timeout case remains disposable-test evidence only.

The lock stayed held until live acceptance; the persistent state changed only
in `imageId`, and the launcher and Task XML were unchanged. Prior containers
`194e06ea9584`, `bd4bb7c37e55` and `571a1e2bede3` remain stopped. No actual
rollback, login/reboot or current independent ChatGPT acceptance has run.
See the [actual window receipt](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6519950198).

### One independent ChatGPT acceptance pass

In the already connected ChatGPT client, ask Hermes MCP to discover the three
approved sandbox devices, resolve Hermes, then use unique temporary files
outside repositories to verify write/read/unique edit/duplicate-match refusal,
targeted search/results, rename/stat and process exit on each device. Verify
the actual file contents after each edit, including `isError` on refusal.
Remove exactly those fixtures, close only the sessions created for this pass,
and record real tool results per device. Report missing Git and unavailable
capabilities explicitly. Do not enable the native reader, read credentials,
change Docker/SSH/tasks, restart a device or claim the Codex run as ChatGPT
evidence. This is the remaining independent client acceptance, not a claim
that it has run.
