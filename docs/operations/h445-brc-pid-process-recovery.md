# H-15 #445 — PID1/process capacity preflight for Windows BRC sandbox

## Observed production-independent reality — 2026-10-26

The **existing** BRC device called `H15 Windows permanent sandbox`
(`h15-win-05be75515428`) is a **Linux/Docker container on Windows**,
not original Windows host process access. Three BRC sandbox devices
remain online, but Online is not proof that a `start_process` can launch.

Actual read-only Hermes MCP sample:
- cgroup v2 `pids.current=96`, `pids.max=96`, then after
  identifying/terminating **only our own** abandoned synthetic Node test
  `pids.current=90`, `pids.max=96`.
- `pids.events=max 25` (historical cumulative failures). After synthetic
  test/diagnostics `max 29`.
- 23–24 zombie `esbuild`/`git`/Node children with `PPid=1`;
  the PID1 process did not reap them. Another still-live process tree
  contained an `esbuild` process with ~42 threads.
- `memory.max=512 MiB`, actual memory consumption ~187 MiB;
  `/tmp` now 64 MiB with ~46 MiB free. Prior #483 tmpfs
  pressure was distinct and should not be confused with this new
  **PID process lifecycle** failure.
- Node normally aborted on `uv_thread_create` assertion / fork
  failure even though the MCP device was online. No host reboot,
  broad kill, Docker restart, PID budget increase or unsafe cleanup.

A previous synthetic BRC test started `node -e ...setInterval(...)`:
`force_terminate` of the tracked **outer shell PID** did **not**
terminate its now-adopted child. Confirmed the exact abandoned
`/proc/<pid>/cmdline`, original test signature, owner UID and PPid=1,
then terminated **that synthetic PID only** using Linux pidfd.
It became a zombie owned by PID1. This strongly implicates two
independent defects: process-tree termination AND PID1 reaping.

## Immediate safe operating mode

`scripts/h15_brc_process_preflight.py` is a **read-only diagnostic**.
It reads cgroup PID/memory limits, `/tmp` free bytes and
`/proc/<pid>/status` fields `State`/`PPid`. It **does not**
read arguments, credentials, environment, or arbitrary file contents;
does not enumerate project files; does not launch tools or mutate
processes. Exit 2 + `status=HOLD` whenever:
- fewer than 24 pids/threads of headroom;
- any unreaped zombie belonging to PID1;
- fewer than 8 MiB in `/tmp`;
- less than 64 MiB of memory headroom;
- malformed/unavailable cgroup or unreadable process evidence.

Healthy snapshot is only `CAPACITY_OBSERVED_NOT_AUTHORIZED`;
the preflight does not grant new execution or prove Docker config.
Readings are racy and can change immediately.

For the **single-use, fixed command** Node test already approved
within the existing sandbox, a lower footprint was confirmed
independently in *real Hermes MCP*:

```sh
UV_THREADPOOL_SIZE=1 exec node --v8-pool-size=1 -e 'console.log("bounded-ok")'
```

A 128 KiB binary `guarded_write.mjs` file create/readback SHA-256 and
repeat stale-write denial also PASS using this process shape. Critically,
`exec` replaces the shell for a **single executable**, so
`force_terminate` targets that executable rather than leaving
a separate shell child; this is a recommended *mitigation*, **not**
proof that every BRC tool/child process is killed as a tree.

Do **not** use the reduced thread option as justification for
parallel builds, background Node/Go/esbuild workers, long tests,
VPS host actions, changing PID limits or avoiding a proper repair.
Pending host recovery, give other active owner tasks precedence.

## Actual Windows Docker host repair — separate scoped owner gate

The existing sandbox cannot repair its own PID1 semantics:
it has UID 65534, no Docker socket/host mount/admin shell,
and must not acquire any of those for self-repair.

1. On the original authorized Windows Docker host, verify exact
   existing container ID/image and launch mechanism (existing
   Task Scheduler/Compose/Docker run). Inspect **locally**
   whether `HostConfig.Init` is true and whether PID1 reaps children.
   Never paste `docker inspect` environment/credentials publicly.
   Verify the original `pids.max` is 96 and current 512 MiB memory,
   identity, mount and network before planning a change.
2. Preserve a rollback-ready pinned image, old container configuration,
   existing BRC device identity, OAuth/relay pairing and a safe
   reattach path. Prefer a **real init/reaper** (`--init`/pinned
   `tini`) over merely increasing `--pids-limit`. Test process
   groups/session termination and bounded esbuild/Go concurrency in
   a **disposable** container first.
3. Only under the separate Windows-host owner change authorization,
   swap/recreate precisely this one sandbox container. Do not
   touch original Windows repositories, private vault, Codex,
   other three host services or VPS production. Check rollback and
   new device registration is NOT triggered.
4. Re-test: both clients' MCP authorization, 3+ bounded
   sequential + concurrent sessions, Node/Python/Git tasks, graceful
   and forced subtree termination, PID1 no-growth zombies,
   /tmp + memory + cgroup headroom, 128 KiB binary/stale writes,
   unexpected disconnect/reconnect. Windows **reboot/login**
   acceptance remains a distinct approved maintenance window.
5. No claim of native Windows host file/command access; previous
   original Win32 read-only device stays paused/offline.

## Tests and honesty

```sh
python3 -B -m unittest tests.test_h15_brc_process_preflight -v
```

These are deterministic source tests (schema, kernel metadata
fixture, abnormal PID counts, zombie reaper and denial paths),
**not host repair**. One-shot real preflight needs pinned source
installed into existing `/workspace/commander-tools` with
verified immutable Git blob SHA. Leave #445/#454 open until
actual owner host cutover/reconnect and both-client evidence.
