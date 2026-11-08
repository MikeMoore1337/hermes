# H454 - recover native original-Windows read parity in the active BRC relay

This procedure is **not** the Hermes source-code release. The running
`hermes-brc-relay` image on `vps1777112993` must be upgraded separately.
Observed legacy image (2026-10-27):
`sha256:4f7c2d0a8f7a3e23e19b1e5110ba3722f37435ff93b9b352abb9122f0bbd5f`
exports `native_file_stat,native_file_read`, while the restricted Win32 agent
advertises `native_file_stat,native_file_read,native_file_list`.
This is a **confirmed tool-catalog mismatch**; it does not independently
prove that every other owner/transport/audit gate is healthy.

## Already verified independently

- Windows original-folder `hermes/README.md` local Win32 stat and MCP stat PASS.
- Restricted Windows identity `hermes-brc-readonly`, SSH loopback health HTTP 200.
- Existing device `h454-win-01335a1f6e6705b4`: exactly one owner `admin`,
  `win32`, `paused=false` (live connector currently OFFLINE).
- Original three Linux/Docker sandbox devices remain online.
- Client original native stat/read refused; no successful original-host
  read/SHA256/secret-path negative E2E has been observed.

## Candidate CI acceptance (NO production change)

1. Require exact merged `main` source SHA with passing repository and
   `H-15 pinned Remote Commander candidate` jobs.
2. The candidate's **compiled** `NATIVE_TOOLS` and **built OCI image**
   must each pass `H454_*_NATIVE_TOOLSET_3=PASS`, with exact names/order:
   `native_file_stat,native_file_read,native_file_list`. Do not accept
   TypeScript source inspection or a green source release in lieu of
   this check.
3. Verify immutable OCI ID, archive SHA256, release manifest, CI job log,
   source provenance, OAuth/sandbox negative E2E and rollback rehearsal.
   Reuse `scripts/h15_brc_owner_artifact_stage.py` to discover, download,
   verify, and optionally load the **new** candidate (no runtime cutover).
   Never reuse an artifact whose relevant BRC inputs differ from `main`.

## Stage 1 workspace catalog preservation (2026-11-07)

The **real running** owner relay has two Docker bind mounts, not one:

- `/state`, the original read/write SQLite state directory.
- `/run/h454/workspace-registry.json`, the previously owner-approved
  **read-only** Stage 1 registry used for four sandbox projects.

The verified candidate's first offline `plan` refused with
`relay_mounts_not_single`. The isolated OCI bundle and image were independently
verified; the image can be loaded without starting or switching a container.
The strict check now accepts the legacy one-mount layout or the exact Stage 1
two-mount layout **only** if the extra bind is pinned to the original root-owned
regular single-link `0444` registry file (SHA-256
`8253e69bf43597e4d76dbba941588c930e1ce3fbb14e7daf5426f3ab8f482e85`)
under the original source release, with no symlinked or group/world-writable
ancestors. All three `BRC_WORKSPACE_REGISTRY`, `BRC_DB` and `HOME` env pins
must appear exactly once.

The transaction must preserve that read-only mount and all three env pins,
re-check the source and effective mounts immediately before Docker stop and
after candidate creation, and restore the original container if the registry
is dropped. Generic host paths, Docker sockets, writable catalogs, extra
mounts or unexpected owner/permissions fail closed. Do **not** remove the
registry merely to satisfy a historical single-mount rule.

**Offline operator usage:** Run the owner artifact verifier from the
**exact released source directory**, e.g.
`/opt/hermes-agent-owner/releases/main-<verified-main-sha>`, with the
private staging directory. The active module mirror at
`/opt/hermes-agent-owner` does not contain the immutable
`deploy/h15/load-verified-image.sh` loader and `--load` must refuse there.
An image imported into Docker is **not** a live cutover. The root-owned owner
approval JSON previously observed on this host pins an unrelated old image,
archive and source SHA, and must never be reused as new consent.

## Stage 1 WSS proxy pair gate (2026-11-07)

**STOP BEFORE CUTOVER:** On the actual owner VPS, the running
`hermes-h454-wss-proxy` is configured with
`HostConfig.NetworkMode=container:<current hermes-brc-relay container ID>`.
The pair is currently healthy and shares the **old relay's specific
network namespace**, not merely its host/IP. A relay-only `docker stop`,
rename and fresh `docker run` would strand the sidecar and can break
client WSS while the internal relay health still passes.

The existing H454 native3 **single-container** wrapper calls the generic
transactional operator, which does not reconnect or replace the WSS sidecar.
The generic operator now refuses **both** `plan` and `cutover` if the
owner Stage 1 pin file exists, or Docker lists the exact paired proxy.
If Docker discovery cannot be verified, it also refuses. This gate runs
before OCI preflight, state backup, Docker stop, checkpoint rename or any
relay mutation. **Never remove the pair's pin file or proxy to bypass it.**

A future owner-reviewed, explicitly authorized **joint** relay + WSS
proxy operator must verify and retain both original container IDs,
root-owned WSS/TLS pins, the 2-mount workspace registry, shared
network namespace, OAuth/device state, a rollback checkpoint for each
component, and live ChatGPT/Codex reconnect before cutover can be
considered safe. A green OCI candidate or prior `PLAN_ONLY`
without the pair gate is **not** cutover approval.

## Owner WSS-pair read-only admission (source-only tool)

Use `scripts/h454_native3_paired_preflight.py` to prove the currently
running relay/WSS pair is suitable for a **future** joint transaction, without
stopping, renaming, creating, or deleting either container:

```bash
cd /opt/hermes-agent-owner/releases/main-<exact-installed-release-sha>
python3 -m scripts.h454_native3_paired_preflight plan \
  --release-sha <exact-installed-release-sha> \
  --bundle-dir <owner-verified-private-bundle-dir> \
  --image <pinned-ci-config-image-sha256> \
  --archive-sha <pinned-verified-archive-sha256> \
  --candidate-sha <candidate-build-source-commit>
```

The CLI intentionally exposes `plan` **only**, never `cutover` or `--execute`.
It requires the exact deployed source directory and current source receipt,
root authorization, the independently verified OCI bundle and image,
the original owner-approved relay image, the root-owned pin store and pinned
reconciler source, the correct WSS proxy attached to the **same relay ID**
network namespace, TLS certificate provenance, the original immutable
four-project workspace registry and free, unique rollback checkpoint slots.
It refuses stale WSS recovery markers or missing baseline devices.
Rollback checkpoint availability is queried through a non-optional Docker
`container ls --all` with an exact anchored name filter. Any Docker API
error or ambiguous discovery is a hard refusal; a failed optional
`container inspect` must **never** be interpreted as proof that a slot is
free. This is covered by a regression that models a failing Docker subprocess.

Success returns `PAIR_PREFLIGHT_PASS_NO_MUTATIONS`,
`changes_performed=false` and `deployment_approved=false`.
No credentials, WSS pins or certificate contents appear in stdout. A green
`plan` is **necessary, not sufficient**, for live parity. It does not grant
permission for a joint WSS/relay switch and does not implement rollback,
re-pairing, root ACL changes, or native Windows operations. The previous
single-relay `h454_brc_native_three_tool_cutover` remains blocked by the
Stage 1 WSS pin/sidecar gate; **do not bypass it**.

## Production gate (separate explicit owner approval required)

- Ensure exactly the expected existing running image and healthy sandbox
  baseline; capture the actual image ID and exact approved image/archive/commit.
- The already approved generic transactional cutover operator's old
  `hermes-brc-relay-h454-rollback` checkpoint is occupied, as are
  `hermes-brc-relay-h455-rollback` and
  `hermes-brc-relay-h455-refresh-rollback` and the *already occupied*
  `hermes-brc-relay-h454-native3-rollback`. **Never overwrite them.**
- Read-only check on 2026-11-06 observed the old native3 rollback container
  STOPPED and the new `hermes-brc-relay-h454-native3-v2-rollback` slot AVAILABLE.
  Re-verify both states immediately before any authorized cutover.
- This change supplies `scripts.h454_brc_native_three_tool_cutover`,
  which uses only the new
  `hermes-brc-relay-h454-native3-v2-rollback` checkpoint. Run its `plan`
  mode first with verified `--bundle-dir`, `--image`,
  `--archive-sha`, `--hermes-sha`; assert `changed=false`.
- Prepare the exact, root-owned 0600 owner-approval file defined by
  `scripts.h15_brc_transactional_upgrade`; previous image and all candidate
  pins must match. The caller must provide `cutover` **and** `--execute`.
  The operator retains SQLite backup/restore evidence, uses the existing
  one-mount/no-capabilities container contract, performs bounded health
  checks and attempts rollback on failures. Do not run this from MCP or
  modify the OCI code live.
- Keep public `/ws` closed, unchanged SSH/OAuth, no Windows host writes,
  shell execution, new mounts or ACL/privilege changes.

## After cutover: genuine user-host acceptance

1. Check live exported native tool names **from the new container** and
   all three original sandbox devices independently.
2. Re-pair only the same restricted Windows device over the private tunnel
   if it is offline; use the owner-only `h15_brc_owner_private_repair`
   only for `paused=false`. Never disclose code or bearer.
3. While the Win32 agent is confirmed online, perform actual ChatGPT
   `native_file_stat` and `native_file_read` of an original approved
   `README.md`, compare size + decoded SHA256 with a local owner-host
   reference, verify traversal, `.env`, `.git`, vault refusals and
   preserve three sandbox devices. Refresh ChatGPT tool registration if
   `native_file_list` is still absent; do not infer client availability
   from the relay's server catalog.
4. Then end temporary Windows agent session, separately approve owner-only
   bearer revocation, verify device `offline/paused=true`, both native
   reads refused and sandbox baseline unchanged.
5. Full Desktop Commander parity remains **OPEN**: native writes/process,
   durable authorization, onboarding, login/reboot recovery and Codex
   Desktop independent E2E are not delivered by this read-only repair.

If any preflight/identity/CI/backup/checkpoint evidence is absent, do not
cut over. No default automation or model-provider charges are introduced.

## Stage 2 joint relay/WSS transaction candidate (source-only, NOT RELEASED)

The new `scripts/h454_native3_paired_transaction.py` is a **dormant code
candidate**. It is not the old `h454_brc_native_three_tool_cutover`, and it
does not bypass the fail-closed WSS pair gate in the generic relay-only
operator. The new runner accepts `plan`, `cutover`, `recover`, and `rollback`.
Only `plan` is allowed without `--execute`; `plan` delegates to the
previously reviewed read-only pair preflight. Do **not** run the mutating modes
until exact-code security review, CI, a real owner-host read-only plan, explicit
owner approval, production release and a rehearsed rollback are complete.

Separate root-only `0600` approval file:
`/etc/hermes-brc-relay/native3-paired-approval.json`. Its strict schema binds
the decision `OWNER_APPROVED_H454_NATIVE3_JOINT_RELAY_WSS_CUTOVER`, exact
installed Hermes release SHA, candidate build SHA, verified OCI config/runtime
image IDs, archive SHA256, both original container IDs/images, the original
WSS pin-file digest and **both unique checkpoint names**. Never copy the
historical single-relay or Stage 1 owner approval, accept missing/extra keys,
or generate an approval from an MCP parameter. No tool writes this file.

The transaction preserves the original pinned Stage 1 read-only workspace
registry and `/state`, enforces the installed WSS/TLS identity and Linux
sandbox security profile, creates two **distinct retained checkpoints** and
uses the original proxy OCI image with `--network container:<new-relay-ID>`.
It keeps disposable SQLite backup evidence and checks authorization-state
regression without replacing the current database with an old copy. The
success receipt explicitly says
`SWITCHED_PENDING_CHATGPT_CODEX_LIVE_ACCEPTANCE`, never `DONE`.

On a normal failed cutover it attempts to restore both verified original
containers. If Docker returned an ambiguous create/rename result or a foreign
container occupies a name, the runner **fails closed for manual recovery**
rather than deleting an unidentified container. A root-owned
`native3-pair.pending` marker records old/new IDs across known phases;
`recover --execute` uses only that exact receipt and the independently
pinned artifact/approval. Following a successful switch, the original
containers are retained; `rollback --execute` revalidates active new IDs
and original checkpoints before attempting restoration. A failed recovery
must be treated as an incident and verified by the owner, not retried
indiscriminately. Subsequent repeat cutovers are intentionally blocked by
the retained original pin snapshot until a separate reviewed cleanup
procedure is authorized.

**Mandatory before readiness:** independent code/security review at the exact
PR HEAD; repository, BRC candidate, Windows native and UI regression checks;
fault injection for every stop/rename/create/update/pin/health/reconcile
boundary; a live root-only `plan` with no Docker mutation; WSS reconnect from
both ChatGPT and Codex, devices+workspaces checks and a real pair rollback
rehearsal in an authorized maintenance window. Original Windows
native service, ACL, private SSH, device token/re-pairing and original-folder
write/execute permissions are still **NOT APPROVED** by this source change.
No automatic cutover, deployment or background worker is introduced.

## Admin password hash stability during a paired cutover

The pinned upstream BRC relay `cbe511702dd0147650353c29ac6ab1decd8afda1`
calls `SqliteStore.upsertUser(cfg.adminUser, cfg.adminPassword)` at every
`buildRelay()` startup. Its original `upsertUser` generated a fresh random
scrypt salt and wrote a new `users.password_hash` even when the configured
password had not changed. That behavior is consistent with the single
`users.password_hash` delta observed between the two preserved 2026-11-08
owner-only SQLite snapshots. This identifies a concrete, reproducible **source
mechanism**, not definitive attribution to the live incident without inspecting
the installed candidate's compiled source and startup event trace.

The isolated source patch `scripts/h454_brc_admin_hash_stability.py` is
restricted to the exact upstream commit and the expected original Git blob.
When an existing admin password passes the upstream `verifyPassword`, the
original user ID and password hash are kept **byte-for-byte** across startup.
An actual password change still produces a fresh salted hash, revokes the old
password and causes the unchanged strict `compare_disposable_copies` auth
gate to HOLD. No credentials, token values, SQLite fields, or protected owner
files are read or changed by the source patch.

Acceptance requires both a pinned-source negative unittest and an **actual
compiled upstream relay** test with a disposable SQLite database: first
startup, second startup with the same synthetic password, password rotation,
and another unchanged-password startup. The original database compatibility
and credential-regression guard stays unchanged, including its check of
`users.password_hash`.

**Deployment / recovery boundary:** source merge or isolated CI does not update
an already installed BRC OCI image or authorize a second owner-host cutover.
Preserve original container/pin snapshots and the retained before/after SQLite
files. Obtain fresh, independently reviewed OCI/CVE attestation, exact owner
source-release approval, read-only paired `plan`, a separate root-only
authorization record and an agreed maintenance window before any new live
attempt. Never bypass `STALE_SECURITY_STATE`, delete evidence, write older
password hashes to live SQLite, or retry an ambiguous Docker operation based
only on `inspect` state. Real Windows login/reboot and multi-client functional
acceptance remain separate gates.
