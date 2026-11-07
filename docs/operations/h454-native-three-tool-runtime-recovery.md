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
