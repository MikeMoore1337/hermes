# H454 - Hermes VPS native private TLS versioned upgrade (source only)

## Exact objective and original-host state

Upgrade the **already installed, inactive, disabled/static** Hermes native Linux
source from `e8887bfb7a04aaff9cbb91a1c46003fcd8d5347a` to the separately
verified 14-source bundle
`30db4fbab46626985b078d574dbe0b839872840e`.
This changes only the future native Linux code/dependency directories, the
private CA trust files, the two inactive systemd definitions and native manifest
after **another separate owner-approved root-console transaction**. Never
restart, start, enable or pair the native agent in this operation. Never touch
the BRC/WSS containers, credentials or original project trees.

Owner supplied the following exact **original Hermes VPS** evidence:

- `H454_NATIVE_POST_INSTALL=PASS`, original state on release e888,
  two units inactive, `device.json` absent, original rollback preserved;
- the approved old manifest SHA256
  `2fa2794f11d562ec2f2ec7317dac94c3a068bba1449f50268c55dbd8b227a2a1`;
- old disabled preflight/active unit SHA256
  `f8fad39f621838b2d8e98eaeec6a7a59f8ce6d9d8a218f4824719ffe1308b019` /
  `d4970ff3bb024e044ada9ac3c8d285e92c1edf9c9ad24005ab357017b55b059a`;
- the exact root-only WSS pin file and CA verified on the original host:
  `H454_PRIVATE_TLS_ORIGINAL_VPS=PASS`. Both unauthenticated ordinary
  HTTPS routes returned 404 because the old WSS proxy had not yet been
  deployed with PR #896's new protected bearer status route.
- **Both new 30db archives privately staged** on the original Hermes VPS
  with owner outputs `H454_STAGE_hermes-vps=PASS`,
  `H454_STAGE_yfc-vps=PASS`,
  `H454_NEW_NATIVE_ARTIFACTS_STAGED=PASS`,
  `H454_NATIVE_SERVICES_CHANGED=NO` and `H454_BRC_WSS_CHANGED=NO`.

The new **Hermes VPS** 14-file source TAR is pinned SHA256
`c61fd03785b5ffda9cc24b058ae779ad4514fb79d276769e21b48f8059a6e111`,
the deterministic embedded source-manifest SHA256 is
`9d58b7ddced287cb9eaa8a1e7874946a8b4757175ec70bb7e5f594664454e059`.
Source archive contains only exactly 14 approved Python files and a canonical
read-only manifest, with original Git blob provenance independently verified
against commit 30db. The previously pinned official `websockets==17.2`
wheel SHA256 is
`6aa59f0ef92e796b2db6f5f26550c4713c0e4036899fadf02f55e2ed4db0b7ae`.
The wheel is read from the previously verified e888 private staging location.

## Operator

Source file `scripts/h454_native_private_versioned_upgrade.py` has three
distinct modes:

- `plan` - strict read-only owner-host pin audit; reports new manifest,
  preflight unit, active unit, root CA and private-relay config SHA256. It
  checks the actual existing old unit and backup SHA, service state and owner
  UID, current 30db stage, the official 17.2 wheel, protected WSS TLS pins
  and unchanged Docker BRC/WSS pair; it never reads original project content.
- `install-off` - a separate *explicit owner-approved* exact-hash change.
  Requires root-owned original terminal, exact new plan, locked transaction,
  a typed challenge, readback of root-private backups and a repeated drift
  check after confirmation. New code/deps are placed in their own versioned
  paths; a PUBLIC (not private) exact pinned CA and restricted client
  configuration are written to a root-owned service-readable trust directory.
  The existing old renderer is checked by its exact Git blob, and its two
  audited, deterministic transformations generate the same private active
  unit as the source-only current renderer. The only egress rule is the
  existing verified **one private relay IPv4 /32**, no Cloudflare/DNS IPs.
  Atomically replaces only two **inactive** unit files and the native
  manifest; performs daemon-reload and rechecks both units remain static/
  disabled and inactive, original code/deps/backup remain, Docker IDs match.
- `rollback-off` - separate interactive, root-only restoration from the
  new sealed backup. Denies unexpected current unit and manifest bytes,
  active services or altered ownership, restores the e888 manifest and two
  old unit files. Leaves the new release and CA trust files on disk for
  incident forensics and leaves old e888 and older 8a retained.

The operator imports the **already installed trusted owner-source** baseline
`82a51cc0d718e16e6d0be8869436359a06fc94b7`, including the old
active renderer and old preflight renderer; its exact expected Git blob
digests are embedded and verified by the read-only plan. The new source
bundle and wheel are verified without trusting arbitrary tar members.
Never execute the operator from an unverified checkout, and never copy a
`device.json` or a BRC bearer into the private staging area.

### Future original-host read-only plan

After PR review, passing exact SHA CI and controlled GitHub merge, obtain
the **exact operator source** from the merged commit into an unused root-only
file. Verify its exact Git blob SHA-1 or SHA256 against reviewed GitHub source
before import/execution. From the previously pinned owner-source release:

```bash
cd /opt/hermes-agent-owner/releases/main-82a51cc0d718e16e6d0be8869436359a06fc94b7
PYTHONPATH="$PWD" python3 -B /root/h454_native_private_versioned_upgrade.py plan
```

Expected report status `H454_PRIVATE_UPGRADE_PLAN_PASS`. It must be
independently checked for target Hermes VPS, exact old/new releases and
new manifest+unit CA/config hashes, private single-IP-only egress and no
device pairing. This runbook does NOT authorize `install-off` automatically.

Only after a separate current-conversation owner approval specifically
naming the preview hashes and original VPS changes should the same
exact-blob operator execute `install-off` in an owner root TTY, with
typed exact confirmation. Save the receipt. If any step prints `HOLD`,
preserve staging/backup and stop; use guarded `rollback-off` only after
identifying whether a partial switch occurred. Never manually remove
historical receipts or previous source/dependency directories just to
pass a new preflight.

## Remaining barriers to end-to-end

This operator DOES NOT deploy PR #896's private status-enabled WSS proxy
or perform a BRC/WSS joint image switch. The old pinned private WSS
sidecar continues to give 404 to `/device/native-status` and will cause
the new native client to fail closed. New CA trust alone cannot authorize
an unpaired device. Device registration, token storage, WSS proxy update,
authoritative live bearer revocation, non-root openat2 canary, and bounded
native service first start are separate owner-approved original-host
steps. Native YFC VPS and native Windows must receive their own independently
verified host installations, followed by ChatGPT+Codex 2x3 E2E before #454
can close.
