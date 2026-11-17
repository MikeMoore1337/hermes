# H454 - independent WSS native-status source readiness gate (source only)

## State at 2026-11-17

The owner provided a successful original Hermes VPS root-console receipt for the
disabled-only native Linux release upgrade e888 -> 30db:

- H454_APPROVED_PLAN_MATCH=PASS
- H454_NATIVE_PRIVATE_MIGRATION=INSTALLED_DISABLED
- H454_NATIVE_OLD_VERSIONS_AND_BACKUPS=PRESERVED
- H454_NATIVE_PAIRED=NO
- H454_BRC_WSS_CHANGED=NO
- Both systemd units remain inactive: active service disabled, preflight static

The private-TLS status source from PR #896 is in main but NOT in the running
root-mounted WSS proxy. The running proxy script is pinned to the earlier Git
blob 7a0f4c20095ba2d98850c4e8e16d1823c60a1f06. The merged status-capable
source is 014c3ec08d2b532f710b52601efcb2a3dae4c633 at the exact source
commit 8303df159ae8cc00cc79a7c691c80c673f1e71a6. The old helper used
by the paired relay/WSS transaction recreates the proxy from the old root
mount; a new BRC image alone cannot deliver the status endpoint.

## Read-only operator

scripts/h454_wss_native_status_preflight.py is intentionally plan-only:

- Original-root identity and fixed pre-existing owner source import are required.
- A root-only candidate file is validated against the exact merged Git blob.
- The active proxy must still match BOTH its protected pin-file SHA256 and the
  approved original Git blob. Existing BRC/WSS container IDs, network namespace,
  TLS CA and normal legacy HTTPS 404 behavior are checked.
- The installed dormant 30db source/manifest/trust and both inactive systemd
  unit SHA256 values are checked. A device.json would refuse the plan.
- Previous pending/rollback markers and an occupied new sidecar checkpoint
  name cause refusal. A failed Docker list command must NEVER count as free.
- There are NO Docker, systemd, key, token, DB or filesystem write operations.
  The plan cannot stage, migrate, start, stop, pair, revoke, or cut over.

## Historical native3 transaction receipt admission (2026-11-17)

After the owner-approved **successful** Nov-13 joint BRC/WSS cutover, the
original transaction deliberately preserved the root-private file
`native3-original-pins.json` and the stopped original relay/proxy
checkpoints. This file is **not** `native3-pair.pending`, and must never
be deleted or renamed merely to satisfy a subsequent sidecar-only plan.

The first preflight implementation inadvertently treated both the durable
history and a genuinely pending transaction as the same
`EXISTING_WSS_TRANSACTION` error. The corrected read-only admission
distinguishes them:

- Any `prepare.pending`, `reconcile.pending`, `native3-pair.pending`,
  `native-status-upgrade.pending`, existing status-upgrade backup or an
  unrecognized old proxy checkpoint remains a blocking failure.
- A historical `native3-original-pins.json` is accepted **only** when its
  root ownership, regular-file mode 0600 and single link pass the no-follow
  read, its exact previously attested SHA256 matches
  `a7efdbb4d0d5eec05890929b27e4e76ee6c38ee20bb13d18e99cc5a2a67ee0cb`,
  its old BRC/WSS IDs/images match the known Nov-13 original pair, its
  shared TLS CA/key/certificate and network identity match the **current**
  protected pins, and both stopped original native3 checkpoint containers
  still have the exact attested Docker IDs/images/network namespace.
- No historical file is also a valid clean state (a previous operation
  may have archived its evidence through the separately reviewed re-arm).
- The output records only `completed_native3_history_verified=true|false`.
  It never prints the old/new pin JSON or secrets.

These are **specific historical admission checks**, not a general
`ignore retained pins` switch. A different snapshot or missing/checkpoint
drift still fails closed. Tests distinguish genuine pending operations,
foreign identities/CA and an occupied new status rollback checkpoint.

Before rerunning the plan on the original VPS, preserve the previous
`/root/h454_wss_native_status_preflight_902.py` unchanged. Stage the next
exact merged operator revision in a fresh root-only filename. Only `plan`
is permitted; Docker/WSS/native service starts, device pairing, credentials,
recovery and cutover require their own separately scoped authorization.

## Corrected active pair identity (2026-11-17)

Original-owner-host read-only diagnostics confirmed that the currently
active BRC and WSS Docker containers both match their protected pinned
images. The previous plan compared the active BRC against the now inactive
Stage1 rollback image `sha256:7dd283729e164ccd0bb4477b4e8edab342fc4ca350922acee6b4d4f33de8bfa1`,
and therefore wrongly refused `EXISTING_BRC_WSS_PAIR_CHANGED`.

The **approved and directly attested** H454 native3 cutover on 2026-11-13
installed active relay image
`sha256:3488e1ff44bb0843ecbc62a1951277ccbf118d1f3ba899b7636a66aa84d55e06`.
Its original active relay ID was
`c10587c6bdb51bcbdd4ccea65d5020a6a18deefaa13fb9f9d04eca4661b848d0`,
and WSS sidecar ID was
`ad1977a65f10051a15eb69343f5925f9c47188bd4686bfefea8834c6667fd653`.
The WSS sidecar's image remains the pinned `sha256:6e5f74...`.
The owner-verified source-only deploy on November 13 independently
reconfirmed these exact identities and running/network status; see
Hermes #454 owner evidence comment 6858145960.

The corrected read-only plan uses these **fixed, exact accepted-image and
container identity pins** rather than adopting arbitrary values from
`pins.json`. It then still independently validates Docker inspect,
private network namespace, root-owned proxy source SHA and private CA/TLS,
disabled native units and available rollback slots. Mismatched pinned
manifest, runtime container, unexpected rollback, or a future separately
authorized replacement still fails closed. This fix cannot authorize
cutover, pairing, service start, or a user-host mutation.

The previous root staging file
`/root/h454_wss_native_status_preflight.py` is intentionally retained
for evidence; new operator revisions must be staged under a **new**
root-private filename and exact verified Git blob before any read-only
plan rerun. The candidate WSS source at
`/root/h454-wss-native-status-8303.mjs` is unchanged and already
verified against `014c3ec08d2b532f710b52601efcb2a3dae4c633`.

The host-side candidate must not be downloaded, trusted or executed merely
because this PR is merged. After reviewed exact-main CI, a new owner-approved
source-only staging step may place the exact reviewed source and operator in
new absent /root filenames with mode 0600 and verify both Git blob hashes.
The exact staging and operator SHA must be approved and verified independently.
From the original unchanged owner-source release, the *read-only* command is:

    cd /opt/hermes-agent-owner/releases/main-82a51cc0d718e16e6d0be8869436359a06fc94b7
    PYTHONPATH="$PWD" python3 -B /root/h454_wss_native_status_preflight_903.py plan \
        --candidate-source /root/h454-wss-native-status-8303.mjs

It must report H454_WSS_NATIVE_STATUS_PREPARE_PLAN_PASS; all original
containers continue running throughout. The report includes only public source
hashes, existing container IDs, and boolean state, never CA bytes, bearer,
private network addresses, or project file content. The terminal must not
paste live passwords, device codes or Bearer tokens into ChatGPT or GitHub.

## Next release boundary

Plan PASS is not production authorization. Create and independently review
a separate atomic, rollback-safe WSS-proxy replacement transaction, retaining
the old live proxy, original pinned source, certificates, pin file and Docker
rollback evidence. Prove a real authenticated owner-status/revocation flow and
the anonymous 403 on the private TLS route while all other HTTP paths remain
404. Restore the old proxy on any failed status or device reconnect check.

A sidecar-only switch should be preferred to restarting the working BRC
relay where the original pinned relay is already sufficient. Any actual
Docker or root-owned WSS update, owner pairing, resident service start,
YFC/Windows host installation and full 2x3 client acceptance require their
own scope and runtime evidence. No production cutover is covered by this PR.

Refs #454, PR #896, PR #899.
