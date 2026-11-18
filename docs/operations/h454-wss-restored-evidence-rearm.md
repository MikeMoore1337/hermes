# H454 - archive a verified restored WSS failure without new cutover

## Scope and owner approval

**Source only**. On 2026-11-18 the owner's original Hermes VPS attempted
one specifically approved WSS sidecar replacement. The original WSS and its
exact source/pins were automatically restored. BRC was never restarted.
The root-private original evidence was intentionally retained:

- `/var/lib/hermes-h454-wss-sidecar/native-status-upgrade-evidence`, mode 0700
- `/var/lib/hermes-h454-wss-sidecar/native-status-original-pins.json`, mode 0600

The protected evidence now blocks the old plan and a second cutover. Never
delete it, change its permissions, reuse the first consent, or bypass the
existing `preflight` gate. The first failure phase was lost in the old
operator; GitHub PR #904 can label failures only in subsequent attempts.

Source: `scripts/h454_wss_native_status_evidence_rearm.py`.
It is designed exclusively for this first failed attempt on the original
`vps1777112993`, with exact fixed BRC/WSS IDs, immutable old and candidate
proxy hashes, the existing original owner-installed
`h454_wss_native_status_sidecar_cutover_901.py` Git blob
`ab4b07083955934f49994646b9bf634823620165`, and pinned root-only
`h454_wss_native_status_preflight_903.py`. It cannot load arbitrary
source bundles, auto-activate native services, or issue an owner token.

## Operations

`plan` - read-only and root-only. It loads the exact former signed-in
operator source, validates its known immutable source blob and preflight;
takes the existing original relay and WSS pin-file locks; verifies the
protected backup contents and active old source/pins by SHA256 byte
equality, fixed CID/image/namespace, TLS 404, dormant 30db native release,
previous native3 retained checkpoint, absent all pending markers and no
new WSS sidecar checkpoint or competing archive slot. It does not run
`reconcile` or any Docker mutation. Its success status:

`H454_WSS_RESTORED_EVIDENCE_PLAN_PASS`

`rearm --execute` - a **separately owner-approved** action, only after an
unchanged identical `plan` report and exact phrase typed on the original
root TTY. Under the same original relay and pin locks it:
1. Creates a new 0700 archive directory using an exclusively absent path
   `native-status-failed-attempt-20261118-1237`.
2. Creates and fsyncs a root-0600 manifest inside the prior protected backup
   with the old/candidate SHA256 and explicit no-cutover authorization.
3. Hardlinks the existing root-0600 original pin record into the prior backup
   directory, fsyncs it and verifies matching device/inode.
4. Atomically renames the prior whole evidence directory under the new
   archive directory, retaining all six original evidence files and receipt.
5. Only after verifying the archived pin inode's identity, unlinks the
   old *duplicate link* in the root. The original inode and bytes survive
   in the protected archive. No original backup content is deleted.
6. Invokes the previously merged **read-only** `_903.py plan` after unlocking
   to verify the clean gate. This remains **NO NEW CUTOVER AUTHORIZATION**.

The new archived history remains private and must never be garbage-collected
as part of this transaction. Crash/failure between any steps keeps at
least one root-private copy of the original pin bytes and **HALTs**;
do not auto-retry, rename leftover evidence or manually clean up.
Source tests inject failures before link and before atomic rename, test
existing foreign slots, original pin mismatch and immutable evidence.

## Release boundaries

The root original owner source remains
`82a51cc0d718e16e6d0be8869436359a06fc94b7`.
The original WSS BRC relay CID remains
`c10587c6bdb51bcbdd4ccea65d5020a6a18deefaa13fb9f9d04eca4661b848d0`,
and original WSS sidecar CID remains
`ad1977a65f10051a15eb69343f5925f9c47188bd4686bfefea8834c6667fd653`.
No BRC/WSS restart, native service start, Windows or YFC host operations.

**DO NOT EXECUTE** this source from GitHub or root console until exact
PR/CI review, then original-root read-only plan acceptance and a fresh
separate owner approval **only for evidence archiving**. That approval
must NOT be conflated with permission for another WSS production cutover.
A future cutover must use the independently staged newer WSS operator
and need a new explicit authorization, with status/reconnect/rollback
acceptance on the original VPS.

Refs #454, #901, #903, #904, #905.
