# Hermes #346 - private-CA WSS leaf rotation

## Scope and decision

Automatic rotation means **unattended activation of previously signed leaves**.
The CA signing private key stays offline, outside the Hermes VPS, H-01 agent,
ChatGPT and GitHub. Each future leaf must be signed and staged before expiry.
Completely unattended issuance is NOT included; it would require an isolated
online CA signer and a separate owner decision. No new paid service is needed.

This source release does not install/restart a service, alter the current
seven-day pilot WSS identity, enroll devices or add command-execution access.

## Implementation

- Certificate preflight validates approved CA chain, serverAuth, DNS:localhost
  SAN (CN alone rejected), private-key match, certificate validity at the
  requested evaluation time, and minimum remaining lifetime.
- A root-owned generations directory keeps cert/key together. An atomic
  replacement of one active symlink switches **both** files at once.
- One pending candidate, an exclusive process lock, and a rollback marker
  fsynced under a private temporary name before atomic publication prevent
  concurrency, partial live markers and unverified promotion after interruption.
  Once rollback succeeds, the interrupted candidate's pending pointer is
  removed: the owner must explicitly re-stage it after review, not blindly retry.
- Interrupted candidate staging is safely retryable with the **exact same**
  pre-signed certificate and private key. A fully published but not yet
  pending-linked generation is revalidated (permissions, trust chain, SAN,
  expiry, exact source bytes) before publishing the pending pointer.
  Partially copied `.incoming-*` directories have unique private names and
  cannot block retries. They are never auto-deleted because they may contain
  sensitive key material or forensic evidence. The owner should inspect and
  securely remove orphaned staging directories separately after confirming
  that no staging process is running. A mismatched existing generation is a
  hard NO-GO, never an overwrite. On failure the previous pointer and service are restored.
- After restart, verify a real loopback TLS handshake against the CA, hostname,
  TLS version, and **exact expected leaf DER**. systemctl active is insufficient.
- Systemd unit/timer templates are supplied but disabled and not installed.
  Ops Watch expiry uses the active generation after approved migration while
  preserving the current legacy cert behavior before it.
- Tests use only throwaway OpenSSL keys and a localhost TLS fixture, never
  production device identities, connections or owner credentials.

## One-time migration (requires separate real-host release approval)

The original hermes-device-fabric-pilot.service reads regular TLS cert.pem and
key.pem from /var/lib/hermes-device-fabric/tls. Windows and YFC clients trust
the old pilot certificate. Replacing it directly with a private-CA leaf would
break the clients. An operator must do the following IN ORDER:

1. Back up original unit/cert/key, both client trust bundles, persistent
   registry, credentials and service state in private owner-controlled storage.
   Test restore before activation. Preserve existing SSH key and device IDs.
2. While original WSS is online, verify BOTH Windows LocalService and YFC
   systemd client can validate an overlap bundle containing the original pilot
   trust certificate AND the new public CA. Respect the 6144-byte client
   certificate field size limit. Re-check live authenticated heartbeats.
   Do not change CA and server leaf together.
3. Privately provision new CA PUBLIC cert and pre-signed localhost leaf/key.
   CA PRIVATE signing key must remain offline. The source private leaf key
   must be root-owned mode 0600. Require TLS layout: tls/ and generations/
   root:hermes-device-fabric 0750; ca-public.pem root:hermes-device-fabric
   0640; individual generation directories 0750 and cert/key 0640, also
   root:hermes-device-fabric. Group-read is required for the non-root WSS
   service; using root:root 0600 for its active key would break the service.
4. From the reviewed source root, inspect the exact signed artifacts and run
   the read-only preflight first. Run these root-only commands with actual
   approved input paths (do not paste key bytes anywhere):

       python3 -m scripts.h15_presence_tls_rotation stage --leaf /root/leaf.pem --key /root/leaf.key
       python3 -m scripts.h15_presence_tls_rotation bootstrap

   Bootstrap ONLY establishes a pointer. It does NOT restart WSS.
5. Separately review and install the
   deploy/hermes-device-fabric-pilot-rotating.service.in template, replacing
   @SOURCE@ with the reviewed source location. Validate systemd-analyze verify,
   restart just this service on the owner-approved maintenance window, inspect
   the actual TLS identity and fresh Windows/YFC device heartbeats. On any
   failure restore the original unit/cert/key and trust bundles without
   revoking enrollments or disabling TLS hostname verification.
6. Only after successful Windows and YFC proof may the operator install and
   enable the separate staged
   deploy/hermes-device-fabric-tls-rotation.service.in and
   deploy/hermes-device-fabric-tls-rotation.timer.in templates. Substitute
   the exact reviewed @SOURCE@. No public listener or provider calls are
   introduced. Verify the next real daily tick and both client reconnects.

## Daily operation after migration

An authorized operator stages the next already signed leaf using the stage
command, with at least three days remaining at activation. The root-only timer
calls auto daily and uses `Persistent=true` to catch up a missed tick after
host downtime. This does not issue or sign certificates. If existing certificate expiry is more than three days away,
it returns ROTATION=NOT_DUE. When due, auto requires a single pending candidate,
changes one atomic pointer, restarts only the pinned presence service, checks
the exact new certificate over TLS and reports ROTATION=PASS. Failure restores
the original cert and service, reports ROTATION_ROLLED_BACK or
ROLLBACK_HEALTH_UNVERIFIED, and does not retry the failed candidate blindly.

A crash/power failure after marker publication leaves a durable rollback
marker, which auto/recover handles BEFORE any subsequent promotion. A crash
while writing the temporary marker leaves no incomplete live marker. If the
old leaf has already expired, auto permits recovery only when the old cert/key,
CA chain, SAN and EKU revalidate at its historical valid time; the fresh
pending leaf must still pass all present-time checks and the real TLS probe.
Rollback to an expired leaf is reported as HEALTH_UNVERIFIED unless real TLS
health is proven. Old generations remain for rollback, not automatically pruned. Device TLS expiry and offline/recovery Ops Watch
alerts remain required. Local TLS success is NOT device heartbeat acceptance.

## Release gate

| Criterion | Source/offline | Owner production |
| --- | --- | --- |
| CA/SAN/key/expiry, permissions | Tested | Pending |
| Atomic pointer, lock, interruption recovery | Tested | Pending |
| Exact TLS leaf proof and rollback | Tested localhost | Pending |
| systemd timer and genuine first tick | Templates only | Pending |
| Both real device trust bundles and reconnection | No owner data | Pending |
| CA custody, owner production opt-in and rollback | Offline CA design | Pending |

**Code release readiness does not imply production enablement.** Do not
close #346 until actual owner host and both agent acceptance checks pass.

## Ops Watch TLS-only expiry alerts (independent owner opt-in)

The presence agent opt-in must remain disabled until both real clients pass
boot/reconnect acceptance. However, an expired pilot certificate already
prevents either client from completing TLS, so tying *certificate* expiry
alerts to that presence consent creates a monitoring blind spot.

The existing Ops Watch collector supports a separate **TLS-only** root-controlled
consent. No scheduler, sender, network listener or device enrollment is added.
When the dedicated marker is absent, the legacy presence opt-in continues to
control certificate alerts as before. A malformed/symlinked TLS-only marker
fails closed with `unknown`, never silently falling back to presence consent.

On the Hermes VPS, **after owner approval**, create this marker one time using
an already authorized root console. The parent must be owned by root and 0700;
the JSON file must be root-owned 0600 with no hardlinks or symlinks.

```bash
python3 - <<'PY'
import json, os, stat
from datetime import datetime, timezone
from pathlib import Path

p = Path("/etc/hermes-device-fabric/ops-watch-tls.json")
p.parent.mkdir(mode=0o700, exist_ok=True)
st = p.parent.lstat()
if (not stat.S_ISDIR(st.st_mode) or st.st_uid != 0 or
        stat.S_IMODE(st.st_mode) != 0o700):
    raise SystemExit("TLS_MONITOR_PARENT_UNTRUSTED")
flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
fd = os.open(p, flags, 0o600)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump({"schema": 1, "purpose": "tls-expiry",
                   "enabled_at": datetime.now(timezone.utc).isoformat()}, f)
        f.write("\n")
        f.flush()
        os.fsync(f.fileno())
except BaseException:
    p.unlink(missing_ok=True)
    raise
print("TLS_ONLY_OPS_WATCH=ENABLED")
PY
```

No automatic service restart is needed. The **existing** 10-minute Ops Watch
collector reads the fixed TLS leaf certificate expiry and queues the existing
`device_tls_expiring` (48 hours) or `device_tls_expired` incident. The
existing sender handles deduplicated owner notifications. The absence of
`/var/lib/hermes-device-fabric/ops-watch-presence.json` continues to
suppress device-offline incidents. Do not create that legacy marker prematurely.

To verify without touching private keys, inspect the TLS status from the
deployed approved source root and the existing collector/outbox status.
For rollback of this *monitoring opt-in only*, move the marker into a
root-private backup directory under a documented maintenance action; the
monitor itself never changes the TLS listener or trust materials.

## Client trust-overlap preflight (source-only, no config writes)

Before migrating either Windows or YFC, use the existing client configuration,
the owner-approved public CA, and **both** CA-signed leaf certificates for an
isolated, read-only preflight. This is distinct from staging a new server leaf,
from an actual client trust update, and from verifying real WSS connectivity.

Run the reviewed helper from an exact-SHA source snapshot on the **authorized
client host** with the original device's private configuration available
locally. Public CA/cert files may be copied securely, but never send a device
token, private SSH key or server leaf key through ChatGPT or GitHub.

~~~bash
python3 -B -m scripts.h346_client_trust_preflight \
  --config "$PRIVATE_DEVICE_CONFIG" \
  --ca-public "$PUBLIC_CA_CERT" \
  --primary-leaf "$SIGNED_PRIMARY_LEAF" \
  --fallback-leaf "$SIGNED_FALLBACK_LEAF" \
  --device "$APPROVED_DEVICE_ID" \
  --expected-ca-sha256 "$OFFLINE_CA_DER_SHA256"
~~~

Use exactly linux-vps for the existing YFC host and windows-pc for the
approved Windows client. The **expected** CA DER SHA-256 fingerprint must be
attested independently at the offline signer; do not calculate it from the
same untrusted transfer and treat that as owner verification. The operator
should independently confirm both signed certificates correspond to the
pre-existing CSR public keys and the server's separately protected keys.

The helper checks existing client bundle schema/ID/local SSH-forward URL,
private POSIX file mode and single-link/regular-file integrity, public CA
signature/CA key-usage, chain verification of both distinct leaves, explicit
DNS:localhost SAN, serverAuth EKU, validity, the 6144-byte trust ceiling,
and SSLContext strict hostname/certificate validation. No token/config
contents or private key bytes appear in normal stdout. It **never modifies**
the original config or trust bundle.

A H346_CLIENT_TRUST_PREFLIGHT=PASS means that a dual-trust bundle is
*cryptographically compatible*. It does **not** mean that the bundle has
been installed, that Windows NTFS permissions have been verified, that any
running process reloaded its configuration, or that Windows/YFC have
connected to the real WSS relay. A native Windows ACL review, owner-approved
atomic write with backup, and actual TLS/heartbeat proof are still mandatory.

Keep the existing pilot trust certificate during the overlap interval;
do not replace the old trust with the CA alone. The old certificate being
expired means the *old relay* cannot pass current-time TLS verification,
even when it remains in the trust store. Back up the old private JSON with
root/administrator-only permissions before a separate client mutation.
The Linux --watch agent reads its JSON on process start, so approved
trust updates require a controlled agent restart; do not assume hot reload.

On the server, use the existing h15_presence_tls_preflight and staged
generation/rollback mechanism to verify that each new signed leaf matches
its protected local private key. A standalone public-only client preflight
cannot prove server key possession or recoverability from the expired
pilot. Do not change live relay/systemd units until both real clients
can prove the new CA after a separately authorized cutover window.

## Finite one-time owner-signed batch (2026-11-03 owner approval)

The owner authorized a **one-time** 15-certificate offline-style issuance
inside a `--network none --read-only --cap-drop ALL` Docker container, with
the CA signing key kept in tmpfs, memory swap explicitly disabled and no key
export. This is **not equivalent to a physically offline CA or hardware HSM**.
The Docker host administrator may access container memory and controls.
After that container was deleted, there is no retained CA private key capable
of renewing the same chain. Do not claim unlimited automatic issuance.

Exactly 15 distinct service leaf keypairs were generated on Hermes VPS:
the initial separately staged fallback, the already signed primary and
future-01 through future-13. Both real clients verified the CA SHA-256
`72e930d2ce5b3798237e1495ccfecf4300f303fb0f6b57f3accc9739b01d8ab0`.
The CA expires 2027-12-28, the last pre-signed leaf expires 2027-10-24.
Each future leaf has a **30-day validity** starting at a 25-day interval.
This is a finite 355-day issuance horizon, not automatic CA renewal.

The `scripts.h346_presigned_batch` helper is a strict, root-only,
CA-pinned **activation scheduler**. Its archive is a root-owned 0700 directory
at `/var/lib/hermes-device-fabric/tls/presigned-batch`, containing a
root-owned 0600 `manifest.json` and only the approved `primary.pem` and
`future-01.pem` .. `future-13.pem` with matching private leaf keys.
The fallback is kept separately as the initial trusted generation.
Never copy the owner CA signing key or any private device identity there.
Keep the archive root-only: the presence service reads only the active
group-readable generation, never the archive.

The manifest schema is `hermes-h346-presigned-batch-v1`, with exactly
the 14 ordered slots above, approved public CA DER digest and each public
leaf DER digest / UTC validity window. An owner-admitted archive must
verify *every* leaf/key pair and CA chain against this signed batch,
confirm strict `DNS:localhost` and `serverAuth`, and check all
permissions before the first timer activation.

Once real Windows/YFC authenticated reconnect and an independently valid
rollback generation have passed after the primary switch, install and
`systemd-analyze verify` only the new templates:
`deploy/hermes-device-fabric-tls-presigned.service.in` and
`deploy/hermes-device-fabric-tls-presigned.timer.in`, substituting
`@SOURCE@` with the exact approved immutable main SHA release. Do not
enable the old `hermes-device-fabric-tls-rotation.timer` simultaneously.
Never enable either timer until the archive passes admission.

Use `python3 -B -m scripts.h346_presigned_batch check` to inspect the
next step before enabling the owner-approved timer. `check` selects the
next approved candidate but does not stage/promote it. The daily timer
runs `auto` at 04:00 UTC, with persistent catch-up after reboot.
It uses the existing single-pointer stage/activate, restart, strict
loopback TLS and fail-closed rollback. If a previously published candidate
failed or an interrupted transaction needs review, it never silently
selects a later certificate. A bad candidate leaves a clear NO_GO.
At the last leaf's threshold it returns
`PRESIGNED_BATCH_EXHAUSTED_OWNER_RENEWAL_REQUIRED`; restore an owner
signing operation well before October 2027.

The previous legacy expired leaf **cannot provide a healthy rollback**.
The signed fallback generation serves as that rollback while testing the
primary. Retain the same approved CA in both Windows/YFC trust stores.
Strict real authenticated device heartbeat evidence is required after
every live switch, not merely localhost TLS success. Ops Watch TLS expiry
and offline devices remain independent controls.

## Early warning for the finite presigned CA batch (no signing key)

The one-time CA was destroyed after issuing 15 public certificates, so
**automatic activation is NOT automatic signing**. The 48-hour active-leaf
expiry alarm alone would be dangerously late for issuing an entirely new CA
and changing both approved device trust bundles.

The existing root-controlled **TLS-only** Ops Watch consent now also governs
a strictly read-only finite-batch horizon check. The monitor reads only
`ca-public.pem` (public CA) and the 0600 root-owned
`presigned-batch/manifest.json`. It **does not read any private leaf key,
device identity token, SSH credential, or CA signing key**. It checks the
attested public CA DER SHA-256 and complete 14-slot/25-day public schedule
before calculating the smaller of the last leaf's expiration and public
CA expiration. No new listener, timer, provider or account is introduced.

The sanitized fixed incident codes are:

- `device_ca_batch_renewal_due` - at most 90 days before the end of the
  signed batch; arrange owner-approved signing and a staged client CA overlap
  **without assuming a retained old CA key**.
- `device_ca_batch_renewal_critical` - at most 30 days, critical; have a
  replacement CA, signed primary/fallback, and verified Windows/YFC trust
  migration ready before expiry.
- `device_ca_batch_expired` - the signed supply has reached its end. It
  is **not** cryptographic revocation and must not authorize bypassing TLS
  checks, hostname checks, or public WSS exposure.

With the actual signed batch ending **2027-10-24**, the first 90-day warning
would become eligible approximately **2027-07-26**, and the critical warning
approximately **2027-09-24**, subject to certificate exact UTC timestamps.
The implementation evaluates current public CA expiry too. A malformed
or unreadable protected manifest/CA produces `unknown`, never `healthy`;
previously confirmed renewal incidents are retained during source outages.
A missing TLS-only owner consent or a legacy installation without a batch
remains `not_configured`, so old installations are not falsely alarmed.
Notifications are deduplicated by the existing Ops Watch state journal.

This monitor does not itself rotate a CA, execute an owner-signing container,
revoke a leaked certificate or prove Windows LocalService survival across
reboot. Any **compromised signer/CA** still requires a separate owner-approved
replacement CA and removal of the old CA from both clients only AFTER
strict genuine WSS acceptance under the new CA. Removing a trust anchor is
not the same as publishing a CRL/OCSP revocation.

## Emergency CA rollover - owner-controlled, two distinct threat cases

No old CA private key remains. **A signed CA cannot be renewed or used to sign
a CRL after its signing key has been destroyed.** Revocation in the current
Python SSLContext is not implemented via CRL or OCSP. Removing an old CA from
*every* client trust store is a separate trust-retirement operation; removing
one leaf file on the server is not cryptographic revocation.

**If only one service leaf private key is compromised:** determine whether a
different already signed certificate is valid **at the current UTC time**, has
a separate unexposed key, a matching localhost SAN/serverAuth and the approved
CA chain. If no safe currently valid leaf exists, fail closed; do not select
a not-yet-valid future certificate, nor silently restore a leaked key. Stage
and switch using the existing pointer transaction, verify exact live TLS and
both genuine client heartbeats, and quarantine the compromised generation.
Keep the restricted SSH/loopback boundary; this is not a CA compromise.

**If the CA signing key or its integrity is compromised, or the finite series
cannot be renewed:** the old CA may no longer be safe as *any* trust anchor.
This requires an independent, explicitly owner-approved new CA. The previous
one-time Docker signer consent does not permanently authorize unattended
CA issuance, nor an always-on signing service.

1. Authorize the new short-lived CA custody model and issue new distinct
   primary and rollback leaves from owner-approved CSR public keys. Never
   send signing keys, device tokens or SSH private keys to GitHub/ChatGPT.
2. Independently attest the new CA public DER SHA-256, both new leaf chains,
   DNS:localhost, serverAuth, validity and exact matching protected server
   private keys. Do not reuse the old compromised issuer.
3. Back up both client configs with their native ACL/owner protection, and
   install **old + new** public CA trust on the already registered Windows
   and YFC clients. Verify unchanged device IDs/tokens, TLS hostname
   verification and SSH pinned known_hosts. Windows LocalService ProgramData
   needs a separately authorized elevated administrator; the user-profile
   bundle alone is not equivalent. Without that authority: **NO_GO**.
4. Stage a valid new-CA **rollback** certificate and a separate new-CA
   primary. Plan a maintenance cutover with old service rollback explicitly
   forbidden when the old CA is compromised. Do not disconnect both clients
   before a verified route for each exists.
5. Switch only the loopback WSS service, prove exact new-CA TLS peer identity
   and *fresh authenticated heartbeat* from both real clients. A local
   openssl/SSL handshake alone is not sufficient.
6. Atomically retire the old CA from **all** client trust bundles, including
   protected Windows LocalService state, after new-CA proof. Reconnect and
   verify both clients **again** under new-only trust, without CERT_NONE or
   disabling check_hostname. A compromised CA cannot remain a trusted
   fallback; retain only independent new-CA rollback.
7. Update the owner-pinned batch public CA fingerprint and separately approved
   automatic activation source through exact-HEAD CI, PR review, main CI and
   production CD. Never silently rewrite the old batch or allow two timers
   to run together. Preserve the old evidence and audit trail.
8. If any stage fails, use an explicitly approved incident isolation procedure,
   not automatic acceptance of the compromised CA. Report which real client
   proofs and native permissions remain NOT_VERIFIED; leave #346 open.

This runbook is a **prepared safety procedure, not an executed emergency
reissue**. The absence of an online CA signer is intentional. The 90-day
batch-runway warning is the point to schedule the ordinary new-CA rollover,
not authorization for the monitor to perform it.

## Custody, revocation and emergency boundaries

The private CA key remains OFFLINE. Only owner-signed, pre-staged service
certificates can be activated unattended. There is no CRL/OCSP or online
revocation responder in this pilot; revoked identity rejection and emergency
CA replacement are **not** operationally verified. Before accepting a revoked
certificate policy, the owner must approve a separate offline-signed revocation
procedure and test both clients. Never imply that an expired or removed leaf
has been cryptographically revoked.

If the legacy self-signed pilot identity expires before trust-bundle overlap
is proven, its listening process does **not** establish a valid client TLS
connection. Do not assume existing heartbeats can be used for the migration
preflight. Prepare an owner-approved, out-of-band distribution of the public CA
to both existing enrolled clients, verify strict CA+hostname TLS checks on
Windows and YFC **before** the leaf switchover, retain their device IDs and
secrets, and prove rollback in the approved maintenance window. Until both
clients' trust can be verified, the expired pilot is an operational incident,
not an authorization to replace live certificates or loosen verification.
