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
