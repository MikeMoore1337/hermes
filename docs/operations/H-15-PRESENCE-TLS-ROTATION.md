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
- One pending candidate, an exclusive process lock, and a fsynced rollback
  marker prevent concurrency, accidental replays and unverified promotion
  after interruption. On failure the previous pointer and service are restored.
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
calls auto daily. If existing certificate expiry is more than three days away,
it returns ROTATION=NOT_DUE. When due, auto requires a single pending candidate,
changes one atomic pointer, restarts only the pinned presence service, checks
the exact new certificate over TLS and reports ROTATION=PASS. Failure restores
the original cert and service, reports ROTATION_ROLLED_BACK or
ROLLBACK_HEALTH_UNVERIFIED, and does not retry the failed candidate blindly.

A crash/power failure leaves a durable rollback marker, which auto/recover
handles BEFORE any subsequent promotion. Old generations remain for rollback,
not automatically pruned. Device TLS expiry and offline/recovery Ops Watch
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
