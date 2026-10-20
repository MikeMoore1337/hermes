# H-15 #346 - Private CA TLS rotation (source-only stage 1)

## Offline candidate preflight

The script scripts/h15_presence_tls_preflight.py validates a *candidate* WSS server
certificate against the owner's public private-CA certificate. It checks the
certificate chain, sslserver purpose, hostname (localhost by default), expiry,
matching private key, regular files and key permissions. It does not use the
CA private key, access the network, issue certificates, replace live files,
restart systemd, or revoke existing device enrollments.

Use it only in a private, owner-approved staging directory holding the
pre-signed leaf, its private key, and the CA **public certificate**:

```bash
python3 scripts/h15_presence_tls_preflight.py \
  --ca /path/to/approved/ca-public.pem \
  --leaf /path/to/staged/new-leaf.pem \
  --key /path/to/staged/new-leaf.key \
  --hostname localhost --min-valid-days 2 --root-owned
```

Only CANDIDATE_CERTIFICATE_PREFLIGHT=PASS is a positive check. A rejected
candidate prints NO_GO and a non-secret reason code, returning nonzero.
Never copy the key, device bundles or credentials into CI, Issues or ChatGPT.

## Stage 2 - explicitly NOT implemented or authorized

- Choose the CA custody and signing model. Keeping the CA private key offline
  avoids deploying a standing signing authority to the general Hermes host.
  It requires the owner to supply a newly pre-signed leaf before expiry.
  Fully unattended certificate issuance requires a separate isolated signer
  and explicit owner decision, not a silent CA key installation.
- Implement independently validated staged replacement, atomic activation,
  previous-good rollback, ownership and ACL checks, and restart *only* the
  loopback WSS presence relay after operator-approved staging.
- Verify both real Windows LocalService and YFC Linux client reconnections
  against the **same CA**. Test mismatched CA, expired and not-yet-valid
  certs, stale files, reboot/reconnect and rollback without CERT_NONE.
- Preserve Ops Watch expiry alerts and never silently replace CA trust and
  leaf identity in one transaction.

**Current status:** ROTATION_RUNTIME=DISABLED; Issue #346 remains OPEN.
