# H454 Stage 2A - exact-version Hermes VPS disabled native migration

## Scope and owner-host baseline

This operator migrates only the **already installed, INACTIVE/DISABLED** native
systemd definition on the **original Hermes VPS** from its older source
`8a159e0ba2e575dcdb0a2c2fee9e8d5651065da4` to the independently
verified native source-bundle release
`e8887bfb7a04aaff9cbb91a1c46003fcd8d5347a`. This is a separate
privileged host change; merging this source does not install or activate it.
The new SHA refers to the validated **native package**, not the SHA of the
later merge commit containing this migration operator.

The owner original VPS recorded `H454_NATIVE_VERSIONED_MIGRATION_PLAN=READ_ONLY_COMPLETE`:

- Old manifest SHA-256 `fa3abc717c0dc211897941ebdb8f8a23a824c2369057ecd441edc7eafcd47062`,
  canonical READ_ONLY manifest with exactly one approved `hermes` root.
- Old preflight unit SHA-256
  `b036ab8858898b471f0102047833a1afb13635d05319173d0f7d043911213460`,
  loaded/inactive/static.
- Old active unit SHA-256
  `828e9f6993fbc5fdd8f8b2964c4f0cccc6008d6e2eb783c23ba750a7005129f2`,
  loaded/inactive/disabled.
- Old receipt digests `daf3dce38a17f4c6d2d478adadd36bb846931745fee79da9063f45bf6bac7e6b`
  (preflight) and `e8a780825f04d2ca4835075f75e1e20b1f76b9956c72016e5baffec8660b1c73`
  (active).
- Existing old release and dependencies present, `device.json` absent;
  actual DNS A records matched original `IPAddressAllow` rules.

GitHub [Hermes VPS source package #43490931901](https://github.com/MikeMoore1337/hermes/actions/runs/43490931901)
was independently verified, exact inner TAR SHA-256
`9263a72b746273240fdd0ea96c4d3256b86d3430ce532b54a139841a671afac9`.
The single official `websockets==17.2` wheel was verified at SHA-256
`6aa59f0ef92e796b2db6f5f26550c4713c0e4036899fadf02f55e2ed4db0b7ae`.
Owner already staged them under the private root-only directory
`/root/h454-native-stage/main-e8887bfb7a04aaff9cbb91a1c46003fcd8d5347a/hermes-vps`
and confirmed `H454_HERMES_NATIVE_ARTIFACTS_STAGED_AND_VERIFIED=PASS`.

## Operator: plan, install-off, rollback-off

Source:
`scripts/h454_native_linux_versioned_migrate.py`.
The operator requires Python modules from the previously installed trusted
owner-source release `82a51cc0d718e16e6d0be8869436359a06fc94b7`.
Its active-unit renderer is byte-identical in that owner source and the
`e8887bfb...` bundle HEAD. The old preflight generator is patched for
the single audited `RestrictSUIDSGID=yes` to `no` setting; its source
bytes are independently checked against the new verified package.

**First**, independently check the exact operator file SHA-256 and GitHub
source/provenance, then from the original VPS root console (not ChatGPT
Docker sandbox), run a strictly read-only preview:

```bash
set -Eeuo pipefail
cd /opt/hermes-agent-owner/releases/main-82a51cc0d718e16e6d0be8869436359a06fc94b7
PYTHONPATH="$PWD" python3 -B /root/h454_native_linux_versioned_migrate.py plan
```

Do not proceed unless the report is
`status=VERSIONED_MIGRATION_PLAN_PASS`, the old/new SHAs match this
runbook, the owner confirms exact two resulting unit SHA-256 values and
the runtime baseline is unchanged. The preview never writes or starts a
service.

**Only after separate, explicit owner approval** to replace the two
inactive native unit files and private manifest for the exact target,
new release and preview unit hashes, invoke:

```bash
cd /opt/hermes-agent-owner/releases/main-82a51cc0d718e16e6d0be8869436359a06fc94b7
PYTHONPATH="$PWD" python3 -B /root/h454_native_linux_versioned_migrate.py install-off
```

An interactive root TTY must type the exact challenge; redirecting stdin
or supplying a token in MCP parameters cannot grant approval. The operator
rechecks the old data after confirmation, uses an exclusive flock,
verifies the pinned bundle and wheel, creates only the new immutable
source/dependency directories, copies old manifest/units/receipts into
a root-private backup with readback, atomically replaces both unit files
and the manifest, reloads systemd, verifies *both remain inactive and
static/disabled*, and checks the BRC/WSS four-container snapshot is
unchanged. It preserves all old versioned source/dependencies and original
project files, writes no `device.json`, and does not issue credentials,
enable/start native services, install new accounts or modify Docker.

On a detected error, the operator attempts to restore the backed-up unit
and manifest bytes. A power loss between atomic replacements may leave a
mixed on-disk state. Do not enable the unit; the private backup is retained
under `/opt/hermes-commander-native/receipts/h454-migration-e8887bfb...`.
The `rollback-off` mode is an independently TTY-approved recovery that
accepts only **old/new pinned bytes**, verifies both units are inactive,
restores original SHA-pinned files and reloads systemd, preserving new code
and dependency directories for forensics:

```bash
cd /opt/hermes-agent-owner/releases/main-82a51cc0d718e16e6d0be8869436359a06fc94b7
PYTHONPATH="$PWD" python3 -B /root/h454_native_linux_versioned_migrate.py rollback-off
```

If rollback also returns `HOLD`, do not manually bypass its inode/hash
checks; keep the private backup and obtain exact incident diagnostics.

## Evidence and limits

- Syntax and focused regression tests:
  `python3 -B -m unittest -v tests.test_h454_native_linux_versioned_migrate`.
- A synthetic disposable original-source TAR + wheel simulation exercised
  plan, exact file swap, backup verification, restoration and tamper denial
  with mocked systemd/Docker and narrowed test-only Python imports.
  This simulation does **not** prove original-host systemd acceptance.
- A generated script is NOT an approval and a verified package is NOT an
  original-host production installation. The operator is deliberately limited
  to **Hermes VPS**. Do not reuse it on YFC VPS, where the native host
  baseline/permissions have not been inventoried and separately approved.
- After disabled migration, **native pairing/activation, actual host
  original-file reads, revoked bearer checks, Windows service and the
  two-client x three-device E2E** remain separate tasks.
- No BRC/WSS restart, container/image replacement, deletion of rollback
  checkpoints, broad shell/write permission, or owner root widening is
  authorized by this source change. Keep Hermes #454 open.
