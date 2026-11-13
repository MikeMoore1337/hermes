# H454 Stage 2A - inert Linux systemd preflight unit candidate

**SOURCE ONLY - NOT INSTALLED.** This unit is deliberately **not**
a native resident service. No Linux service, user, account, ACL,
manifest, token, network listener, WSS connection or owner original
filesystem action has been created by this change.

The source-only candidate generator
`scripts/h454_native_linux_unit_candidate.py` renders a single
`hermes-commander-native-preflight.service` **oneshot** systemd
unit based on one canonical, strictly validated existing
`h454-native-install-candidate-v1` manifest. It refuses a manifest
if its SHA-256 differs from the **trusted, independently provided**
exact manifest digest, or if it points to another target/source SHA,
writable mode, auto-start or a different service identity.

The renderer cannot install, enable, start, restart or stop a
systemd service. The output has no `[Install]` section, no
`WantedBy`, no `Restart=always`, no shell, no sudo, no useradd,
no Docker commands and no `ExecStartPre` or `ExecStop`.
It does not interpolate original Linux project paths into the unit.

## What a future operator would review

The unit's **only** `ExecStart` is a future
read-only configuration/root-FD preflight using
`scripts.h454_native_linux_runtime`, with:

- pinned source directory under
  `/opt/hermes-commander-native/releases/main-<SHA>`;
- fixed private config/manifest paths under
  `/var/lib/hermes-commander-native`;
- strictly validated target, source SHA and manifest SHA-256;
- dedicated `hermes-commander-native` non-root account;
- private service directory, no source or original-root mutation;
- `ProtectSystem=strict`, `ProtectHome=yes`,
  `NoNewPrivileges=yes`, empty Linux capabilities,
  `PrivateDevices=yes`, `PrivateTmp=yes`,
  `PrivateNetwork=yes`, `IPAddressDeny=any`,
  `RestrictAddressFamilies=AF_UNIX`,
  `KillMode=control-group`, CPU/memory/PID/time limits,
  namespace, kernel and filesystem protections.

### Kernel openat2 compatibility

The preflight command uses `--inspect-root-handles`, which opens
original-root directory handles through Linux `openat2(2)` with
strict no-follow confinement. The original Hermes VPS has shown that
`RestrictSUIDSGID=yes` blocks `openat2` at the systemd seccomp layer,
returning `ENOSYS` even for read-only `O_PATH` operations.

The rendered preflight unit now explicitly sets
`RestrictSUIDSGID=no` for its fixed non-root/no-login service identity,
matching the separately corrected live worker unit. This does **not**
grant elevated privileges or permit writes: `NoNewPrivileges=yes`,
empty capability sets, strict read-only system mounts, no networking,
private devices/tmp, the kernel handle-bound path policy and resource
limits remain required. Never replace `openat2` with a permissive
`open` fallback.

This is source-only: a pre-existing `hermes-commander-native-preflight.service`
is **not** replaced by a GitHub merge or by the normal Hermes source-only
deployment. The owner must separately approve a reviewed, exact-release
versioned update of the existing disabled unit, manifest and immutable
native source files. Do not overwrite legacy receipts or start a native
agent to test this fix.

**This is an intentionally offline preflight.** The generated unit
disallows all network egress and cannot act as an outbound WSS
native device. A future **separately approved** runtime unit will
need its own strict, minimal authenticated egress policy and a live
revocation channel. Do not weaken this offline unit simply to
connect to `/ws`.

Systemd controls in a text file do **not** prove they are supported,
installed or enforced by the actual owner VPS kernel and systemd
version. `ProtectHome=yes` may intentionally refuse an approved
future root under a home directory; do not silently relax it.

## Source-only invocation format

A future separate, non-root, owner-approved operator may render
the candidate from a protected existing manifest:

```sh
python3 -B -m scripts.h454_native_linux_unit_candidate \
  --manifest /protected/native/candidate.json \
  --target hermes-vps \
  --release-sha <exact-reviewed-main-SHA> \
  --manifest-sha256 <exact-reviewed-manifest-SHA256>
```

This is a **format illustration**, not an instruction to run on the
live VPS today. Its current purpose is to render the exact proposed
unit text for review. A valid candidate is not an installation
authorization. The existing GitHub source-only SSH `deploy`
channel does not have the authority to install it.

## Tests

```sh
python3 -B -m unittest -v tests.test_h454_native_linux_unit_candidate
```

Unit tests use synthetic manifests and a disposable local file
for the private manifest CLI. They verify exact source and manifest
digests, Linux-only targets, no broader original root, fixed service
identity, no autostart, no plaintext credentials or original paths,
required offline OS hardening, malformed/forged/duplicate JSON
rejection, and absence of host shell/command/file effects.

A green repository CI is **not** a native-host systemd validation,
kernel OS permission proof, or live ChatGPT/Codex acceptance.
Even `systemd-analyze verify` on a GitHub runner would prove only
syntax on that runner, not actual production isolation.

## Remaining mandatory owner approvals

1. Verify the **actual** original checkout paths, OS UID, effective
   systemd unit syntax, ACL/mount and resource controls on both
   Hermes VPS and YFC VPS via separately approved read-only
   host-bootstrap access (not the current Docker sandboxes).
2. Produce separate, trusted, restricted SSH install/rollback
   operator and a signed exact-SHA release, then obtain a
   **separate owner approval for each host** before writing
   any systemd unit or creating its service identity.
3. Provision native device credentials privately; test the existing
   Hermes BRC/WSS pair and authenticated MCP route without replacing
   either paired container unless owner approves a joint transaction.
4. Prepare Windows graphical installer, real approval UI, and
   independent ChatGPT and Codex 2x3 original-device positive and
   negative tests. Reboot/rollback require their own approvals.

Keep the paused/revoked Windows native identity unchanged, preserve
BRC/WSS rollback evidence and leave
[Issue #454](https://github.com/MikeMoore1337/hermes/issues/454)
**OPEN**. Native host installation and release are **NOT_RUN**.

Related:
[native host installation plan](h454-native-host-install-approval-plan.md),
[Linux runtime protected config](h454-native-linux-runtime-preflight.md).
