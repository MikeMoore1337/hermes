# H454 Stage 2A - reproducible, read-only Linux native source bundle

**State: SOURCE ARTIFACT ONLY. No owner-host installation or runtime activation.**

The owner accepted a future GitHub Actions + restricted SSH installation
*method* for Hermes VPS and YFC VPS. The current GitHub source delivery SSH
account cannot install a host service, and there is no authorized bootstrap
channel for native systemd agents yet.

This change adds:

- `scripts/h454_native_readonly_bundle.py`: deterministic tar.gz builder
  and independent bounded archive/receipt verification, using only ten
  predeclared regular Git blobs from an **exact HEAD SHA**.
- `.github/workflows/h454-native-linux-source-bundle.yml`: manual,
  read-only GitHub Actions workflow to build one source candidate for
  either `hermes-vps` or `yfc-vps`. It requires that the selected
  revision equals current `main` and that exact-SHA repository and
  Control Center UI checks are successful. All GitHub token permissions
  are read-only.
- `tests/test_h454_native_readonly_bundle.py`: disposable synthetic Git
  fixture and tar/receipt negative tests, including tampered or oversized
  archives, forged approvals, invalid modes/symlinks and untracked secrets.

## Archive contents

The package contains **source only**, not a privileged installer.
Exactly these modules and one manifest are permitted:

| Selected component | Purpose |
| --- | --- |
| `device_fabric/__init__.py` | Python package |
| `device_fabric/native_effect_grants.py` | Shared path validation contract |
| `device_fabric/native_install_preview.py` | Immutable install candidate policy |
| `device_fabric/linux_native_files.py` | Kernel `openat2` read-only handles |
| `device_fabric/linux_native_search.py` | Bounded source search |
| `device_fabric/linux_native_read_dispatch.py` | Exact read-only tool requests |
| `device_fabric/linux_native_outbound.py` | Dormant existing BRC/WSS wire client |
| `scripts/h454_native_install_preflight.py` | Local private-candidate preflight |
| `scripts/h454_native_linux_runtime.py` | Local preflight and injected API only |
| `scripts/h454_native_linux_unit_candidate.py` | **Disabled, offline** systemd unit text renderer |

`device_fabric/linux_native_process.py`, `linux_native_create.py`,
`native_owner_issuer.py`, `native_effect_admission.py`, their
private signing/replay state and any host secrets are NOT bundled.
No source outside this allowlist is accepted. The bundle includes no
Python interpreter, no `websockets` installation, no signed keys, no
`systemd` installed unit and no running service.

The generated tar members are regular files, mode 0444, uid/gid 0,
mtime 0 and are sorted deterministically. Verification bounds the
**decompressed** TAR stream to 3 MiB before calling `tarfile`, rejects
PAX/GNU extension headers and concatenated gzip streams, and checks
the fixed USTAR file records before reading member content. Git reads
the exact pinned HEAD blobs with replacement refs disabled
(`GIT_NO_REPLACE_OBJECTS=1` and `--no-replace-objects`), preventing
a local `refs/replace` from silently changing source bytes.
The archive contains
`h454-native-bundle-manifest.json` with target, exact source SHA,
individual SHA-256/byte sizes, `activation=DISABLED` and
`install_authorized=false`. Output files are placed exclusively
in a new private 0700 CI directory with 0600 file modes; existing
files are never overwritten.

The companion `h454-native-bundle-receipt.json` includes the
archive and manifest SHA-256, target and exact release SHA, and
`installation=NOT_RUN`. These are **checksums, not signatures**.
A future host installer must independently authenticate the artifact's
origin before trusting a digest. A person reading this receipt has
not approved host installation.

## Manual GitHub Actions source candidate

Workflow: **H454 native Linux READ source candidate (manual, no deploy)**.

The operator chooses `hermes-vps` or `yfc-vps`, provides the exact
current `main` SHA and starts the workflow on `main`.
The workflow checks the SHA again through GitHub, confirms successful
exact-revision repository/UI checks, checks out source without
persisted credentials, builds/independently verifies the archive and
uploads only the archive plus receipt as a 7-day artifact.

The release SHA is an operator-run security input, **not** a recurring
manual step for the user. Normal project onboarding should ultimately
use the existing Control Center owner UI.

In CI or a disposable test checkout, the source-only builder is:

```sh
umask 077
install -d -m 0700 "${RUNNER_TEMP}/h454-native-linux-offline"
python3 -B -m scripts.h454_native_readonly_bundle build \
  --repo "$GITHUB_WORKSPACE" \
  --out-dir "${RUNNER_TEMP}/h454-native-linux-offline" \
  --target hermes-vps --release-sha "$GITHUB_SHA"
python3 -B -m scripts.h454_native_readonly_bundle verify \
  --out-dir "${RUNNER_TEMP}/h454-native-linux-offline" \
  --target hermes-vps --release-sha "$GITHUB_SHA"
```

**These commands are CI examples, not instructions to run on an actual VPS.**
No `workflow_dispatch` task uses `ssh`, `sudo`,
`systemctl`, `useradd`, Docker socket, production credentials,
published host services or an owner-provisioned key. Artifact
creation on GitHub is not production deployment.

## Verification and limitations

```sh
python3 -B -m unittest -v tests.test_h454_native_readonly_bundle
```

Git test fixtures use a temporary repository, synthetic author,
untracked fake secret, regular files, Git blob replacement refs
and intentionally malicious symlink/executable Git objects. In addition,
a GitHub-Actions-only test packages the **actual checked-out HEAD** on
isolated Linux CI for both target labels, verifies both target receipts
and ensures the archives differ by target. It writes artifacts only to
a private temporary CI directory and does not upload or install them.
The validator
compares the exact Git commit, ignores uncommitted files, refuses
`refs/replace` injection, rejects archive changes even if an untrusted
receipt hash is recomputed, blocks extra members/symlinks/duplicates,
PAX headers and a highly compressed 16 MiB expansion bomb, wrong
target, forged install flags, group/world-visible output and
existing file overwrite.

No live Windows original root, Hermes VPS original checkout or
YFC VPS original checkout was accessed to build or test this module.
A passing source-bundle check is not evidence of service identity,
effective OS namespace, ACL, WSS pairing, authenticated consent
or native host parity.

Before the package can be installed, require independently verified
artifact provenance, an owner-approved and restricted **per-host**
forced-command bootstrap/rollback installer, exact original-root
inventory and OS sandbox, protected device credentials, trusted
existing Hermes MCP/WSS transport, a separate approval for the
specific cumulative source SHA and for each host activation.
Do not reuse `HERMES_DEPLOY_KEY` as admin or bypass an existing
BRC/WSS paired release pin. The old revoked Win32 native identity
stays paused.

**`HOST_INSTALLATION=NOT_RUN`, `NATIVE_HOST_PASS=NOT_RUN`,
`OWNER_AUTH_UI=NOT_IMPLEMENTED`, Issue #454 OPEN.**

See [native host install plan](h454-native-host-install-approval-plan.md),
[offline systemd preflight unit](h454-linux-native-systemd-preflight.md)
and [protected local runtime preflight](h454-native-linux-runtime-preflight.md).
