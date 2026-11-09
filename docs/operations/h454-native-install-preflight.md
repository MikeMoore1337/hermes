# Hermes #454 Stage 2A: native installation preflight (source-only)

**Status: IMPLEMENTED AS SOURCE, NOT AN INSTALLER.** No owner host has been
modified or inspected by this PR. This source package never changes
Windows services, systemd units, local accounts, ACLs, registry entries,
mounts, tokens, devices, BRC/WSS images, or production state.

This increment is the first executable **read-only candidate admission
contract** for the [owner-approved installation channels](h454-native-host-install-approval-plan.md).

## Components

- `device_fabric/native_install_preview.py`: strict, canonical JSON
  candidate contract binding target host category, exact release SHA,
  immutable artifact SHA-256, service name/identity, DISABLED startup,
  READ_ONLY mode, and a bounded allowlist of original project roots.
- `scripts/h454_native_install_preflight.py`: local file-based
  syntactic check. It opens one private regular manifest without following
  its final symlink, compares pinned inode/size before/after reading, and
  prints **sanitized** JSON (no original absolute paths). Invalid manifests
  return a stable HOLD reason and a nonzero exit status.
- Optional `--verify-local-roots` calls the already-reviewed
  `LinuxNativeFiles` root-FD constructor under a *non-root*
  Linux identity. It verifies current directory resolution with pinned
  file descriptors and no-follow ancestors and closes those handles
  immediately. It never opens project file contents. This is **not**
  OS sandbox proof, owner approval or native host installation.

The manifest is an offline preview, not an approval token. It has no
`approved`, `execute`, `ssh_key`, `sudo`, `install`, or privileged
operation field; extra fields are rejected. Windows candidates require
**exactly** the five previously approved read-only original roots from
[the native Windows gate](h15-native-windows-approval.md), without
parent-folder widening. All proposed services start DISABLED and
READ_ONLY.

Linux candidate roots must be provided by a *separately authorized
read-only inventory on the actual original host*. There are **no
guessed** `/workspace/projects` values. Unsafe root, special paths
(e.g. `/root`, `/etc`, `/proc`, Docker socket), duplicate or
overlapping roots, symlink redirects and noncanonical path segments
are denied. A source-only lexical check cannot validate all bind
mounts, service filesystem namespaces or host-level ACLs.

## Private candidate contract

The candidate JSON must use ASCII `ensure_ascii=True`, sorted keys
and compact `separators=(",", ":")` with no trailing newline.
Its exact keys are:

- `schema=h454-native-install-candidate-v1`
- `target=windows|hermes-vps|yfc-vps`
- `release_sha=<exact verified 40-character lowercase main SHA>`
- `artifact_sha256=<actual verified package SHA-256>`
- `service_name` and `service_identity` pinned for the target;
  the Windows candidate is `HermesCommanderNative` under
  `NT SERVICE\HermesCommanderNative`; Linux is
  `hermes-commander-native.service` under
  `hermes-commander-native`
- `start_state=DISABLED`
- `access_mode=READ_ONLY`
- `roots`: 1-5 exact `{"project":..., "path":...}` objects;
  Windows requires precisely all five approved roots

This source-only manifest **does not** include an approval signature,
authentic owner identity, verified build attestation or OS privilege.
Never send the Linux original root names to GitHub job logs, PR
comments, or external models. Store real manifests on the original
host only after its separate owner-approved bootstrap.

## Running an operator preflight (FUTURE, not authorized by this PR)

Once an original-host read-only inspection is separately authorized
and a protected local manifest actually exists, a restricted Linux
operator could run:

```sh
python3 -B -m scripts.h454_native_install_preflight \
  --manifest /protected/operator/candidate.json \
  --target hermes-vps \
  --release-sha <exact-reviewed-main-SHA> \
  --verify-local-roots
```

This is documentation of a proposed invocation, **not** an instruction
to execute it on a production VPS now. The `--verify-local-roots` option
must **never** be invoked from the existing Docker sandbox against
guessed host roots. If the manifest is absent, symlinked, world-readable,
oversized or its metadata changes during read, the preflight denies.

A successful response contains `CANDIDATE_SYNTAX_VALID`,
`LOCAL_DIRECTORY_HANDLES_PASS` only when explicitly checked on Linux,
`original_paths=REDACTED`, and the mandatory flags:
`install_authorized=false`, `owner_operation_approved=false`,
`release_deploy_approved=false`,
`os_isolation_verified=false`, `changes_applied=false`.

A **passing source-only CI** cannot be used as a native install
authorization, as an independent OS sandbox attestation, or as
`NATIVE_HOST_PASS`. This preflight cannot create an account, install
a service, create keys or connect the Hermes MCP.

## Synthetic CI evidence

```sh
python3 -B -m unittest -v tests.test_h454_native_install_preflight
```

On Linux, tests exercise actual pinned kernel handles against
**disposable** directories, root/manifest symlink and permissions
denials, missing roots and non-root identity, no content reads,
sanitized CLI results, wrong target/SHA/service identity, five exact
Windows roots, owner approval injection and invalid/duplicate JSON.
No Windows original-folder execution or production host modification
occurs.

## Still required before real installation

- A **real graphical Windows installer**, reviewed publisher/build
  digest and user-approved UAC. No unsigned executable bypass or
  PowerShell archive fallback.
- A **new per-host, restricted SSH forced-command install operator**,
  manual GitHub Actions workflow, and proof of permitted bootstrap
  rights on BOTH VPS. The existing production source deploy command
  cannot be reused as an administrator shell.
- Actual owner authentication + exact one-operation consent UI,
  protected signing key provisioning, live Hermes MCP registration and
  device revocation; negative OS-access and process-cgroup tests.
- A distinct owner-approved exact cumulative source release SHA,
  exact host installation manifest and rollback for each device.
  Keep the paused/revoked Win32 identity and existing BRC/WSS network
  namespace and rollback pins unchanged.

**Issue #454 remains OPEN.** All three original-host live acceptance
statuses stay `NOT_RUN`; installing or activating a resident agent is
out of scope for this PR.
