# H454 Stage 2A - protected local Linux native read runtime

**State: SOURCE-ONLY. No service, host activation, installer, device
enrollment, original-owner VPS access or production deployment.**

The native Linux WSS bridge and local `openat2` read dispatcher now have
a **single, composable, fail-closed runtime entrypoint**:
`scripts/h454_native_linux_runtime.py`. This brings their previously
separate source-level contracts into one prepared host-identity,
root-scope and one-session workflow. It does not register a Hermes MCP
tool or make the existing paired BRC/WSS proxy accept a new device.

## What is implemented

`load_local_runtime(target, expected_release, expected_manifest_sha256,
manifest_path, config_path)` loads exactly two private, same-directory
local JSON files under the dedicated, **non-root**
`hermes-commander-native` Linux account:

1. A source-only `h454-native-install-candidate-v1` manifest that pins
   `target`, exact approved release SHA, exact artifact SHA-256,
   service identity, `start_state=DISABLED`,
   `access_mode=READ_ONLY` and exact owner-reviewed Linux project paths.
2. A protected `h454-native-linux-runtime-config-v1` document with
   exactly `schema,target,device_id,token,url,release_sha,
   manifest_sha256,roots`. The device identity must match either
   `h454-linux-hermes-<hex>` or `h454-linux-yfc-<hex>` as appropriate.
   No arbitrary URL is accepted: it must match the current pinned
   `wss://hermes.mikemoore.top/ws` exactly. A real owner-paired bearer
   must be provisioned **outside the repository**.

The files must be regular, owned by the effective service UID, mode
0600, with one link, in a directory owned by that UID with mode 0700.
Symlinked files/ancestors and unexpected world/group-writable parent
hierarchies are rejected. Manifest bytes must match the exact
out-of-band pinned digest and approved release SHA. The runtime
configuration must repeat exactly the approved target and project/root
mapping. No client-provided host directory, requested permission,
`owner_approved` boolean or alternate BRC endpoint is permitted.

The `--preflight`-only CLI verifies this private configuration and may
optionally check actual original-root directory handles under the
current Linux identity. It reports sanitized counts, digests and
fixed statuses **without original paths, tokens or source file
contents**. Both prepared configuration object representations redact
secrets. Success explicitly reports:
`owner_authenticated=false`,
`os_isolation_verified=false`,
`native_host_pass=false`, `connected=false`,
`changes_applied=false`.

`run_once(prepared, connector, is_device_revoked,
is_os_isolation_verified)` is an **injected library API** for a future,
independently reviewed native service. It rejects missing or ambiguous
external isolation/revocation callbacks, checks a dedicated non-root
service identity and only then opens the owner-approved project root
FDs and invokes **one** bounded outbound BRC session. Handles close
on all paths. No activation or network capability is available through
the checked-in CLI.

**Important security limitation:** a caller-supplied callback returning
`True` cannot, by itself, prove kernel OS isolation. A real installer
must create and verify effective systemd sandboxing, ACLs, mount and
network egress restrictions, owner-paired credentials and a live
revocation provider. A Python closure is not a security boundary.
A real owner approval for exact Linux original roots is required
before this module is invoked on either original VPS.

## Verification (isolated synthetic only)

```sh
python3 -B -m unittest -v tests.test_h454_native_linux_runtime
```

Real Linux `openat2` fixture tests use disposable files in a private
temporary folder under the test runner's own home, and an injected
fake WebSocket. The suite checks positive private configuration and
exact manifest SHA binding, owner/service UID, canonical JSON,
duplicate/extra fields, wrong device/target/project, forged approvals,
mode/symlink denial, root-FD-only preflight, blocked revocation,
missing OS isolation and successful read-only BRC read with verified
SHA and no bearer/path leakage.

These synthetic tests **do not authenticate a real owner**, prove
systemd isolation, connect a production relay or verify an owner VPS.
No original Windows filesystem commands or writes are performed.

## Activation blockers remain

- A separately owner-approved native original-host runtime install
  channel for *each* VPS (not the existing `production-deploy.yml`
  source-only SSH command), verified host OS paths and systemd UID/ACL
  sandbox, protected transport keys and authenticated device pairing.
- Real revocation checks and an independently verified OS isolation
  callback tied to the service's effective kernel-enforced controls.
- Verified BRC/WSS existing relay support for a Linux-native device
  with exactly the advertised read tool catalog; the historic
  public `/ws` access was blocked. No unapproved proxy or
  paired-container cutover is permitted.
- Windows GUI installer, owner-authenticated approval UI for each
  write/execute effect, and genuine ChatGPT and Codex
  **two-client x three-native-device** acceptance and rollback.

Keep `NATIVE_HOST_PASS=NOT_RUN`, `HOST_INSTALL=NOT_RUN`,
`PRODUCTION_DEPLOY=NOT_RUN` and Hermes
[Issue #454](https://github.com/MikeMoore1337/hermes/issues/454)
**OPEN** until independently verified.

See [native Linux outbound protocol](h454-native-linux-outbound-wss.md),
[installation admission plan](h454-native-host-install-approval-plan.md)
and [native install manifest contract](h454-native-install-preflight.md).
