# Hermes #454 Stage 2A - pinned offline Linux websockets transport

## Goal

Make original Linux-native WSS readers import the same free Python
websockets transport on Hermes VPS and YFC VPS. Previously the source
bundle contained 13 Python files but not the third-party dependency;
the active systemd service could fail to import websockets, or load an
unreviewed system-level version. Mocked CI connectors did not prove
the real dependency was available.

Official PyPI universal wheel:
- websockets 17.2 (BSD-3-Clause)
- Filename websockets-17.2-py3-none-any.whl
- SHA-256 6aa59f0ef92e796b2db6f5f26550c4713c0e4036899fadf02f55e2ed4db0b7ae
- https://pypi.org/project/websockets/17.2/
- PyPI has publisher Trusted Publishing evidence for this wheel.

## Disposable CI only

The requirements.lock file pins the exact hash. GitHub Actions fetches
only the universal Python wheel with pip download --no-deps
--require-hashes, then checks the ZIP structure and package/metadata.
It must contain only websockets and its dist-info subtrees, no
symlinks, traversals, .pth Python hooks or native .so executables.

CI actually stages the verified wheel under an isolated temporary
directory and imports websockets.sync.client with Python site
initialization disabled. It compares every byte during rollback.
A downloadable CI artifact is source evidence only, not permission
to install a dependency on an original VPS.

## Future owner-approved offline host operation

After exact root/service/UID/original paths and source SHA acceptance,
an authorized independent original-VPS root TTY operator may run:

  python3 -B -m scripts.h454_native_linux_wheel install-offline
    --target hermes-vps|yfc-vps --release-sha EXACT_APPROVED_SHA
    --wheel OWNER_PRIVATE_ROOT_OWNED_FILE

The command above is illustrative: the real command uses one of the
fixed target names. It requires a separate root-console typed
confirmation; it does not accept any permission flag from MCP.
Host-admin must prepare the pinned wheel bytes in a root-owned mode
0600 file, verify official SHA and artifact provenance and review
the exact release before invoking it. No secret is sent to ChatGPT.

The only destination is
/opt/hermes-commander-native/deps/main-EXACT_APPROVED_SHA/.
The operator exclusively creates root-owned immutable package files
(mode 0444). It never calls pip, downloads dependencies, creates
users, starts/enables services, changes system Python or opens original
project files.

Rollback-offline requires the exact original wheel/target/SHA, checks
every present file, its content and permissions, refuses symlinks and
unexpected members and removes only that exact dependency tree.
It preserves different releases and original project files.

The systemd unit pins PYTHONPATH to this exact source-SHA directory,
asserts that websockets/sync/client.py exists and mounts this directory
read-only. The Linux worker independently denies a global pip or
other-version import, even if someone replaced PYTHONPATH.

## Limits

A PyPI wheel fingerprint is not a signed Hermes release or host
installation approval. Original Linux UID/service/mount/network/egress
proof, fresh BRC pairing, original owner-approved roots and genuine
ChatGPT + Codex 2x3 host E2E remain mandatory.

Until then:
VPS_NATIVE_WHEEL=NOT_INSTALLED
VPS_NATIVE_SERVICE=NOT_STARTED
ORIGINAL_HOST_E2E=NOT_RUN

Issue #454 remains OPEN.
