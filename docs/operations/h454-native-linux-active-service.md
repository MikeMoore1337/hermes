# Hermes #454 / Stage 2A - live Linux native READ systemd service

**Implementation status: a real single-session worker and a hardened systemd
unit renderer, NOT deployed on either owner VPS.** It is not another MCP
server. The existing owner OAuth BRC relay, accepted READ-only native
toolset and Linux openat2 kernel handles are reused.

## Architecture (no privileged agent)

The new scripts/h454_native_linux_service.py is the executable entrypoint
for a dedicated unprivileged hermes-commander-native Linux account. The
previous scripts/h454_native_linux_runtime.run_once already contains
the actual handle-bound original-file READ/WSS wire implementation.

The --run-once command only accepts the exact target, Git SHA and manifest
digest from a trusted root-owned systemd unit. The original project roots,
device ID and bearer are loaded ONLY from the restricted private files
/var/lib/hermes-commander-native/manifest.json and device.json after
independent source SHA and digest validation by the existing runtime.
No arbitrary path, token, device ID or authorization flag can be supplied
via command line or an MCP tool call.

Before a network import or socket connection:

1. The process must run on genuine Linux with the existing dedicated
   non-root/no-login UID/GID. UID/GID cannot be root or a Docker label.
2. Kernel /proc/self/status must prove NoNewPrivs=1, Seccomp=2, no
   effective/permitted/bounding/ambient capabilities and identical
   real/effective/saved/fs UID/GID.
3. Kernel /proc/self/cgroup must identify the exact genuine
   hermes-commander-native.service systemd cgroup; an interactive shell
   or foreign Linux/Docker container is refused.
4. Verified systemd manager properties must confirm strict read-only OS
   and home protection, private devices/tmp, denied setuid/namespaces,
   empty capabilities, IPAddressDeny=any plus only two pinned public
   IPv4 /32 egress addresses. Owner must independently verify the
   actual BRC relay A-record IP and DNS resolver; addresses MUST NOT
   be guessed or inferred from Docker networking.
5. Existing original-root openat2 reader must use the exact owner-reviewed
   manifest root handles, no symlink/path traversal, read-only calls.
6. The BRC authoritative status endpoint must show the current device
   bearer for the same owner/native ID is ACTIVE and not paused. Missing
   endpoint, wrong TLS peer, timeout, rotation or revocation refuses
   the whole session and each subsequent READ call.
7. The websockets.sync.client.connect dependency is imported lazily,
   after all required checks. It preserves TLS hostname validation and
   owner bearer headers from existing linux_native_outbound.py. Never
   open a raw/public /ws link without actual owner-approved relay ingress.

The service performs one bounded WSS session (up to 240 seconds and
16 READ calls) then exits successfully. Source-only unit renderer
scripts/h454_native_linux_active_unit.py uses Restart=on-success with
90-second delay, never restart failed/unauthorized sessions. The
unit has a real [Install] section for later owner-approved boot enable,
but it is NEVER installed/enabled by code merge or GitHub CI.

## Exact egress configuration

The future owner must explicitly approve, for each VPS:

- The actual source SHA, private manifest SHA, source archive SHA-256 and
  separately verified provenance.
- The original Linux project roots (real host directories, not sandbox).
- One or two separately verified public relay IPv4 /32 addresses for
  the single pinned WSS hostname. The owner must review both when DNS
  returns two Cloudflare A-records; there is no wildcard egress.
- Exactly one DNS IPv4 /32: a public resolver, or **only** 127.0.0.53
  when the owner has verified the original host uses systemd-resolved's
  local stub (as on Hermes VPS). Other loopback, private, multicast and
  link-local addresses are denied. IPAddressDeny=any remains enforced.
  For a stub, the upstream servers run in the separate resolved service,
  not inside the native agent's restricted cgroup.
- Resolve the hostname and confirm the actual WSS protocol through the
  installed restricted service before enabling boot start. Cloudflare A
  records can change; fail closed and approve a fresh release or unit if
  these pinned /32 entries no longer match. TLS-over-TCP alone is not
  proof of authenticated BRC pairing.
- Dedicated service UID/GID and root-owned systemd unit/command path.
- TLS certificate verification, owner-authenticated new-device pairing,
  live revocation route, no access to another user's original projects.
- A pinned, approved websockets Python library available to this service.
  Do not use an arbitrary global pip package or silently download deps.

Use render_active_unit(...) from a trusted operator to preview the
target-scoped service text, have the owner approve its exact content,
then independently install with root privileges and protected rollback.
The prior Linux disabled preflight installation operator must NOT be
misrepresented as installing this active service. Real systemd service
installation and account/pairing provisioning are still owner actions.

## Test evidence and limits

A disposable Linux GitHub runner executes the new Python contract tests,
renders real systemd syntax and runs systemd-analyze verify. Tests
check token/session denial, real cgroup/capabilities/hardening refusal,
wrong user, alternate paths, broad destination IPs, tampered source,
and correct integration with the existing bounded read dispatcher.

These are source and CI sandbox assertions, not original-host acceptance.
No BRC/WSS production route, native service identity, private keys,
owner VPS original folders or files are touched by this PR. The
Win32 native SCM + MSI still requires separate signed/owner host
activation. Hermes Issue #454 stays OPEN / RUNTIME_NO_GO.

## Release-scoped offline websockets 17.2 dependency (2026-11-11)

The real native Linux WSS worker imports websockets.sync.client. To avoid
accidentally trusting a mutable system/global pip package, the unit now pins
PYTHONPATH to /opt/hermes-commander-native/deps/main-<exact source SHA>
and requires the installed sync/client.py to exist before a start. The
worker checks that websockets 17.2 and both its __init__.py and sync client
load from the identical root-owned release dependency path, with no
group/other writable bits. A mismatch refuses BEFORE BRC WSS access.

scripts/h454_native_linux_wheel.py stages the SHA-256-pinned upstream
pure-Python universal wheel into that separate immutable folder without
pip/global site changes on the owner VPS. The operator is owner-root-TTY
gated and requires exact per-host release approval. Its rollback removes
only verified, unchanged staged bytes and never affects original source.
The wheel originates from PyPI; its source-code license is BSD-3-Clause.
The specific pinned archive is NOT a signature on the user's native host.

This does not imply installation, enablement, owner pairing or real WSS.
