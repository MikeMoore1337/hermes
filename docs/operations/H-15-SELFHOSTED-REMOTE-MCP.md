# H-15: self-hosted full remote MCP (owner goal #297; delivery #371 / #372)

## Product contract

**Owner request (2026-10-18):** independently host the equivalent of
`https://mcp.desktopcommander.app/`: ChatGPT reaches owner's Windows PC,
Hermes VPS and YFC VPS through a device-selectable MCP gateway, with remote
file read/write/edit/move/search, persistent terminal sessions, processes,
audited device management and OAuth. **No vendor monthly relay-call quota**.
Do not misrepresent VPS compute, ChatGPT plan/tool limits, or model/API
quotas as unlimited.

The existing `device_fabric` WSS service and Windows/YFC background agents
are **presence-only**, not command executors. Their stored SSH keys/WSS
enrollment remain untouched. Nothing in this document grants operations,
starts a public listener, upgrades the device agents or enables shell for
the H-01 resident agent.

## Candidate / build-vs-buy decision

- Candidate: MIT `shahidx0x/better-remote-commander`, pinned immutable
  source commit `cbe511702dd0147650353c29ac6ab1decd8afda1`.
- Verify original `LICENSE` and `NOTICE`, including the derived MIT
  Desktop Commander core attribution, on every provenance test.
- Upstream claims: 24 agent tools, outbound WebSocket clients,
  OAuth PKCE + dynamic registration, MCP Streamable HTTP `/mcp`,
  SQLite device registry and auditing, admin page, pairing/revoke.
- **Not production-approved**: upstream is young and unreviewed at the
  depth required for shell access to personal and production machines.
  Do not `docker compose up`, `npm install -g brc-agent`, publish a
  domain or open firewall rules yet.
- Reuse/fork upstream only after evaluating actual tests and applying
  Hermes-specific OS and gateway hardening. If critical issues cannot be
  isolated, implement our own bounded gateway instead of accepting them.

### Verified architectural risks, not merely hypothetical

1. Upstream exposes `start_process` and `interact_with_process`.
   A shell can execute programs that touch **any path available to the
   OS user**, even when `allowedDirectories` limits file-tool APIs.
2. `set_config_value` is exposed through the same tool dispatcher;
   file-policy configuration cannot be trusted as an immutable
   enforcement boundary until that tool is removed/gated for clients.
3. Upstream default `allowedDirectories: []` is not a proof of a
   restricted file policy. The admin password / OAuth consent protects
   identity but does not prevent a prompt-injected authorized session
   from running an unsafe shell command.
4. The upstream encrypted cross-device transfer uploads encrypted blobs
   to **tmpfiles.org**. Even with encryption this is a third-party external
   service with its own availability and usage constraints. Hermes must
   replace it with self-hosted transfer before claiming full independence.
5. Default Linux/Windows service installation is not equivalent to a
   dedicated, minimal OS identity or boot-time Windows LocalService.
   Never install a shell-enabled BRC agent as `root`, Administrator,
   LocalSystem, or inside the existing protected presence-service user.
6. Do not mount `/var/lib/hermes-device-fabric`, `/etc/hermes-agent`,
   `/root`, production YFC app state, private SSH keys, or Second Brain
   vault into a generic agent runtime. Different users/actions can be
   approved independently later.

**Strong policy boundary:** separate restricted OS accounts,
filesystem ACLs or container mount namespaces, no ambient write access
outside explicitly approved workspaces, agent-side immutable capability
profile, separate non-privileged terminal identity, short bounded
request deadlines and output sizes, no remote policy mutation.
Adversarial tests MUST demonstrate shell/Node/PowerShell cannot escape
to disallowed paths; a denylist of command words is NOT sufficient.

## Hermes source-only hardening applied to the pinned candidate

`scripts/h15_brc_apply_policy_patch.py` is a fail-closed, exact-signature
patcher. It removes `get_config`, `get_recent_tool_calls` (to avoid
exposing security policy internals and potentially sensitive historical tool
arguments), and `set_config_value` (to prevent remotely editing agent policy).
It also temporarily hides external
`prepare_file_transfer` / `send_file_transfer` /
`receive_file_transfer` calls until a self-hosted transport exists.
It refuses the `read_file(isUrl=true)` route to prevent direct URL/SSRF
reads from remotely authorized MCP clients. It preserves the *actual*
`start_process`, `write_file` and normal file tool implementations
for future OS sandbox testing.

The isolated GitHub CI checks the true rebuilt and patched dispatcher:
each denied tool must be absent from `listTools`/`hasTool` and yield
an error on direct `callTool`; external URL reads must be denied;
approved process and file tools must remain. It then exercises the
upstream full OAuth/MCP/agent tests on the patched source. None of
this makes the host OS account a secure sandbox or authorizes
production execution.

### Pinned relay WebSocket device-token hardening

The original BRC 2.0.2 relay accepted `/ws?token=<device-credential>`
when an Authorization header was not provided. Credentials in URI query
strings can leak to HTTP/reverse proxy access logs. The original device
agent already sends `Authorization: Bearer`, so the fallback is unnecessary.

`scripts/h15_brc_harden_relay.py` pins and changes the exact upstream
`packages/relay/src/app.ts` source signature to refuse any
`?token=` parameter, even with a valid Bearer header, and accept only
a valid header. This patch is fail-closed on source drift. The native
`scripts/h15_brc_relay_ws_e2e.mjs` starts a real compiled BRC relay
on loopback with scratch SQLite and test-only credentials, verifies
that query-only, query+Bearer, missing-header and invalid-header
handshakes all fail, and verifies that a valid header-only agent WSS
handshake succeeds. It then runs full patched upstream agent+OAuth tests.

Do not activate this relay publicly or on existing owner devices:
this closes one token transport leak, **not** the mandatory OS shell
sandbox or browser CSRF/replay gates.

### Linux OS sandbox proof (disposable CI only)

`scripts/h15_brc_sandbox_linux_e2e.mjs` invokes **actual rebuilt BRC
agent file tools and `start_process`** in a throwaway Docker container
with a non-root UID 65534, zero Linux capabilities, no-new-privileges,
read-only root and source mounts, only one writable disposable
workspace, no network, memory/PID/CPU limits and no production mounts.
The subprocess itself tests that it cannot mutate mounted BRC source,
read an unmounted owner-only host canary or `/root`, or establish
Internet egress; authorized workspace writes must still work.

The CI Docker image tag is used only for ephemeral negative tests,
**not** a pinned production deployment artifact. Future production
builds must be pinned by digest and have signed provenance. This
proves these specific Docker/kernel restrictions in GitHub Actions;
it does not prove equivalent Windows OS isolation or execution within
the real owner YFC VPS. Real shell execution remains owner-gated and
disabled by default.

### Independent MCP gateway policy against a malicious device

Agent-only filtering is not a sufficient trust boundary: a compromised
device can report any `tools[]` during WebSocket hello. The owner-side
relay must independently enforce the accepted tool policy on
**both** `tools/list` and `tools/call`, even for direct/unadvertised
calls. `scripts/h15_brc_harden_gateway.py` adds a fail-closed
immutable allowlist to the pinned BRC `mcp/server.ts` and
`mcp/invoke.ts` and a separate policy module. Sensitive config,
history, external transfers, future unknown tool names and
`read_file(isUrl=true)` are denied before forwarding to a device.
Standard file/edit/search/shell/session tools remain available only
within their eventual host OS sandbox.

The actual compiled `h15_brc_gateway_policy_e2e.mjs` uses an
intentionally untrusted mock device advertising blocked and unknown
tools and attempts direct calls that were never advertised. It verifies
zero forwarded denied calls, refusal of remote URL reads and that
legitimate calls still route with an audit event. This **does not**
by itself isolate the shell from owner filesystem or production
resources. No owner device is paired for command execution yet.

### Browser-owner mutation CSRF gate

The candidate relay uses a signed `SameSite=Lax` browser login cookie
for pairing approval, OAuth consent, device pause/delete, registered
OAuth clients and API-key administration. A signed cookie proves a
session but not the intent of a browser request initiated by another
site. For these **seven authenticated owner POST endpoints**,
`scripts/h15_brc_harden_browser_csrf.py` installs an exact same-origin
`Origin` guard with `Sec-Fetch-Site` rejecting cross-site requests.
Absent/foreign/null Origin fails closed. This changes native upstream
e2e's synthetic (nonbrowser) form POST fixtures to include the same
Origin header a real browser sends; it does not bypass production
policy.

`scripts/h15_brc_browser_csrf_e2e.mjs` boots a genuine compiled
relay on isolated loopback with throwaway SQLite and tests missing
Origin, foreign Origin, contradictory cross-site fetch metadata,
and successful same-origin browser mutation requests. OAuth/MCP
Bearer traffic is not incorrectly forced to send browser Origin.
No live browser cookies, keys or real devices are used.

This is protection against ordinary browser cross-site request
forgery, **not** protection against malicious JavaScript already on
the same origin, a stolen authenticated cookie, or prompt injection
through an authorized MCP client. HTML output encoding, OAuth client
consent, and per-action authorization still require their own tests.

### Windows native kernel ACL negative test (disposable CI)

`scripts/h15_windows_os_sandbox_e2e.ps1` registers and immediately
removes a temporary Windows Scheduled Task under
`NT AUTHORITY\\LOCAL SERVICE` on a disposable GitHub Actions
`windows-2022` runner. It creates separate NTFS ACL-protected
disposable private and source directories, a writable approved
workspace, and invokes a real child `powershell.exe` inheriting the
service token. The child must prove SID S-1-5-19, read the
read-only source, write only in its workspace, fail both reads and
writes under the private directory, and fail writes to the protected
source. The task and test data are removed in a `finally` block.

This verifies a **real** Windows token+NTFS boundary; it does not
prove containment of all possible system writable directories,
network egress, Windows user-profile junctions, or malicious native
binary behavior. A separate dedicated non-admin service identity,
host-specific ACL policy, and full patched BRC dispatcher tests
remain required before enabling command execution on the owner's
Windows PC. This CI never modifies the owner's real
`HermesDevicePresence` task or credentials.

### Reproducible owner-maintained source fork artifact

The isolated pinned-candidate workflow produces a downloadable CI
artifact `h15-brc-selfhosted-fork-source` with:

- `UPSTREAM_SHA`: immutable MIT BRC base
  `cbe511702dd0147650353c29ac6ab1decd8afda1`
- `hermes-brc.patch`: all reviewed modifications from the exact
  upstream source, including the newly added gateway allowlist
  module, relay WS Bearer-only, browser CSRF, agent tool reductions,
  and synthetic upstream e2e fixture updates
- `LICENSE` and `NOTICE`: original MIT license and derived
  Desktop Commander attribution, without relabeling authorship
- `PROVENANCE.json`, `EXPECTED_PATHS.txt`, and `SHA256SUMS`

CI performs `git apply --check`, applies the patch in an **independent
clean detached checkout**, compares the full binary diffs byte-for-byte
and validates the SHA-256 manifest, after native upstream/patched
OAuth+MCP, security and Linux OS sandbox tests have passed. This
allows the owner to create a maintainable fork or mirror without
hand-merging code or trusting a mutable package tag.

Rebuild from that artifact on a development machine only:

```bash
git init brc-hermes && cd brc-hermes
git remote add upstream https://github.com/shahidx0x/better-remote-commander.git
git fetch --no-tags upstream cbe511702dd0147650353c29ac6ab1decd8afda1
git checkout --detach FETCH_HEAD
(cd /path/to/artifact && sha256sum -c SHA256SUMS)
git apply --check /path/to/artifact/hermes-brc.patch
git apply /path/to/artifact/hermes-brc.patch
npm install --global pnpm@11.24.0
pnpm install --frozen-lockfile
pnpm build
pnpm test
```

**Not yet an independently hosted GitHub fork or a runnable production
image**. It is a reproducible, license-preserving patchset, not a
ChatGPT plugin, not a real Windows/YFC remote command enrollment and
not an OS security certification. The production relay image still
needs a pinned digest/SBOM and per-device sandbox signoff.

### First real OCI service artifact (ephemeral CI pilot, not production activation)

`deploy/h15/Dockerfile.brc-relay` builds **actual fully patched BRC
relay and shared packages** directly from the immutable MIT upstream
source checkout. Node 24 and pnpm 11.24.0 compile the entire project
using the upstream frozen dependency lock; the resulting container
retains original LICENSE/NOTICE and source attribution.

For this step the OCI image is **test-only** and must not be published
or deployed to owner devices: the mutable `node:24-bookworm-slim`
base has not been pinned to an immutable OCI digest, no SBOM has been
approved, and the cross-device command channel still requires owner
permissions and an OS sandbox for every agent. Image `EXPOSE 3000`
only documents the internal service port; it does not publish a host
port. The default `HOST=127.0.0.1` intentionally denies remote
connections inside the container until TLS/reverse-proxy routing is
explicitly approved.

The existing pinned candidate GitHub workflow executes `docker build`
from the **patched source**, runs the resulting real relay as UID/GID
65534 with no Linux capabilities, no-new-privileges, read-only root,
`--network none`, limited memory, CPU and PIDs, plus only two
temporary writable tmpfs volumes. The container never receives
owner-device tokens, production SSH keys or mounts.

`scripts/h15_brc_oci_relay_smoke.mjs` probes the live process:
fresh SQLite state, no registered device, correct Linux identity,
read-only application source, no host SSH or read-only presence
database access, unauthenticated MCP denied with HTTP 401,
OAuth metadata available, owner dashboard requiring login, and
cross-origin admin mutations denied. Docker also verifies no
published ports or external egress network. These are stronger
proofs than a successful `docker build`, but **not** a production
remote-MCP readiness verdict.

Security ownership remains strict: isolated relay is not a
shell isolation mechanism on paired endpoints. Do not enroll
`windows-pc` or `linux-vps` with command credentials merely
because the relay smoke passes. Windows and YFC presence-only
agents keep operating unchanged.

### Pinned OCI base image and component inventory

The evaluation-only image is now built from a **fixed Docker Official
Node 24 OCI manifest digest** in both stages:
`node:24-bookworm-slim@sha256:a5f4366e834695d5f363b920c104953a535d3a9864d1bdf74566a0ebe01daee5`.
This digest is an immutable pointer to the reviewed base (not a
guarantee that the base is free of vulnerabilities). Updating it
requires code review and exact-head CI; a mutable `latest` base is
not accepted. Production availability for each CPU architecture,
package CVEs and Node release support need a separate deployment
review.

The isolated CI generates a real CycloneDX 1.7 dependency SBOM via
pinned `pnpm@11.24.0 sbom --lockfile-only` and verifies the built OCI
image `docker inspect` contains the correct base, MIT license
attribution, upstream revision, non-root runtime identity and no
baked-in BRC admin/password/device tokens.
`scripts/h15_brc_oci_receipt.py` fails closed if any of those
conditions, SBOM contents, or exact upstream audit is missing.
The artifact `h15-brc-oci-source-and-sbom` contains
`sbom.cdx.json`, a checked `OCI_RECEIPT.json`,
`UPSTREAM_AUDIT.json`, `NODE_BASE_DIGEST`, and `SHA256SUMS`.

The CycloneDX inventory covers dependencies resolved by the pnpm
lockfile; it is **not an OS-package inventory or a complete container
image SBOM**. A separate image-layer scanner/SBOM, platform
compatibility check, CVE triage and cryptographically signed image
attestation are still required before publishing a release.
A sha256-manifest checks artifact integrity after download, not
authenticity of an unrelated mirror.

No image is pushed to a public registry, no new listening
socket is enabled on owner VPS and no remote device operation is
authorized by these reproducibility checks.

### Two-device live WebSocket routing proof (synthetic read-only agents)

The pinned candidate CI now starts the **actual compiled/patched**
BRC relay on a throwaway loopback port with empty SQLite, then
connects two independently authenticated synthetic WebSocket
agents advertising only a `read_file` fixture. It checks
`hello/welcome`, owner-specific device state and routed
`invokeTool` responses. With two devices, omitting
`deviceId` must be rejected; targeted calls must deliver
a distinct per-device reply without cross-device confusion.
Disallowed remote config tools must fail at the relay.
The owner's pause state must prevent a call, and a closed socket
must become offline and reject calls while remaining visible
in device inventory. Receipts include
`HERMES_BRC_TWO_WSS_AGENT_ROUTING_E2E=PASS`.

This demonstrates real network frames, registry state and internal
MCP routing **without enabling OS file reads or process execution**:
the synthetic agents never open files or run commands and no
OAuth browser client is enrolled by this separate test.
The existing full OAuth/MCP single-agent native E2E and
Docker Linux OS-shell confinement remain independent passing
checks. The future acceptance test must join the entire chain
OAuth → remote MCP tools/call → two OS-sandboxed live native agents,
then prove read/write/shell behavior only in disposable directories.
No owner device is affected by these CI fixtures.

### Reconnect / replay boundary for remote commands

The reviewed MIT BRC `DeviceHub` formerly tracked pending calls by
random request ID alone, without binding a result to the authenticated
WebSocket that received the call. If a device reconnected while a call
was running, the superseded socket could still complete that call,
update presence and leave old calls waiting for the full timeout.
This is a lifecycle correctness/security gap independent of OAuth.

`scripts/h15_brc_harden_reconnect.py` now patches the *actual exact-pinned
relay source* to bind pending request state to `(deviceId, socket)`,
reject pending work immediately on reconnect, disconnect or heartbeat
expiry, ignore foreign/old socket results and stale activity, and
reject duplicate `hello` on a single authenticated socket.
The patcher checks the original source signatures and makes **no**
partial writes on source drift. `scripts/h15_brc_reconnect_socket_e2e.mjs`
exercises the compiled `DeviceHub` against real pending Promises:
old-socket and foreign-socket forged result IDs are ignored; only the
correct live socket resolves; a stale pending call is rejected during
reconnect and close, and duplicate hello and expired heartbeat are
rejected. The full upstream OAuth/MCP regression suite and separate
real WSS two-device test must continue passing.

Limitations: a remote command already running on the old device
cannot necessarily be rolled back by the relay. Rejection means
the **result is no longer trusted**, not that filesystem side effects
have been reversed. Future operation IDs and dedicated destructive
action confirmation still require explicit owner approval.
No owner Windows/YFC device is paired or reconfigured by this step.

## Target deployment (not yet activated)

```text
ChatGPT / owner-selected MCP client
  | HTTPS OAuth 2.0 + PKCE, Streamable HTTP
  v
Hermes VPS: dedicated remote-mcp relay (not H-01; not presence daemon)
  | SQLite device authorization / client consent / audit
  | device_id scoped WSS, outbound from each user sandbox
  +----> Windows PC: restricted nonadmin agent (files/shell only in owner workspace)
  +----> YFC VPS: restricted nonroot agent (NOT YFC production dirs)
  +----> Hermes VPS: restricted nonroot agent (NOT H-01 secrets/state)

Existing Hermes presence SSH/WSS (38177/38178/38179): unchanged
Existing Desktop Commander hosted OAuth connector: unchanged until cutover
```

`/mcp` must have separately verified OAuth consent, audience/resource
binding and client token revocation. Public listener must not be exposed
until authorization and TLS/domain tests pass. The project currently has
only a 7-day pilot presence certificate; do not reuse it as a permanent
public MCP identity. Keep independent incident notifications in Ops
Watch and rotate production TLS per #346.

## Evidence stages

1. **Source-only discovery (#371):** run
   `python3 scripts/h15_remote_commander_candidate_audit.py
   --source-dir /PATH/TO/EXACT/PINNED/CHECKOUT`, with no secrets.
   It checks true Git SHA, MIT NOTICE, OAuth/Streamable HTTP, agent
   dispatch, audit, and important policy bypasses. Expected status:
   `SOURCE_PIN_VERIFIED`, `production_ready=false`,
   `live_execution=DENIED`. If source signatures change, fail closed.
2. **Isolated actual E2E (#371):**
   `.github/workflows/h15-remote-commander-candidate.yml` uses a
   disposable GitHub runner with no production secrets, checks out the
   pinned commit, installs its frozen dependency lock, builds,
   and runs the upstream real agent/relay/OAuth/multi-device tests.
   An upstream `pnpm test` pass is **not** a security acceptance.
3. **Mandatory negative acceptance (#371):**
   credentials denied; out-of-policy file reads and writes through
   direct file tools **and terminal** denied; test data survives;
   no agent root/Admin user; config mutation cannot expand access;
   concurrent request IDs, timeouts and reconnect replay denied;
   no unapproved file transfer; symlink/junction traversal denied.
   Cross-device data cannot be read by another device ID. Windows
   native runner + Linux native test coverage required.
4. **Owner-visible pilot (#372):** mount **disposable test directories
   only**, pair exactly two new remote-* identities (not presence
   identities), verify list/read/write/edit/search and one bounded
   subprocess, process stdout/interactive session/stop, multi-device
   routing, audit redaction, offline/reconnect, OAuth revoke.
   No user home or production YFC mounts by default.
5. **ChatGPT gateway integration (#372):** check **actual account UI**
   for Plugins → Add custom MCP server and enabled tool permissions.
   Connect only to an approved HTTPS/OAuth `/mcp` or an authorized
   Secure MCP Tunnel; verify actual tool calls with the intended
   client. Plan eligibility can differ from documentation/availability.
   An OpenAPI-based GPT Action may be a separate fallback on
   eligible clients, but is not equivalent to automatic MCP availability.
6. **Release:** existing pattern PR → exact-head CI → merge → exact-main
   CI → deployment of code only → explicit owner approval for
   per-device execution scopes → runtime acceptance. No hosted-service
   OAuth revocation before the replacement demonstrably works.

### Mandatory user-scope gate (first real command)

Before granting command execution: exact device IDs, allowed directories,
OS user identity, whether shell is read-only or write-enabled, path to
Hermes/YFC production, and irreversible actions require explicit owner
approval in the relevant issue. Never infer authority from
`ONLINE=True`. ChatGPT instructions alone do not establish or widen
an OS capability.

### Project separation and operational constraints

- Existing current device enrollment and `hermes-device-agent.service`
  continue sending read-only heartbeat.
- Existing Ops Watch monitoring and the YFC application remain running.
- No duplicate public `/mcp` ports or Cloudflare ingress changes until
  the owner confirms routing/hostname.
- No pay-per-call relay vendor. Hardware/network/LLM token limits and
  bounded deadlines for safety remain.
- Preserve upstream LICENSE/NOTICE in any fork or distributed image.

## Current disposition

`CANDIDATE_EVALUATION` only. No private device agent, new OAuth client,
production TCP listener or owner filesystem/process command access has
been activated by this work. Parent #297 remains open.
