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
