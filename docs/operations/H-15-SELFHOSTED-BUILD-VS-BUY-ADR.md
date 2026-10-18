# ADR H-15-001: fork existing MCP remote-control stack, do not rewrite

Status: **ACCEPTED FOR PROTOTYPE, NOT LIVE EXECUTION**
Date: 2026-10-19
Parent: #297; security gate: #371; owner-facing delivery: #372.

## Decision

Develop a **minimal, maintainable Hermes-specific fork** of
`shahidx0x/better-remote-commander` (BRC) at immutable SHA
`cbe511702dd0147650353c29ac6ab1decd8afda1`, preserving MIT
`LICENSE` and derived Desktop Commander `NOTICE`.
Reuse its MCP Streamable HTTP/OAuth2 PKCE, outbound WebSocket device
routing, session/process and file tools, and admin interface. Own
infrastructure; no hosted relay service or per-call vendor charges.

**Important distinction**: current Hermes source-only verified
BRC-patch workflow in #373 and #374 is NOT an independent GitHub fork.
A dedicated fork/source mirror and signed versioned build provenance are
the next build/publishing gate. Do not confuse a patching script or a
released Hermes source tree with a running remote-MCP gateway.

No security assertion follows simply from the source being open.
No shell/write permission on `windows-pc`, `linux-vps` or H-01 is
approved by this ADR. Existing read-only presence services remain
running and untouched.

## Comparison (source/README/license checked 2026-10-19)

| Candidate | License / immutable reference | Native multi-device relay & remote OAuth MCP | Local files, terminal, interactive sessions | Gap / decision |
|---|---|---|---|---|
| [Better Remote Commander](https://github.com/shahidx0x/better-remote-commander) | MIT + derived upstream NOTICE; `cbe511702dd0147650353c29ac6ab1decd8afda1` | YES; WSS agents, Streamable HTTP `/mcp`, PKCE, device approval, SQLite | YES; agent port of Desktop Commander | **SELECT**; 28 real MCP tools exposed in the isolated prepatch E2E, not proof of production readiness. Young project; security gaps enumerated below |
| [DesktopCommanderMCP](https://github.com/wonderwhy-er/DesktopCommanderMCP) | MIT; `f508e524469c26f6366e17dbfd3ee5a69d112127` | **NO self-hosted remote relay**; hosted `remote-desktop-commander` implementation proprietary | YES; most mature file/process core | Already upstream of BRC's derived core; for a single local stdio MCP use only. Rebuilding its multi-device relay would duplicate BRC |
| [slepp/ssh-mcp](https://github.com/slepp/ssh-mcp) | MIT; `37381ddc68a941b62ed8557dcbb5644dc3b6c5fd` | NO, local stdio SSH MCP; relies on SSH accounts and reachability | YES on SSH POSIX hosts | **Fallback for trusted Linux host tools only**; lacks out-of-box HTTPS OAuth remote MCP, user-facing device pairing, Windows agent and central dashboard |
| [MeshCentral](https://github.com/Ylianst/MeshCentral) | Apache-2.0; `029b7338ecfeeacc65da3b5a1a4cc069baeb2f65` | Multi-device management YES, native MCP/ChatGPT OAuth gateway NO | Browser remote terminals/files plus RDP/KVM | Mature backup if remote OS management becomes primary. MCP bridges exist, but an independently maintained connector adds security and integration scope; too heavyweight for our direct ChatGPT goal |
| [RustDesk Server OSS](https://github.com/rustdesk/rustdesk-server) | OSS self-hosted server, see independent upstream license before reuse | Remote GUI relay, not MCP API | Graphical desktop-oriented | Out of scope for file/tool calls directly from ChatGPT |

The commercial/hosted [Remote Desktop Commander](https://github.com/desktop-commander/remote-desktop-commander)
repository is **documentation and manifests only**, not the server's
reusable source. Do not reverse-engineer proprietary tokens or
reuse Desktop Commander OAuth credentials.

## Reproducible evidence already obtained

1. PR #373 exact-source audit and native upstream `pnpm build; pnpm test`
   PASS in isolated GitHub runner (OAuth PKCE, device pairing, MCP
   initialize/tools/list, `start_process`, revocation).
2. PR #374 changes the actual BRC dispatcher from a pinned source
   tree without changing owner machines. Rebuilt dispatcher and the
   complete upstream E2E passed. It removes remote policy mutation,
   third-party `tmpfiles.org` transfer tools and URL fetch via
   `read_file` until secure alternatives exist.
3. The BRC default `allowedDirectories: []` means unrestricted
   **file tool** access, and any command shell can bypass file-only
   allowlists. Upstream security documentation itself says a
   compromised AI session can control what the host user can do.
   Security is **not accepted** merely by a green test badge.

## Additional security controls before an owner production pilot

- **Remote MCP tool surface**: remove `get_config` (exposes security
  configuration) and `get_recent_tool_calls` (logs may contain secrets),
  as well as `set_config_value` (rewrites policy), remote URL fetch, and
  third-party file transfer. This remains a *defense-in-depth* filter:
  an authorized shell can still access any file visible to its OS identity.
- **OS boundary**: a separate non-privileged runtime identity per
  approved device/workspace, not root/Administrator/SYSTEM and not the
  current `hermes-presence-agent`/Windows LocalService identity. On
  Linux use a locked filesystem namespace/container and approved
  writable mounts only; no root filesystem, host sockets, secret volumes
  or network egress by default. On Windows use a dedicated unprivileged
  user/token, NTFS ACLs + process/job restrictions and deny access
  to user profile secrets and ProgramData presence state. If the
  required negative tests cannot be enforced, **do not activate shell**.
- **Gateway boundary**: HTTPS with stable owner domain, audience-
  constrained OAuth/PKCE/refresh, client and per-device revocation,
  device pause, audit without args/results/secrets, explicit device ID,
  no stale command replay after reconnect, per-call deadlines and
  response-size bounds, session quotas for *resource safety only*.
- **Dangerous actions**: separate approval for shell/write/delete/
  poweroff, no resident H-01 broad privileges. Enforce approvals in
  server/agent policy, never prompt text. Revalidate policy on
  every request and after reconnect.
- **Own file courier**: replace upstream `tmpfiles.org` with a
  self-hosted encrypted transfer store on Hermes VPS with expiry and
  disk quotas (no 3rd-party billable relay).
- **Safe tests**: escape via shell substitution, absolute binary path,
  Powershell/Node/Python, symlinks/junctions, filesystem mount
  namespace, cross-device routing, config mutation, token replay,
  arbitrary file upload/download, SSRF/DNS rebinding, process output
  exfiltration, invalid OAuth audience, compromised client session.
  Record actual denied calls, not tests that only grep source.

## Fork and deployment steps

1. Maintain Hermes hardening patches in source control, with a pinned
   upstream SHA and dedicated CI. Next fork/mirror into owner GitHub
   under separately approved scope, preserving NOTICE/mit license and
   not using moving `latest` image tags.
2. Replace the relay's remote tool registry with a server-side
   **immutable owner policy** plus independent OS-enforced sandbox.
   Keep existing local Desktop Commander core (don't reimplement
   terminal/file editing). First E2E uses **disposable paths** only.
3. Release relay in a dedicated container/service on **Hermes VPS**
   after checking YFC and Hermes resources and ports. No deployment
   into YFC production, no exposure of `/mcp` before real TLS/OAuth
   negative tests. Never reuse read-only WSS tokens.
4. Connect distinct restricted Windows and Linux remote-MCP agents
   with fresh IDs and grants; prove multi-device live read/edit,
   terminal session, logs and reconnect. Do not change the existing
   paired `windows-pc`/`linux-vps` presence-only agents.
5. Perform an **actual ChatGPT custom MCP** client call to the owner
   gateway. A functional `/mcp` does not guarantee plan entitlement.
   Official documentation states full custom-MCP write support is
   currently beta on Business/Enterprise/Edu; verify user's actual UI
   before promising Plus direct writes. Do not attempt to bypass
   client plan permissions. Keep a local stdio-MCP client path as
   optional fallback.
6. Only after real owner sign-off consider disabling hosted Desktop
   Commander. Preserve working rollback, telemetry and Ops Watch.

## Go/no-go

Current: **GO for forked development and isolated tests only**.
**NO-GO for production command execution**, full user filesystem,
YFC app/DB, vaults, Windows admin, shell exposed to the public,
new ChatGPT integration claims without live proof.

The success criterion is not another heartbeat check. It is an
authorized ChatGPT MCP call specifying a device and a safe test
workspace, modifying/verifying a disposable file, running a bounded
process, returning output, and proving that out-of-scope files and
commands are denied by the OS and policy simultaneously.
