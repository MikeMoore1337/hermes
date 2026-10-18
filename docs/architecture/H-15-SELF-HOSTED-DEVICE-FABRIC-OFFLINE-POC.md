# H-15 #297: Self-hosted Device Fabric — offline spike

Status: **isolated proof of concept; NOT an operational multi-device relay**. Parent #297; Windows pilot #276. Existing read-only Desktop Commander #275 unchanged.

## Build vs buy, pinned source review (2026-10-18)

| Candidate | Exact SHA | License | Assessment |
|---|---|---|---|
| [Better Remote Commander](https://github.com/shahidx0x/better-remote-commander) | `cbe511702dd0147650353c29ac6ab1decd8afda1` | MIT with Desktop Commander MIT notice | Closest fit: paired Windows/Linux device agents, outbound WS/WSS, OAuth-enabled MCP relay, SQLite, audit, revocation. Young upstream, not live-tested in Hermes. Its agent offers shell/filesystem tools under the OS user's permissions; cannot be connected directly to H-01. |
| [Quota](https://github.com/magetsu002/quota) | `bb1e221fa2400a30971850ae78ad62f1833409a6` | QSAL-1.0, source-available | Good local MCP bridge; multi-device fleet/pairing and long-term license suitability not established. Default startup fetches and runs Desktop Commander. |
| This Hermes standard-library PoC | Hermes PR SHA | Hermes project license; no external source imported | Real local TCP streams, in-memory owner pairing/registry, read-only MCP JSON-RPC handler; intentionally no WSS, persistent agent, production MCP server, command tools or real device access. |

**Decision:** treat the pinned Better Remote Commander commit as *design reference* for a later production stage. Do not vendor, install or execute its Node/Docker packages in stage 0. If any upstream code is imported later, preserve LICENSE and NOTICE and review scope/permissions first.

## Implemented offline vertical slice

Module `device_fabric/offline_poc.py`: loopback-only `127.0.0.1` temporary port; no production unit or CLI. One-time pairing codes, random per-device tokens stored in memory as hashes; heartbeat, Online/Offline/last_seen, duplicate-socket refusal, explicit revoke, hard 4096-byte frame limit and bounded timeout. Only two MCP JSON-RPC handler tools: `list_devices` and `get_device_status`. File/process/write/execute calls always denied. No command queue/replay after reconnect; no OS commands or private files touched.

Reproduce from repository root, without Node/npm, provider OAuth, device credentials or VPS changes:

```bash
python -m unittest discover -s tests -p 'test_device_fabric_offline_poc.py' -v
```

Integration tests use two independent emulated devices on real loopback TCP streams: authentication, pairing replay/duplicate, spoofed identity, revoke, heartbeat, offline/reconnect, timeout, oversized/invalid frames, read-only MCP initialize/tools/list/call and denial of `start_process`/`write_file`. A local `ReadOnlyMCP.handle()` call is NOT yet a production stdio/WSS connector.

## Next acceptance gates

1. Isolated WSS/TLS relay, persistent device registry and credentials, owner pairing, per-device scoped audit and allowlist. Confirm pinned third-party candidate tests in sandbox before deciding whether to adopt or implement transport; don't pass broad shell privileges to any agent.
2. Dedicated device agent #276 with manual Windows and Linux owner pilots, outbound-only connections. Offline is valid; commands are never queued for later replay. No autorun or public ingress before scoped owner approval.
3. Owner-only Control Center GET/UI for Hermes self-hosted source; preserve the existing separate cloud Desktop Commander monitor. UI visual approval before live deployment.
4. Explicit permissions for file/process tools, real OS sandbox, separate revocation and negative tests. H-01 #33, YFC production and Second Brain private vault remain denied by default.

**Deployment boundary:** merging may deliver only an inert repository source snapshot using normal exact-SHA CI/CD. No new systemd services, ports, OAuth, production device connection or real tool execution are authorized by this offline PoC.
