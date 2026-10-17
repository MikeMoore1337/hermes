# H-15 Desktop Commander integration - #275

Status: implementation prepared; remote collector and local MCP NOT activated.
Windows alternative tracked separately in #276. Existing #271 Codex scheduler is not
extended with remote-device jobs (its owner grant schema forbids that scope).

## Verified facts (17.10.2026)

- ChatGPT connector: remote quota 0% remaining (10,003/10,000 in web UI).
- list_devices: vps1777112993 and DESKTOP-U6JEQP9 online; vps1789630393 offline.
- Both online devices replied to ping; BOTH start_process calls denied due monthly usage.
- A device's Online/ping is neither OS tool authorization nor execution admission.
- who_am_i reports remaining percentage only, not authoritative used/limit/reset date.

## Architecture and authentication

Control Center serves read-only /api/providers/desktop-commander and a separate
client-side widget. The endpoint reads only /var/lib/hermes-desktop-commander/status.json.
Data have a 15-minute TTL and exact schema; unexpected fields, credentials,
device IDs, raw upstream responses and email are prohibited.
Existing GitHub owner OAuth and proxy protection apply. Web server NEVER
contacts Remote MCP and retains its existing network deny-all sandbox.

Optional collector launches pinned mcp-remote@0.13.5 (MCP stdio bridge)
to https://mcp.desktopcommander.app/mcp using a SEPARATE owner-authorized OAuth
session for hermes-desktop OS identity. It calls only who_am_i and list_devices.
Existing ChatGPT connector authentication does not transfer to this MCP client.
First interactive OAuth login requires a separate owner action. The collector
is NOT enabled by this PR. If upstream auth/response contract differs, record
UNAVAILABLE; do not assume a working connection or silently retry provider calls.

Dedicated service/timer templates exist but installer does NOT enable them.
Before enabling, pin and preinstall approved Node/npm packages with controlled
cache for dedicated OS identity; verify exact version and OAuth compatibility.
Set writable HOME/npm cache for that identity, owner-only OAuth artifacts.
Snapshot permissions must allow hermes-control web group to read (0640).
Test sandbox, OAuth persistence and systemd dry-run before enabling production.
Never put OAuth credentials in the web process, GitHub, frontend or logs.

For a separately authorized manual read-only test under the isolated account:

    HERMES_DC_OWNER_AUTHORIZED=1 python3 -m control_center.desktop_commander --remote --output /var/lib/hermes-desktop-commander/status.json

No reset prediction, cloud quota bypass, account rotation, browser HTML scraping,
or pay-per-use fallback. Offline devices or stale snapshots are not healthy.
device_gate() is ADVISORY (DENY/DEFER/UNKNOWN/ALLOW) requiring separately
verified owner grant AND runtime execution evidence for ALLOW. Not wired into
Codex job execution (#271 remains unchanged).

## Local MCP - independent of Remote MCP quota

Official local config for a permitted MCP-compatible agent, pinned instead of latest:

    {
      "mcpServers": {
        "desktop-commander-local": {
          "command": "npx",
          "args": ["-y", "@wonderwhy-er/desktop-commander@0.2.52"]
        }
      }
    }

Run under separate least-privilege OS account with approved directories and
tool allowlist. Do not enable resident Hermes or arbitrary shell access to
YFC/Second Brain simply because an adapter exists. Existing H-01 and Codex
services unchanged. --probe-local performs tools/list only; no execution.

## Tests / delivery / rollback

    python3 -m unittest tests.test_desktop_commander -v
    python3 -m unittest tests.test_control_center tests.test_control_center_assets -v
    node --check control_center/frontend/public/desktop-commander.js

The widget is independent of React and is injected by Python server into HTML
with same-origin JS/CSS. Its static files originate from frontend/public and
are copied unchanged by Vite. The browser shows NOT_CONFIGURED/STALE/EXHAUSTED,
never claiming remote-execution readiness. No public write API added.

Rollback: disable optional timer if activated separately, restore previous
verified release via existing CD. Do NOT revoke unrelated owner devices/tokens.
