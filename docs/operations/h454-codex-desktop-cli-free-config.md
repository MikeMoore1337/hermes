# H-15 #454 — Codex Desktop Hermes MCP config without Codex CLI

This is an opt-in, owner-scoped **local Windows user profile** helper.
It does **not** launch `codex`, invoke any model, use credits, query
a paid API, fetch network content, log in with OAuth or open a socket.

Existing `deploy/h15/codex-hermes-mcp.ps1` already offers initial
configuration using `codex mcp add` and login, but the owner's
workflow prohibits Codex CLI and the script lacked a full config
rollback. This new helper **does not replace or invoke** that script.

Source: `scripts/h15_codex_desktop_mcp_config.py` (Python 3.11+).
Fixed target for an explicitly approved Windows host invocation:
`Path.home() / ".codex" / "config.toml"`.
Fixed server identity: `hermes`, URL
`https://mcp.mikemoore.top/mcp`.

Modes:

```text
--mode status      (default, no changes)
--mode install     (append only the fixed Hermes MCP entry)
--mode rollback    (remove only the exact entry that this helper installed)
```

No arbitrary target path, command shell or override URL is accepted
by the CLI. Linux CLI refuses mutating modes. The existing `.codex`
folder must already be present and not a symlink/junction.

**Safe workflow for the future native Hermes agent (not activated):**

1. Identify a genuine Windows user session and verify the Codex Desktop
   installation without reading tokens/chats. Use `status` first.
2. If a Hermes entry exists, **never take it over or rewrite it**.
3. Owner explicitly approves the one-person profile edit.
4. `install` validates TOML, appends a clearly marked Hermes MCP
   section, and creates a `.hermes-mcp-install.json` receipt with
   only before/after SHA-256 digests and whether the config existed.
   It does not copy secret-bearing TOML into a separate backup.
5. Restart Codex Desktop under the owner's control and verify actual
   MCP discovery and a harmless tool call, then explicitly handle
   normal official user OAuth in Codex Desktop. Do not infer success
   from the presence of the TOML entry.
6. On `rollback`, require the installed file's **exact expected
   SHA-256** and the original prefix hash; restore exactly the
   original bytes or remove only the newly-created config file.
   If the user changed any other config field since installation,
   refuse instead of discarding those changes.
7. Verify the Hermes entry is absent after rollback and other MCP
   entries survive unchanged. Existing independent Codex OAuth state
   is not automatically logged out or removed.

On interrupted install, the receipt can be safely cleared when
the original file still matches its recorded digest. The receipt
contains only hashes, never provider tokens. This is not a persistent
host permission grant; an authorized native agent and Windows OS ACL
constraints still need separate approval.

**Verification:** Python tests on Linux and real GitHub-hosted
Windows runner using *disposable temporary profiles*, no real Codex
process, original owner's Windows files or subscription. CI success
means the file helper passed, **not** native Codex Desktop E2E.

Issue links: Hermes [#454](https://github.com/MikeMoore1337/hermes/issues/454),
[#445](https://github.com/MikeMoore1337/hermes/issues/445),
[#276](https://github.com/MikeMoore1337/hermes/issues/276).
