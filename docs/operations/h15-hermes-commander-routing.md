# Hermes Commander: workspace routing and client acceptance (#454)

**Current state (2026-10-24):** the owner-authorized Hermes BRC Docker relay
is deployed with authenticated native MCP tools `list_workspaces` and
`resolve_workspace`. Their presence was verified via exact pinned OCI CI,
then by **real ChatGPT and Codex client calls**. Baseline 2-client ×
3-sandbox file/edit/search/move/Node isolation E2E PASS; additional
onboarding/recovery remains OPEN. Original Windows READ-only E2E passed
separately and the temporary credential was revoked; no native host write/exec.

See [native MCP workspace contract and live evidence](h15-brc-workspaces-mcp.md),
including the exact source SHA, CI run, both client acceptance records,
sanctioned roots, per-command Git safe.directory handling and remaining gates.

## Workspace registry and trust boundaries

`deploy/h15/workspace-registry.json` allowlists four public sandbox clones:
Hermes (`main`), YFC (`master`), Second Brain (`main`) and
AI Development Toolkit (`main`). The native relay tools resolve aliases
using the authenticated user's currently paired device list; the selected
Windows sandbox must be unique, online and not paused. The tool returns
`git_verified=false`. The caller must still verify actual origin, branch,
HEAD and clean working-tree status **before any write**.

`scripts/h15_workspace_router.py` remains a separate *read-only local
verification aid*, not an additional MCP tool or authorization boundary.
It checks Git origin, branch, repository SHA and unsafe/missing paths.
In a disposable exact-source checkout, it verified all four real existing
sandbox clones; the standalone script is not guaranteed to be present in
old workspace clones. In the actual Codex client, YFC Git verification
passed using the returned path and a temporary
`git -c safe.directory=/workspace/projects/your-fitness-coach`.
The initial unqualified Git call was refused with `dubious ownership`,
which is expected for a different container UID; do not globally disable
this protection.

**Never** infer owner permission from an MCP catalog response:
`/workspace/projects` is a confined sandbox, not the owner's native
Windows checkout or either VPS host. No implicit mounts of drives,
Docker sockets, secrets, private Second Brain vault or production
databases. Keep branch/PR/review and rollback controls.

## Remaining issue scope

See the [evidence-based Desktop Commander parity matrix](h15-brc-parity-acceptance.md)
for the live 2-clients × 3-devices scope and remaining failure-mode tests.


The workspace discovery/resolution milestone is accepted for both real
clients. Other #454 goals remain in progress:

- Baseline 2-client × 3-sandbox file/edit/search/Node/cleanup PASS (2026-10-24).
  Remaining scope: extended binary payload, concurrent-write/replay/failure
  scenarios and runtime availability differences. See #454 evidence.
- Complete #455 authenticated metadata collector and onboarding; the
  owner already accepted the scoped Project Explorer layout, but no broader
  unapproved UI modification or host permission is implied.
- Verify device/agent reconnect, safe self-heal and Windows login/reboot
  recovery under an approved maintenance window (#445).
- Exactly four native original Windows folders were approved for READ-only
  E2E, and the one-shot read agent is now paused with token revoked. Every
  future host command, write or re-enrollment requires a separate owner gate.

See [#454](https://github.com/MikeMoore1337/hermes/issues/454) for the
authoritative full acceptance criteria and linked E2E evidence.
