# Hermes Commander vs Desktop Commander: evidence-based parity matrix (#454)

**Status:** partial acceptance as of 2026-10-22. This is a record of
**observed** MCP calls, not a claim of full Desktop Commander parity.
Hermes BRC is an owner-hosted relay with sandboxed clients. The preexisting
Desktop Commander feature list is the *parity target*; its current backend
and mobile/device behavior were not re-tested in this matrix.

## Live proof legend

- **PASS:** actual named client invoked the capability on the named
  device and returned the expected result.
- **PARTIAL:** related live evidence exists but a required subcase is missing.
- **NOT TESTED:** no client/device live execution trace. CI unit/isolated
  OAuth tests do not substitute for end-user client acceptance.
- **GATED:** requires separate owner approval or an agreed maintenance
  window. Do not attempt in normal acceptance.

Evidence anchors:
[ChatGPT native workspace E2E](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6349129129),
[Codex native workspace + Git E2E](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6349223554),
[three-device ChatGPT acceptance](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6348244002),
[move/metadata tests](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6348279885)
and [isolated OAuth MCP candidate CI](https://github.com/MikeMoore1337/hermes/actions/runs/39821964343).
Production Docker cutover was approved by the owner and returned
`CUTOVER_PENDING_BOTH_CLIENTS_E2E`. Its backup and rollback image are
retained.

## Real clients × devices

| Capability | ChatGPT Windows sandbox | ChatGPT Hermes VPS sandbox | ChatGPT YFC VPS sandbox | Codex Windows sandbox | Codex Hermes VPS sandbox | Codex YFC VPS sandbox |
| --- | --- | --- | --- | --- | --- | --- |
| Paired online device discovery | PASS | PASS | PASS | PARTIAL | NOT TESTED | NOT TESTED |
| `list_workspaces` + `resolve_workspace(YFC)` | PASS | N/A (routes to Windows) | N/A (routes to Windows) | PASS | N/A (routes to Windows) | N/A (routes to Windows) |
| Read/write/edit one ephemeral sandbox file | PASS | PASS | PASS | NOT TESTED | NOT TESTED | NOT TESTED |
| Content search against ephemeral file | PASS | PASS | PASS | NOT TESTED | NOT TESTED | NOT TESTED |
| File move + metadata + cleanup | PASS | PASS | PASS | NOT TESTED | NOT TESTED | NOT TESTED |
| Start isolated process | PASS | PASS | PASS | PASS (Git command) | NOT TESTED | NOT TESTED |
| Process output + exit code | PARTIAL | PARTIAL | PARTIAL | PASS (Git verification) | NOT TESTED | NOT TESTED |
| Git origin, branch, tracked status | PASS (four worktrees via local resolver) | N/A | N/A | PASS (YFC) | N/A | N/A |
| Negative host private-key read | PASS (EACCES) | PASS (EACCES) | PASS (EACCES) | NOT TESTED | NOT TESTED | NOT TESTED |
| Non-root UID / no host Docker socket | PASS | PASS | PASS | NOT TESTED | NOT TESTED | NOT TESTED |
| Protected-path write policy | PARTIAL (platform blocked attempted call) | PARTIAL (platform blocked attempted call) | PARTIAL (platform blocked attempted call) | NOT TESTED | NOT TESTED | NOT TESTED |
| Multi-session interaction, cancellation and termination | NOT TESTED | NOT TESTED | NOT TESTED | NOT TESTED | NOT TESTED | NOT TESTED |
| Large/binary file behavior and size limits | NOT TESTED | NOT TESTED | NOT TESTED | NOT TESTED | NOT TESTED | NOT TESTED |
| Concurrent edits, conflict behavior, replay and timeout | NOT TESTED | NOT TESTED | NOT TESTED | NOT TESTED | NOT TESTED | NOT TESTED |

**Clarifications:** the `list_workspaces` endpoint describes four **projects
on the Windows sandbox**, not four mounted host folders and not separate
workspace catalogs for the two VPS agents. Evidence that a tool was shown
in `tools/list` during CI is not sufficient to mark a live client PASS.
The Codex Git verification was initially refused by Git's `dubious
ownership` protection; using temporary
`git -c safe.directory=/workspace/projects/your-fitness-coach`
allowed read-only verification without changing persistent Git config.
`git fetch` was not run; remotes' latest HEADs remain unknown.

## Remaining Desktop Commander replacement gaps

| User goal / parity dimension | Hermes status | Required next acceptance |
| --- | --- | --- |
| Project selection without memorizing `deviceId` | PASS for four allowlisted sandbox clones via native tools in both clients | Expand catalog only through separately approved onboarding |
| Original Windows filesystem / native process access | GATED: sandbox-only by design | Owner provides exact allowed directories/operations; never auto-mount a whole drive or private vault |
| New-project onboarding with safe conflict handling | OPEN (#455) | Design, visual approval, backend authorization, negative E2E |
| Per-device diagnostics and actionable recovery | OPEN (#455) | Freshness, offline/auth/stale distinction; no browser RCE |
| Reboot/reconnect without another registration | OPEN (#445) | Maintenance-window Windows reboot/login evidence |
| Cross-client 2 × 3 complete functional parity | PARTIAL | Real Codex calls on Hermes and YFC sandboxes, plus edge cases |
| Cost and isolation | Owner-hosted, no mandatory paid vendor relay | Model usage and host resource limits still apply |

## Release policy

Keep [#454](https://github.com/MikeMoore1337/hermes/issues/454)
**OPEN** until the owner accepts the outstanding full-parity criteria.
No new Docker deployment, CLI authorization, broad host grant, reset,
forceful repository clean-up or unsafe fixture generation is implied by
this document.
