# H-15 / #454: versioned project workspace resolver (stage 1)

This is a **development-only, read-only resolver**, not a new registered MCP
action, background agent, or shell privilege. It is a deterministic base for
future `list_workspaces` / `resolve_workspace` tools and the Control Center
onboarding screen. Never claim that merely merging it makes new MCP tools
appear in ChatGPT or Codex.

## Current approved locations

`deploy/h15/workspace-registry.json` identifies three already enrolled H-15
**Docker sandbox** devices and the four existing public-source clones on the
Windows sandbox. Only these roots may be resolved:

| Alias | Root | Branch | Scope |
| --- | --- | --- | --- |
| Hermes | `/workspace/projects/hermes` | main | sandbox clone |
| YFC | `/workspace/projects/your-fitness-coach` | master | sandbox clone |
| Second Brain | `/workspace/projects/second-brain` | main | public source only |
| Toolkit | `/workspace/projects/ai-development-toolkit` | main | read-only reference |

The resolver verifies the actual `.git/HEAD` and public `.git/config` origin,
rejects symlinks and arbitrary aliases, and returns fixed device identity,
approved path, access scope and canonical branch. It **does not** grant access
or infer online state. It never copies, clones, fetches, installs, modifies or
deletes project files.

## For MCP clients and future gateway integrations

1. Use real Hermes `list_devices` first, not a remembered device count.
   Compare the resolver's exact `deviceId` with one owner-authorized online,
   non-paused device. Unknown/changed identities and missing devices are
   **DENIED**, not guessed from the name.
2. On that known Windows **sandbox device**, run the resolver in the checked
   out Hermes source: `python3 scripts/h15_workspace_resolver.py resolve YFC`.
   `list` enumerates all four locally verified clones.
3. Route only to its returned `root`. For Git with a differently owned
   Windows bind mount, use `git -c safe.directory=EXACT_APPROVED_ROOT -C ROOT`
   **per invocation**, after resolving the trusted root; never use
   `safe.directory=*` or globally disable Git ownership checks. This solves
   the observed `dubious ownership` without broadening global permissions.
4. Before write/commit/PR actions, check the actual Git tracked status,
   branch, remote identity and project `AGENTS.md`; create a short-lived
   branch under the project's own GitHub Flow. Do not change Toolkit references,
   the private Second Brain vault, YFC production or host Windows original
   working copies by selecting a sandbox alias.
5. Fail explicitly when a clone is missing, origin/HEAD mismatch occurs,
   device is offline or the operation requires a permission not in the
   sandbox scope. A registry mapping is not an OS boundary.

The current user experience still includes a client tool call to
`start_process` with an actual device ID. A true **single-call ergonomic
`list_workspaces` / `resolve_workspace` MCP API** requires a separately
reviewed change to the pinned self-hosted BRC relay and live OAuth tool
catalog, followed by real two-client tests. Do not silently alias tool
descriptions, modify active relay images or provision new host mounts.

## Verification

```bash
python3 -m unittest discover -s tests -p 'test_h15_workspace_resolver.py' -v
python3 -m unittest discover -s tests -v
```

Acceptance includes synthetic wrong branch/origin, symlink, duplicate alias,
host path injection, other-device denial, and a **live** read-only inspection of
the four already approved Windows Docker clones. No model calls are needed.
Reboot persistence remains a separate deferred item in #445.
