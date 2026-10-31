# Hermes BRC: native MCP workspace tools — live acceptance (#454)

## Delivery and evidence

The verified source release `bbf316d7887bc0bdabb871a065da7f2bf2a833b1`
was installed on the owner VPS via an owner-authorized transactional Docker
cutover. The old image, rollback container and SQLite backup were retained.
The pinned CI candidate [run 39821964343](https://github.com/MikeMoore1337/hermes/actions/runs/39821964343)
compiled the **relay-native** workspace tools and proved OAuth MCP tool
advertisement, owner-scoped routing and negative requests. This is not just
a stand-alone Python CLI patch.

Actual **ChatGPT and Codex clients both called** `list_workspaces` and
`resolve_workspace(project="YFC")` over Hermes MCP in fresh sessions on
2026-10-22. Recorded evidence is in [#454](https://github.com/MikeMoore1337/hermes/issues/454):
[ChatGPT](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6349129129)
and [Codex](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6349223554).

The MCP catalog has four public **sandbox** projects:

| Workspace | Branch | Approved root |
| --- | --- | --- |
| hermes | main | `/workspace/projects/hermes` |
| your-fitness-coach (YFC) | master | `/workspace/projects/your-fitness-coach` |
| second-brain | main | `/workspace/projects/second-brain` |
| ai-development-toolkit (Toolkit) | main | `/workspace/projects/ai-development-toolkit` |

The authenticated MCP tools select the unique online, unpaused
`H15 Windows permanent sandbox` from live user-owned device discovery.
They do **not** grant extra filesystem permissions, mount Windows-native
folders or reach either production VPS host. The returned
`git_verified=false` and `verification_required_before_write=true`
are deliberate: a catalog entry does not attest the current Git tree.

## Safe use in ChatGPT or Codex

1. In a fresh client session, call `list_workspaces`, then
   `resolve_workspace` with an approved alias (for example `YFC`).
2. Take the returned `deviceId` and `root`; do not guess them. Actual
   device availability changes. New tools may require the client to reload
   the MCP tool schema after a relay update.
3. **Before modifying a workspace**, read Git origin, current branch, HEAD
   and working-tree status using the returned device. Example for YFC:

   ```sh
   root=/workspace/projects/your-fitness-coach
   git -c "safe.directory=$root" -C "$root" remote -v
   git -c "safe.directory=$root" -C "$root" branch --show-current
   git -c "safe.directory=$root" -C "$root" rev-parse HEAD
   git -c "safe.directory=$root" -C "$root" status --short --branch
   ```

   `-c safe.directory=<exact verified root>` is per-command only, not
   `git config --global`; Codex observed `dubious ownership` on the
   first unqualified attempt and passed after using this scoped override.
   No fetch was performed in that evidence; comparison with the current
   remote GitHub tip is **not verified**.
4. Write only in the approved sandbox checkout, after Git verification,
   normal protected-branch/PR rules and task authorization. Do not
   confuse these clones with original local Windows folders.

## Remaining acceptance gates

The [six-device/client parity matrix](h15-brc-parity-acceptance.md) separates
live PASS, partial coverage and untested scenarios by device and tool.


- Both clients' new native workspace discovery: **PASS**.
- ChatGPT sandbox file/edit/search/move/process checks across Windows,
  Hermes VPS and YFC VPS sandboxes: **PASS**, using isolated temporary
  files; all temporary files removed.
- Independent Codex 3-sandbox write/read/edit/search/move/Node/cleanup
  E2E: **PASS** on 2026-10-24; exact scoped Git verification PASS for all
  four Windows sandbox clones. See [owner-reported client trace](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6388962086).
  Advanced binary/concurrency/reconnect tests remain incomplete.
- New-project onboarding and Control Center workflow: **OPEN** (#454).
  The owner-approved visual direction has a source-level, read-only preview
  for a narrowly formatted GitHub URL. It checks syntax, reserved Windows
  device names and collisions with the built-in catalog. A public repository
  name may contain ASCII letters, digits, `_`, `-` and
  internal dots; names beginning with a dot or hyphen, ending with a dot or
  containing `..` remain unsupported. Windows device names remain reserved
  even with an extension such as `CON.txt`, as described in [Windows naming
  rules](https://learn.microsoft.com/en-us/windows/win32/fileio/naming-a-file).
  The name is limited to 100 characters. An owner-initiated,
  credential-free request to the fixed GitHub API checks public repository
  metadata without following redirects; a timeout, rate limit or ambiguous
  response remains unavailable. The request sends the entered repository
  name to GitHub, uses a four-second socket timeout and returns unavailable
  after six seconds. At most two checks run per Control Center process; a
  stalled DNS lookup may continue in its bounded background slot.
  Runtime use requires the separately approved `api.github.com` egress; it
  does not require new credentials. This does not verify Git HEAD or the
  device filesystem, and connecting is disabled. The device label uses only an
  existing fresh, validated observation and says when it is unavailable; it
  does not prove current command execution. It makes no MCP call and adds
  no registry entry. Runtime delivery and actual onboarding require separate
  implementation, authorization and live verification.
- `scripts/h454_sandbox_project_probe.py` is a separate, non-installed
  read-only helper for the existing Windows sandbox. With a verified script
  supplied to that sandbox and a public GitHub URL on stdin, it checks the
  public HEAD and an instant of root/name availability, without cloning or
  creating a reservation. Its UID and container checks prevent accidents;
  they do not establish an OS security boundary. It does not feed the UI,
  enable connection or add a workspace. Recheck immediately before any
  separately approved operation because the directory can change afterward.
- Windows login/reboot and outage recovery: **OPEN** (#445; do not perform
  unapproved reboot).
- Original Windows read-only access was separately owner-approved for
  exactly four specified project roots and **live E2E PASS in both clients**.
  Its one-shot bearer was then revoked and native device paused/offline.
  Re-enabling requires fresh owner authorization. Native Windows writes,
  commands, private vault, production credentials and Docker socket remain
  denied without individual scoped approval.

No Codex CLI, paid API or new host privileges are required for these
workspace MCP tools. Keep [#454](https://github.com/MikeMoore1337/hermes/issues/454)
open until its full acceptance matrix is satisfied.
