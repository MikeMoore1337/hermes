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

The previous live acceptance covered four public **sandbox** projects.
The source catalog adds **Financial Horizon** as a fifth. An offline import
subsequently made its public repository available in the live Windows sandbox;
Codex and ChatGPT both resolved and verified its Git state on 2026-11-25:

| Workspace | Branch | Approved root |
| --- | --- | --- |
| hermes | main | `/workspace/projects/hermes` |
| your-fitness-coach (YFC) | master | `/workspace/projects/your-fitness-coach` |
| second-brain | main | `/workspace/projects/second-brain` |
| ai-development-toolkit (Toolkit) | main | `/workspace/projects/ai-development-toolkit` |
| financial-horizon (FH) | main | `/workspace/projects/financial-horizon` |

## Offline import of another public project

On the Windows owner host, Codex can use
`scripts/h15_offline_project_import.py <repository-name>` to prepare a
verified Git bundle of a public `MikeMoore1337` repository and install it in
the existing Windows sandbox. It selects the public repository's default
branch, refuses to overwrite an existing project, and leaves sandbox networking
unchanged. Subprocesses do not create Windows console windows. A failed import
can leave its marked staging directory or an incomplete new target for operator
inspection; it does not delete an existing checkout. It does not support private
repositories.

The live `import_public_project` MCP tool also lets ChatGPT request this
public-repository import without running a host command. On 2026-11-28,
ChatGPT imported `MikeMoore1337/crypto-ema-bot` into the Windows sandbox and
Codex resolved the resulting clean checkout on `master` at
`61a0ff6884f9707d38609b0eb5918d5cbb690621`. This is a sandbox copy, not
registration of an original host directory. Imports must not overwrite an
existing project and remain subject to the helper's public-repository and
size checks.

The live import of `reminder-bot` on 2026-11-25 returned a clean `master` at
`4e89a2ab2f0c3070f6ab873cb3651556d2dfb57b`; both clients subsequently
resolved that same commit. This is an owner-host helper, not a new resident
service or complete cross-client onboarding.

The authenticated MCP tools select the unique online, unpaused
`H15 Windows permanent sandbox` from live user-owned device discovery.
They do **not** grant extra filesystem permissions, mount Windows-native
folders or reach either production VPS host. The returned
`git_verified` may be true for a dynamically inspected repository, while
`verification_required_before_write=true` remains deliberate: a catalog
entry alone does not attest the current working-tree state.

## Original personal projects

The personal-device source also supports separately authorized original
projects. Once a directory is registered on the device, discovery reports
aliases such as `financial-horizon-windows`, `<name>-hermes-vps`, and
`<name>-yfc-vps`. These names are device-specific; they do not replace the
existing sandbox aliases. A discovered entry is not proof of its Git branch,
origin, or clean state. A list request starts a short-lived confined terminal
on each online personal device and may take longer on Windows.

For an authorized owner request, Codex can use
`scripts/h454_windows_personal_add_project.py` on the Windows owner host or
`scripts/h454_linux_personal_add_project.py` as the local root operator on the
appropriate VPS. Each has a non-mutating plan and a separate execution mode;
it retains protected configuration backups for rollback. The caller checks
device reconnection and the intended directory through MCP afterwards. The
Windows source supports up to sixteen selected roots; an installed release may
still have the previous five-root limit until it is updated. The VPS operator accepts at most four
additional roots and refuses directories the service identity cannot already
traverse and write; it does not grant ACLs or change owners. Private Second
Brain vault access remains excluded. These host operators are not currently a
ChatGPT-only self-service registration flow.

The source includes an optional `connect_original_vps_project` MCP tool for
owner-selected existing VPS directories. It uses the personal Windows worker
and the owner's existing key-authenticated SSH configuration to call the
already installed, pinned root operator. Local `worker-private/vps-registration.json`
contains only the two host aliases; it is not a credential and is not part of
the repository. Missing or invalid optional configuration leaves the existing
Windows workspaces usable and the new operation unavailable. This source is
not proof that the tool has been installed or activated.

Use `mode: plan` before `mode: execute`; execution restarts only the selected
personal VPS service and preserves a protected configuration backup. It refuses
`/tmp` roots and paths that the service identity cannot already traverse and
write. A successful response still requires resolving the new workspace and
checking it through MCP. An interrupted or unrecognized response is `unknown`:
inspect the live service and workspace before doing anything further, and do
not automatically repeat the operation. It does not register Windows folders.

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
  E2E: **PASS** on 2026-10-24; exact scoped Git verification PASS for the original
  four Windows sandbox clones. See [owner-reported client trace](https://github.com/MikeMoore1337/hermes/issues/454#issuecomment-6388962086).
  Advanced binary/concurrency/reconnect tests remain incomplete.
- New-project onboarding and Control Center workflow: **OPEN** (#455,
  visual approval required before UI implementation).
- Windows login/reboot and outage recovery: **OPEN** (#445; do not perform
  unapproved reboot).
- Original Windows read-only access was separately owner-approved for
  exactly four specified project roots and **live E2E PASS in both clients**.
  The original one-shot bearer was revoked and its device paused; a later
  separately authorized native device is in service. Native Windows writes,
  commands, private vault, production credentials and Docker socket remain
  denied without individual scoped approval.

No Codex CLI, paid API or new host privileges are required for these
workspace MCP tools. Keep [#454](https://github.com/MikeMoore1337/hermes/issues/454)
open until its full acceptance matrix is satisfied.
