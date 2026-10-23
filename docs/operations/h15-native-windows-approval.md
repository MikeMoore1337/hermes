# Hermes #454/#455 — owner-approved Windows roots and operation gate

**Owner decision (2026-10-23):** Read-only inspection is approved for the
**four specific original Windows project directories below**.
A file modification **or any command execution** requires a **separate
owner approval**. The assistant must first give a concise action proposal:
which project, exact changes/commands, why, and expected effects. The
owner explicitly approves that proposal **before execution**, not after.

| Project | Approved read root |
| --- | --- |
| AI Development Toolkit | `D:\Pet-projects\ai-development-toolkit` |
| Hermes | `D:\Pet-projects\hermes` |
| Second Brain code repo | `D:\Pet-projects\second-brain-workspace\second-brain` |
| Your Fitness Coach | `D:\Pet-projects\your-fitness-coach` |

### Hard boundaries

- These entries **do not grant** the whole `D:\Pet-projects`, the parent
  `D:\Pet-projects\second-brain-workspace`, any home/system directory,
  the private Second Brain vault, secrets or credentials. No new mounts
  into the current Docker agent are implied.
- Read means inspect files, list directories and metadata. **Starting a
  terminal process**, including read-only `git status`, scans, tests or
  file-copy scripts **is an execute operation**, requiring an explicit
  approval for its actual Windows-host execution.
- Write means create, edit, rename, delete or alter permissions. No
  "project approved earlier" shortcut; approvals are purpose- and
  action-bound, not perpetual. A client flag `approved=true` is **not**
  a valid authorization token. No arbitrary browser-to-shell endpoint.
- Owner approval does not waive OS identity limits, audit, immutable
  policy, symlink/junction/reparse-point protection, no-follow handle
  resolution or separate production/security gates. Those protections
  need proof **at the actual native Windows runtime** before activation.

### Current technical status

`control_center/native_windows_policy.py` is a **pure classification
contract** returning `read_policy_approved`, `owner_approval_required`
or `denied`. It rejects lexical path escapes, parent/sibling
overreach, ADS, private vault and secrets. **It is not a filesystem
security boundary** (OS handles, reparse points, ACLs and concurrency
require native implementation). `has_native_windows_access()`
deliberately returns **False**: the existing H15 BRC MCP agent is
sandbox-only and has not acquired read access to original `D:\` paths.

**No native Windows process/service, filesystem mount, file copy,
credential, new TCP listener, arbitrary command endpoint or production
host access is activated by this change.** Do not report owner approval
as proof that any file was opened on a Windows original directory.

### Future one-action approval protocol

1. Discover requested project through native MCP workspace catalog;
   decide whether the desired result can be read from existing sandbox.
   If the true original file is required, restrict to one of the four
   roots and an approved read-only native broker with least-privilege
   OS access. Limit paths, sizes, traversal and redaction.
2. For write or execute, produce a **short proposal** including purpose,
   affected exact original path(s), command/operations and side effects
   (network, subprocesses, git branch, build outputs), plus a rollback
   or stop path where meaningful.
3. Wait for **explicit owner confirmation of that particular proposal**.
   Then require a separate server-held, one-use authorization bound to
   operation identity/path, TTL and authenticated owner; reject replay.
   Never treat conversational text or arbitrary MCP arguments as
   sufficient host-side permission.
4. Execute the approved scope only, capture bounded redacted results,
   verify the desired outcome, record denial/expiry and revoke grants.
   If scope changes, stop and request another approval.

No Codex CLI, paid AI or broad Windows host permissions.
Linked: [#454](https://github.com/MikeMoore1337/hermes/issues/454),
[#455](https://github.com/MikeMoore1337/hermes/issues/455),
[#445](https://github.com/MikeMoore1337/hermes/issues/445).
