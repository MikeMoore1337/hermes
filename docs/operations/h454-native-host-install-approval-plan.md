# Hermes #454 / Stage 2A - owner-approved native host installation gate

**Status:** SOURCE-ONLY INSTALLATION PLAN, NOT INSTALLED.
**Owner decision (2026-11-09):** the owner accepts *delivery methods*:
Windows via a graphical installer, Hermes VPS and YFC VPS via GitHub Actions
plus separately restricted SSH. This decision does **not** authorize changing
host users, ACLs, SSH keys, units, credentials, existing devices, original files
or production services. Exact-operation and exact-release approvals remain separate.

**Scope:** one real Windows PC and two real Linux hosts, reusing the **existing
authenticated Hermes MCP** and outbound-only device transport. A Docker sandbox
or a new GitHub source release is never evidence of original-host access.

## 1. Factual baseline / constraints

| Target | Verified existing capability | Not yet verified or delivered |
| --- | --- | --- |
| Windows PC | Five exact owner-approved original **read-only** project roots; Win32 read prototype and handle/path policy exist | Native Windows device is PAUSED/OFFLINE and its earlier bearer was revoked; no owner-approved resident service or graphical installer |
| Hermes VPS | Existing Hermes source-production workflow has a pinned restricted SSH action to deliver source archives | The SSH action accepts only `deploy <release SHA> <archive SHA-256>`; it does not provide `systemctl`, account creation, arbitrary SSH or native agent installation |
| YFC VPS | Existing Hermes MCP lists an online Linux/Docker **sandbox** agent | No separately verified admin/forced-command SSH installation channel, no confirmed original-host checkout paths and no native original-files access |
| Both clients | Workspace discovery over the existing Hermes MCP exists for earlier sandbox catalog | Native host routing, real owner consent UI, native process/write parity and 2 clients x 3 native devices E2E all remain NOT_RUN |

Current repository source contains dormant Linux original-file
read/search/exclusive-create/one-shot-process adapters, native replay
admission and owner-decision ticket issuer. None creates a resident service,
authenticated owner approval UI, a live native MCP route, keys, or OS sandbox.
The issuer's pure ticket-signing helper alone is **not an owner authentication
control**. A signed effect or a chat confirmation alone cannot elevate host OS
rights.

The paired production BRC relay and WSS proxy share a pinned network namespace.
Existing rollback and security/forensic pins must be preserved. The previous
paired cutover fail-closed gate must **not** be bypassed by replacing only
one container. The existing source deployment workflow is a distinct release
operation, not permission to activate native host agents.

Authoritative boundaries:
- [Original Windows roots and per-operation gate](h15-native-windows-approval.md).
- [Native grant issuer limits](h454-stage2a-owner-approval-issuer.md).
- [Native Linux process OS sandbox requirements](h454-stage2a-linux-native-process.md).
- [Existing relay/WSS joint cutover gate](h454-native-three-tool-runtime-recovery.md).
- [Production source delivery](DEPLOYMENT.md).

## 2. Target install architecture (proposed, not present)

Use one authenticated Hermes MCP and its existing device catalog.
Each original host is represented by a distinct owner-paired native device
identity with outbound-only communication to an authenticated relay endpoint.
Do not open a new public shell, HTTP, WebSocket or unauthenticated TCP port.
The native worker must obtain its allowed original directories, OS identity
and revocation information from **protected local configuration** rather
than MCP tool arguments or guessed `/workspace/projects` paths.

Installation must split a read-only resident broker from one-use write/execute
workers. A signed operation grant must be checked together with
**kernel-enforced per-worker OS permissions**, not substituted for them.
A permanent unrestricted Python/Node/Git executor with write access to
every project is prohibited even if it checks HMAC signatures.

### Windows candidate (one-time owner UI / UAC)

- Candidate deliverable: a reproducible graphical installer (MSI or equivalent)
  with pinned source revision, artifact SHA-256, build provenance, supported OS
  and exact publisher/signing status shown **before** install. This installer
  does not yet exist. Do not ask the user to run a PowerShell archive, import
  a hidden task or disable SmartScreen. If OS policy requires code signing
  that has not been arranged, report BLOCKED rather than bypassing it.
- Candidate service identity: isolated, non-administrator Windows service
  SID/virtual account with only the necessary NTFS access; **not SYSTEM**,
  Administrators, the owner's interactive account or a shared development user.
  Proposed service display name: Hermes Commander Native; proposed service
  key: `HermesCommanderNative`. Names are **candidates**, not installed facts.
- Proposed storage: executable under Program Files; private, service-owned
  settings/receipt/key material under ProgramData with individually checked
  ACLs. No secrets are bundled in the installer or printed into UI, chat, CI
  or logs. Initial installation registers a **disabled** service.
- Read-only roots already approved by the owner (no approval renewal needed):
  1. `D:\Pet-projects\hermes`
  2. `D:\Pet-projects\your-fitness-coach`
  3. `D:\Pet-projects\ai-development-toolkit`
  4. `D:\Pet-projects\financial-horizon`
  5. `D:\Pet-projects\second-brain-workspace\second-brain`
- Exclude parent directories, neighboring projects, private Second Brain
  vault, credentials, .env, SSH keys, hidden system/home locations, NTFS
  alternate data streams, Windows device names and reparse/junction redirects.
  Do not alter the ownership or ACL of a whole parent tree.
- All **original-host command launches** (even read-only `git status`) and
  every new/edit/delete/move require **a separately reviewed, exact
  owner-approved operation**. Installation approval is not such a grant.
- The previously revoked/paused Win32 device bearer must not be reused or
  resumed as an install shortcut. Any new or recovered pairing identity
  needs separate explicit approval and scoped revocation handling.

### Linux candidate (distinct restricted host service on each VPS)

- Candidate, not installed: `hermes-commander-native.service`, dedicated
  locked non-login account `hermes-commander-native`, root-owned immutable
  executable/release directory and service-owned private state directory.
  The exact installed paths and service names must be compared with real
  host inventory to avoid collisions. Do not assume an original checkout
  directory from a Docker workspace; discover it read-only **on the host**
  through an separately approved operator channel.
- Native *read-only* service should use systemd/OS restrictions such as
  User/Group (non-root), NoNewPrivileges, empty capability set,
  ProtectSystem=strict, ProtectHome, PrivateDevices, PrivateTmp,
  ProtectKernelTunables, ProtectControlGroups, restricted address families,
  PID/memory/CPU/task limits, and explicit read-only visibility for only
  the discovered approved roots. Keep all writes limited to private
  state/receipt directories. Test all settings with the real `openat2`
  and outbound transport: a suggested systemd option is not a proven sandbox.
- Block access to production DB, foreign apps, /root, /etc secrets, SSH agent,
  Docker socket, unrelated mounts, system process namespace and unrestricted
  egress. Outbound networking must be limited to the authenticated Hermes
  relay, while forbidding arbitrary host shell/network escalation. Python,
  Node and Git execution must use separately constrained one-use workers
  with verified OS isolation and never receive generic root/sudo rights.
- Never replace the YFC editorial/news worker or add a second owner of its
  publishing schedule. Both VPS receive **separate** identities and
  workspaces with their own approval and rollback records.

### Installation transport / limited privilege

Do **not** re-purpose `.github/workflows/production-deploy.yml` or its
`HERMES_DEPLOY_KEY` as a privileged shell. It currently provides
source-only `deploy` delivery. Build a **separate, manual, exact-SHA-gated
installer workflow** with no automatic `push` trigger and no shared
admin credential. Its future forced-command SSH target must support only:
- Read-only `plan` for an immutable, separately verified install manifest;
- `install` for exactly the owner-approved manifest digest and currently
  approved SHA, with a protected one-use approval check;
- `status` and an individually authorized `rollback` of **only the newly
  installed native service**.

These are **proposed commands**; no such forced-command endpoint is
verified as deployed today. Avoid generic SSH shell, passwordless sudo,
sudoers wildcards, host Docker socket or calling `systemctl` from the
sandbox. Generate/activate separate limited SSH identity and private
secrets **only** after specific owner approval. If the YFC VPS has no
approved bootstrap transport, record BLOCKED and require an authorized
administrator's one-time OS installation action, not a bypass.

## 3. Staged delivery with stop gates

| Stage | Work owned by implementation | Required evidence before advancing |
| --- | --- | --- |
| A. Inventory | Source-only plan and independently reviewed read-only per-host preflight (OS, actual original roots, ownership, active services, exact current production revisions, SSH restrictions) | Three signed/approved inventory records, no host mutation; unknown root/identity/channel = BLOCKED |
| B. Build | Graphical Windows installer, Linux install manifest/forced-command operator, owner-authenticated Control Center decision screen, private key provisioning design, outbound Hermes MCP native route | Immutable artifacts tied to exact source SHA; offline CI; security review; **no** service activation |
| C. Owner scope | Show three **separate** host change previews: executable/artifact hash, intended account, exact paths, ACL/mount policy, unit/task settings, network egress, enrollment/revocation and precise rollback | Specific owner approval for each host + separately approved cumulative source release SHA; no broad pre-authorization |
| D. Prepare | Verify actual SSH account/forced command on Hermes/YFC, protected keys and pinned host keys; run only read-only dry-run; on Windows verify installer publisher/digest and UI | Secure channel + explicit approval record + rollback evidence, otherwise STOP |
| E. Install OFF | Windows: owner runs the verified UI and grants one scoped UAC when presented; Linux: separately authorized workflow installs root-owned artifacts, dedicated service ID and protective OS policy with service **disabled** | Exact installed binary/config hashes, effective UID/ACL/mount/egress controls, no existing service changes |
| F. Read-only live | Explicitly authorize one native-device pairing per host and enable read-only service; connect through **existing** authenticated Hermes MCP relay | Three native ONLINE devices with real original-root read and negative outside-root/secret tests; legacy sandbox and existing OAuth remain healthy |
| G. Exact effects | Implement and review separate one-operation write/process authorization UI and OS worker. For Windows, obtain a fresh scope for **each** original-host write/command | Signed one-use effect, durable replay denial, original path and command evidence, timeout/revocation/error negative tests |
| H. Acceptance | Independently exercise ChatGPT and Codex across 3 native devices, including restart/reconnect and safe rollback | 2 x 3 live trace matrix, no unapproved data access, verified statuses and backout; only then consider #454 close |

Source release and native runtime activation are different approvals. Every
candidate SHA must match `main` and pass exact SHA-scoped repository and UI
CI, with a real rollback path. A merged PR or `PRODUCTION_DEPLOYED`
source archive is not `NATIVE_HOST_PASS`.

## 4. Evidence required for each of the three hosts

Record this information in a *private*, sanitized deployment receipt; never
put credentials, full token values, original file content or private keys
in GitHub comments:

- Exact host ID, OS build/kernel, non-root native service identity (UID/SID)
  and read/write scope; no ambiguity with the sandbox `platform=linux/docker`.
- Current owner-approved native root paths discovered *on that host*; Windows
  five roots as above, Linux roots **NOT_YET_DISCOVERED**.
- Immutable installed source/build artifact SHA and signature/provenance;
  authorized source release SHA; installed location and service unit hash.
- Root/ancestor ACL and no-follow/symlink/mount tests; refusal of other
  users' files, secrets, Docker socket, production DB and private vault.
- Authenticated outbound transport, relay device identity, owner-bound
  enrollment and ability to revoke, including denial of legacy paused
  Win32 bearer and replayed operation IDs.
- CPU/memory/PIDs/time/output/egress limits independently measured; a
  config file without live enforcement is not PASS.
- Existing BRC/WSS paired container IDs, OCI pins and state backups
  unchanged; YFC production/editorial health unchanged.
- Reverse operation: stop/disable only the *new* agent, revoke its new
  credentials, retain consumed UUID receipts/audit, restore only its
  newly installed files/units from approved backups. No deletion of
  existing BRC state, source checkouts, DBs or unrelated services.

## 5. Acceptance matrix - all native targets initially NOT_RUN

| Client | Windows original | Hermes VPS original | YFC VPS original |
| --- | --- | --- | --- |
| ChatGPT | NOT_RUN | NOT_RUN | NOT_RUN |
| Codex | NOT_RUN | NOT_RUN | NOT_RUN |

For **each** cell prove file stat/read/list/search, byte hashing, protected
path deny, negative traversal/symlink/junction, signed create/edit/move
where approved, isolated Git/Python/Node and bounded process termination
with command-specific owner consent, restart/reconnect, clean project Git
status and accurate fallback/offline presentation. If a capability is not
implemented, report GAP rather than marking parity complete. A Windows
native execute test requires its own concrete approval even if the
command only reads files. The Windows reboot test requires an agreed
maintenance interval; do not reboot merely to satisfy CI.

Additional acceptance:
- Functional Control Center owner approval/reject screen; actual owner
  login and CSRF/session checks; rejects forged MCP `approved=true`;
  immutable audit receipt, revocation, TTL and one-use replay.
- The existing authenticated Hermes MCP is the only owner-facing endpoint.
  Workspaces resolve to exact live host identities; no guessed root or
  proxying sandbox-clone results as original-host evidence.
- Same-origin project onboarding from Control Center without PowerShell
  archives, extra OAuth on normal reconnect or manual device IDs.
- Original Windows identity remains revoked until specifically approved
  re-enrollment. No paid APIs, services or new third-party relays.

## 6. Explicit future owner actions (not requested or authorized yet)

The owner has *already selected the installation channels*, so do not
re-ask that choice. The next owner touch points are:

1. **Windows:** inspect verified installer artifact, expected service
   SID and five read-only roots on a GUI preview; approve one UAC prompt
   **only after** the exact installer and ACL proposal is accepted.
2. **Hermes VPS:** approve one read-only install/maintenance preview
   listing exact revision, service identity, root, forced-command scope,
   key provisioning and rollback. Source-delivery approval **alone**
   is not a host-service approval.
3. **YFC VPS:** approve the same distinct preview **after** a restricted
   SSH/bootstrap channel has been independently verified. If no such
   channel exists, a trusted admin must bootstrap it once through an
   approved path; the Docker sandbox cannot create the privilege.
4. **Later per-effect:** explicitly confirm the exact original Windows
   file write or command, including target and side effects. Broad
   install approval does not substitute for one-use owner grants.
5. **Final:** review 2-client x 3-host evidence and accept/decline
   the final parity matrix.

Do not ask the owner to disclose SSH keys, passwords, bearer tokens,
HMAC keys, vault contents or personal system paths in chat. The owner
needs to interact only with a reviewed GUI or a separately approved
narrow installer operation, not copy code from GitHub into an
administrator shell.

## 7. Abort/rollback criteria

Stop immediately, **without retry or fallback**, for any unexpected
device identity, revoked credential, wrong artifact SHA, insufficient
owner approval, unknown OS path, incompatible source/UI CI, unverified
SSH host key, OS identity with broad sudo/admin rights, unexpected
service or container mutation, ACL escape, exposed secret, failed
health check or missing rollback checkpoint.

On failure after install, keep existing H-15 BRC/WSS and unrelated
production services untouched; stop/disable only the new native unit,
revoke *new* pairing/keys, preserve SQLite consumed UUID and audit
evidence, and restore the previous state of the *new* service only.
Escalate if old and new service identities cannot be distinguished.
Do not clear or rename the BRC/WSS incident pin to force a cutover.

**Verification status as of plan creation:** INSTALL_METHOD_APPROVED=YES;
INSTALLER_BUILT=NO; LINUX_HOST_INSTALLER_VERIFIED=NO;
HERMES_SSH_NATIVE_ADMIN_CHANNEL=NOT_VERIFIED;
YFC_SSH_NATIVE_ADMIN_CHANNEL=NOT_VERIFIED;
OS_SANDBOX_LIVE_PASS=NOT_RUN; NATIVE_HOST_PASS=NOT_RUN;
OWNER_AUTH_UI_PASS=NOT_RUN; PRODUCTION_NATIVE_DEPLOY=NOT_RUN.
Issue #454 remains OPEN.
