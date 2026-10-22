# H15 #454: transactional owner-host relay switch

This is an operator-side capability, NOT an activated remote MCP tool. Running
Hermes VPS agent has no Docker host privileges and must not be granted them.

Read-only mode: python3 -m scripts.h15_brc_transactional_upgrade plan
with --bundle-dir, --image, --archive-sha, --hermes-sha.
It checks the sealed candidate and current dedicated relay identity, and
does not alter devices, containers, SQLite or tokens.

Destructive mode: cutover with the same exact pins plus --execute.
It requires a separate root-owned (0600) JSON at
/etc/hermes-brc-relay/relay-upgrade-approval.json (parent root 0700):
schema=1, decision=OWNER_APPROVED_LIVE_BRC_RELAY_CUTOVER,
scope=EXISTING_PAIRED_DEVICES_NO_HOST_PERMISSION_CHANGE, image_id,
previous_image_id, archive_sha256, hermes_commit.

Before service interruption it performs an online SQLite backup and proves
a disposable restore. Old container is stopped, has restart disabled, and
is renamed to hermes-brc-relay-h454-rollback, never deleted on success.
Candidate uses same service UID/GID, secret env-file, /state mount,
fixed internal network IP, read-only rootfs and no published ports.
The candidate must become healthy and recover at least the previous online
device count. Otherwise the code removes only its verified owned candidate,
renames the old checkpoint back and restarts the original. It keeps the
SQLite backup for explicit recovery. It never blindly restores a stale DB
over newer OAuth/device records.

Even on success this is PENDING LIVE CLIENT ACCEPTANCE. Verify ChatGPT and
Codex native connector tools/list and tools/call before clearing checkpoint.
A new DB migration could make old rollback incompatible; if restart cannot
recover, stop and use the safeguarded SQLite snapshot under a separate
owner-authorized restore procedure. This operator is not auto-run by CI,
normal source deploy, OAuth tool calls, or Codex CLI.

Exact current working OCI candidate pins and data recovery instructions
must be verified from current main GitHub Actions before any live switch.
