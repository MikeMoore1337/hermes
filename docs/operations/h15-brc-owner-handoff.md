# Hermes BRC #454: owner-host one-time handoff

Runs only on the authorized Hermes VPS Docker host, not through an MCP
device. No new SSH key, sudo rule, API or Docker socket exposure is added.

From an owner-authorized terminal on the VPS, in the existing verified
Hermes source release (no hand-entered commit identifier):

    cd "/opt/hermes-agent-owner/releases/main-$(cat /var/lib/hermes-main-deploy/last-success.sha)"
    sudo python3 -m scripts.h15_brc_owner_handoff doctor
    sudo python3 -m scripts.h15_brc_owner_handoff prepare
    sudo python3 -m scripts.h15_brc_owner_handoff execute

doctor is strictly read-only: it checks tools, root privilege, Docker
socket and backup directory, printing no token or sensitive inspect output.

prepare uses the existing authenticated GitHub CLI to find the latest
valid exact-main OCI or a provably unchanged ancestor, stages it in the
owner-private backup directory, verifies its checksum/provenance, loads
the image and performs the existing running-relay preflight.
It does NOT stop/restart the relay or change OAuth, devices or SQLite.

execute refuses every noninteractive/CI/MCP invocation before doing
anything. It re-runs verified stage+preflight, displays the actual old
and new immutable image IDs, and requires an exact owner-typed phrase.
It creates an exclusive root:root 0600 one-time approval tied to the
exact image/old image/archive/source and calls the already tested
transactional cutover. The approval is removed on completion/failure.
SQLite online backup and disposable restore rehearsal are required
before container interruption; the old container is kept for rollback.
Success remains PENDING actual ChatGPT AND Codex OAuth MCP tests.

Root must already have access to gh (gh auth login or authorized
GH_TOKEN securely injected on the host), docker, Python and zstd.
Never provide tokens in ChatGPT or command arguments. If unavailable,
the operator fails closed; do not widen the restricted existing
Hermes SSH source-deploy key.

The current ChatGPT Hermes device is a Docker sandbox and cannot run
this. No production BRC upgrade has happened just because this script
exists or a GitHub Actions Docker fixture passed.
