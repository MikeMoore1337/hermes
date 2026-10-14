# H-01 isolated Hermes Agent: same VPS staging

This is an offline-only, no-provider, no-network design. It is NOT a functional connected AI agent.

Scripts:
- prepare-agent-home.sh: separate nologin host identity and /var/lib/hermes-agent storage owned by that identity, mode 0700. Leaves news Hermes user/state untouched.
- run-agent-sandbox.sh: immutable official image, --network none, readonly root, no Docker socket, cap-drop all, no new privileges, nonroot UID, pids 96, 0.5 CPU, 640 MiB RAM and 896 MiB memory+swap. Only private agent state bind-mounted.
- hermes-agent-sandbox.service.example: disabled example with no restart and max runtime 1800s. Not installed by this repo.

Manual review sequence (after H-01 resource verification and explicit operator GO):
1. Confirm actual host RAM, news guard ready, no critical services failing.
2. Validate source hashes and Docker digest. Create OS identity/storage with sudo bash deploy/prepare-agent-home.sh.
3. Perform bounded isolated read-only smoke; verify host mount isolation, no network and resource usage.
4. Stop/remove the candidate and check existing news timer/worker again.
5. Only later, after agreeing on model/provider, credentials and scoped egress, implement a separate integration; never remove --network none without a reviewed firewall + negative tests.

The configuration cannot send chat responses, query models, poll GitHub or notify Telegram. No new SSH, YFC DB, private Second Brain vault or existing Telegram bot token is authorized.
