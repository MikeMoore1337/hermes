# H454 Stage 2A - original Linux host inventory via SSH (source only)

No host credentials, SSH account or key are created by this PR.
No agent installation or production deployment is performed.

## Future operator boundary

- Each original VPS requires a **different** SSH identity, restricted at
  the server via `authorized_keys` with `restrict,command="..."`.
  For Hermes VPS the forced command invokes the reviewed
  `scripts/h454_native_linux_inventory.py --target hermes-vps`;
  YFC VPS uses `--target yfc-vps`.
- The forced command must be root-owned and immutable to the inventory
  account. This account must be unprivileged, non-sudo, without generic
  shell, forwarding, PTY or write permissions to original projects.
  Its `SSH_ORIGINAL_COMMAND` must be exactly `inventory`.
- GitHub Actions manual workflow uses the existing `main` SHA gate and
  **six new, separate** GitHub secrets for the two targets: host address,
  dedicated private key and trusted pinned `known_hosts` record.
  None are supplied today; `HERMES_DEPLOY_KEY` is not used.
- The workflow runs one read-only SSH request, checks the bounded report
  against an exact fixed schema and uploads it for two days. No host paths,
  source file contents, tokens or raw errors are included. Original Linux
  roots remain UNVERIFIED until an owner-authorized exact per-host plan.
- The host-side script can only check status of the dedicated future
  nonroot service account, disabled preflight unit and release directory;
  it cannot create them, install code or activate native access.

**Next owner action after separate approval:** bootstrap the two dedicated
inventory-only SSH principals and set their per-host GitHub Actions secrets.
Never paste private keys, passwords, known_hosts trust material or tokens
into ChatGPT. Do not touch BRC/WSS or reuse its deploy key.

Passing CI is not a live host-inventory proof. Issue #454 remains OPEN.
