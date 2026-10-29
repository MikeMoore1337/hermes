# H454: Windows BRC init-candidate contract

This is a **read-only fail-closed** pre-cutover gate for the original owner
Windows BRC Docker sandbox, not permission to deploy. No secret material,
mount sources, Docker raw JSON, env, or launcher contents are printed.

## Incident and regression

The image entrypoint requires /run/brc/ready. The standard private Windows
launcher decrypts existing device credentials through DPAPI and stages them
to tmpfs using the in-image h15-stage.sh; direct docker start omitted this
and produced H15_CREDENTIAL_STAGE_TIMEOUT (exit 2). The original Windows
sandbox has since recovered and was independently verified online.

The initially created --init candidate was missing **both** mandatory
HostConfig.Tmpfs mounts: /run/brc and /tmp. Comparing ordinary Mounts alone
cannot detect the omission. Never start or promote that retained candidate.

## Offline tests

From a trusted checkout, run:

    py -3.14 -B -m unittest discover -s tests -p "test_h454_windows_candidate_contract.py" -v

18 deterministic Python tests require no Docker, credentials, network or API.

## Owner Windows host, read-only gate

After pinning and reviewing a released SHA, optionally run:

    py -3.14 -B scripts/h454_windows_candidate_contract.py

The inspector uses a pinned Docker Desktop binary and in-memory
docker container inspect for the original and stopped candidate; it emits
only enum statuses. A candidate missing its mandatory tmpfs is HOLD/TMPFS.
No files, containers, registry, Task Scheduler or SSH are mutated.

PASS establishes parity of image, environment, entrypoint, non-root user,
security restrictions, complete host configuration except Docker Init,
the workspace bind, both tmpfs specifications, and 128 PIDs. PASS does
not stage credentials or show a healthy network connection. It explicitly
states CUTOVER_AUTHORIZED=FALSE, CREDENTIAL_STAGE=NOT_TESTED,
RECONNECT=NOT_TESTED.

## Remaining acceptance gates

1. Build a new stopped candidate using identical security, workspace
   bind, both tmpfs mounts, immutable image and --init. Do not start
   the currently incomplete candidate.
2. Prove rollback and live owner-approved, one-device credential staging
   and SSH/relay connection; preserve existing device ID and DPAPI token.
3. Run real ChatGPT and Codex Desktop process/file E2E after cutover.
4. Verify PID1 reaping over time, no PID exhaustion and no private access.
5. Correct the existing private user-logon launcher under separate
   owner-gated rollout. It still recreates the container with 96 PIDs and
   no init; a successful current recovery does not prove reboot recovery.

No added paid API or model calls are involved.