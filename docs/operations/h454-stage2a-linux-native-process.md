# H454 Stage 2A - source-only Linux native one-shot process

**Status:** DORMANT SOURCE. NOT installed on Hermes VPS, YFC VPS or the
owner's Windows PC. No new Hermes MCP tool, HTTP listener, resident agent,
credentials or production process is introduced. This is a narrow first
process-execution building block, **not** Desktop Commander terminal parity.

## Design

`device_fabric/linux_native_process.py` adds a bounded one-shot process
that executes **only after** a trusted local native agent supplies:

- A `LinuxNativeFiles` instance pinned to a real, owner-reviewed source
  project directory (kernel-bound original-root descriptor, not Docker
  `/workspace/projects`).
- A `NativeEffectAdmission` instance with a trusted local device identity,
  protected per-device HMAC key, owner-signed `process_run` grant, active
  revocation and persistent one-use SQLite UUID ledger. No MCP client field
  can replace a real approval.
- A `LocalProcessPolicy` listing exact allowed absolute executable paths,
  an existing private HOME directory, and a **trusted local attestation
  callback**. The callback is a readiness check, **not proof of kernel OS
  isolation or an authorization source**. Runtime activation is forbidden
  until cgroup/OS permission/egress proofs pass.

The grant binds the exact canonical JSON
`{schema:"h454-native-process-v1",argv:[...],timeout_seconds:N}`.
`argv[0]` must be in the host-side executable allowlist. Shell expansion,
an inherited environment, random PATH lookup, stale OAuth bearer access,
MCP-selected cwd, remote PYTHONPATH and client-provided approval booleans
are not supported.

The process starts with a **kernel-verified pinned project-root fd** as
`cwd=/proc/self/fd/<fd>`, inherited only by the supervised child.
`device_fabric/linux_native_child.py` applies `PR_SET_NO_NEW_PRIVS`,
parent-death SIGKILL, private umask and per-process Linux resource limits
before `execve` on the approved executable. No `shell=True` or
`preexec_fn` is used.

## Hard resource ceilings

| Property | Limit |
| --- | --- |
| One-shot wall time | 1-30 seconds, signed |
| CPU per process | 20 seconds |
| Address space per process | 768 MiB |
| Created file size (RLIMIT_FSIZE) | 1 MiB |
| Open FDs (RLIMIT_NOFILE) | 64 |
| Core dumps | disabled |
| stdout returned | 16 KiB, strict UTF-8 |
| stderr consumed but never returned | 16 KiB |
| Command argv | 16 strings, 8 KiB aggregate |
| Reconnect/replay | no retries; UUID permanently consumed |

Output is drained with nonblocking selectors. Timeouts, overflow,
invalid UTF-8 and active-device revocations deny the call, kill the
supervised process group and permanently consume the UUID. A nonzero
exit code is a **completed execution with a nonzero status**, not a
permission failure: it is returned with a bounded stdout. stderr is
discarded to prevent credential and private-path leakage.

**Limitations:** process-group termination alone cannot guarantee removal
of malicious descendants that call `setsid`. Python, Git and Node are
capable of arbitrary code and network calls even with `shell=False`.
The native OS identity must therefore have kernel-enforced filesystem
restrictions, disabled network egress, a restricted systemd cgroup
and verified `KillMode=control-group` before this code can run on
an owner host. The code's non-root check and attestation callback do
not replace that boundary. A source tree owned by an untrusted account
must not be allowed to replace the pinned child launcher.

## Synthetic test

```sh
python3 -B -m unittest -v tests.test_h454_linux_native_process
```

GitHub Linux CI tests run actual one-shot CPython subprocesses in
disposable fixture roots. Positive tests: signed execution, pinned
cwd, private HOME, 16 KiB output, nonzero code. Negative tests:
bad/mutated HMAC payload, forged project/action, unknown executable,
disabled isolation, root identity, secret inheritance, revoked device,
expiry before spawn, stdout/stderr overflow, timeout and replay,
malformed/duplicate JSON and invalid UTF-8 output.

Windows runners only import or skip these Linux-only tests. A green
test on a CI runner is **not** actual owner-host execution or ChatGPT
native-client E2E.

## Mandatory steps before any real device activation

1. Owner approval for exact native host agent identity, locally
   allowlisted **actual original project root**, trusted executable
   paths/commands and a safely bounded operation. Even read-only
   shell/terminal execution on original Windows folders requires an
   independent specific approval.
2. System-installed, root-owned immutable source and executable launcher;
   dedicated unprivileged service user; protected state and HOME;
   kernel-enforced ACL/mount namespace, cgroup memory/PID/CPU/time and
   outgoing-network restrictions; local negative tests for root, vault
   and production-secret escape.
3. Owner-authenticated grant issuance and revocation in the **existing**
   Hermes MCP/relay; private per-device key provisioning; no direct
   public shell endpoint or automatic host permission delegation.
4. Actual ChatGPT and Codex end-to-end native process tests on approved
   host original folders, controlled restart/reconnect and rollback
   without replay. Keep BRC/WSS rollback pins and paused Win32 device
   untouched until a separately approved incident repair.

`NATIVE_HOST_PASS=NOT_RUN` on Windows/Hermes VPS/YFC VPS.
`PRODUCTION_DEPLOY=NOT_RUN`; `HOST_INSTALLATION=NOT_RUN`.
No paid APIs, model, license or third-party relay are introduced.

Related: [Hermes #454](https://github.com/MikeMoore1337/hermes/issues/454),
[Stage 2A signed admission](h454-stage2a-native-admission.md),
[Linux native read](h454-stage2a-linux-native-files.md).
