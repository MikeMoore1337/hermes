# H-585 - Anthropic Sandbox Runtime compared with existing Hermes Docker isolation

Scope: Issue #585, source-only disposable CI pilot; **no resident, VPS, owner Windows, production or BRC permission changes**.

## Goal and source

- Candidate: https://github.com/anthropics/sandbox-runtime, Apache-2.0, pinned commit c66fb77b28fdbea8b9788aca72377238ae67ca20, source package version 0.0.81.
- Build: Git SHA-verified checkout, npm ci (committed package-lock), npm run build; no floating npm package or LLM provider.
- Pre-existing baseline: scripts/h15_brc_sandbox_linux_e2e.mjs (real dispatcher in isolated Docker) and scripts/h15_windows_os_sandbox_e2e.ps1 (LocalService ACL, *not SRT*).
- New: scripts/h585_srt_pilot.py; .github/workflows/h585-srt-isolated.yml runs on isolated GitHub Actions ubuntu-24.04 for same-repo PR or owner dispatch.
- Risk: upstream is a beta research preview. Linux requires bubblewrap, user namespaces and compatible seccomp/kernel; Docker constraints differ and may block nested sandbox execution. Native Windows SRT requires system account/WFP/ACL changes - deliberately NOT_RUN.

## Same intended safety properties and differences

| Probe | SRT intended result | Existing Docker intended result |
| --- | --- | --- |
| Writes inside disposable workspace | Allowed | Allowed via one rw mount, UID 65534 |
| Read synthetic protected marker | Allowed | Allowed via ro mount |
| Write protected marker | Denied by SRT write policy | Denied by read-only mount |
| Read synthetic private file | Denied by SRT denyRead | Denied because not mounted |
| Read private through workspace symlink | Denied | Denied because target not mounted |
| Direct TCP to 1.1.1.1:443 | Unreachable via restricted namespace | Unreachable via --network none |
| Nested Python child | Same restrictions verified | Same restrictions verified |
| Missing/invalid SRT config | Must refuse before running any child | N/A |
| Cgroups | Measured under CI runner limits; no SRT-specific cgroup claimed | Explicit 256 MiB, 0.5 CPU, 64 PIDs |
| Linux startup latency, CPU/RAM | Not a calibrated benchmark; use workflow durations only | Not a calibrated benchmark |
| Windows WFP/ACL after native srt | NOT_RUN | Prior Windows *non-SRT* ACL scripts, separate evidence |

**Important:** A TCP failure to a public IP on its own does *not* prove a network sandbox; combine this with inspection of bubblewrap network namespace and the explicit disabled network policy. Separate known-live endpoint checks are needed before granting security equivalence. A symlink pointing to a path not mounted in Docker is a different security property from denying it in SRT.

## Reporting rules

- Each actual parent and child probe produces only synthetic JSON. CI validates the report schema and every required boolean. Missing script, incomplete report, bad upstream install, or refused namespace -> **FAIL / NOT_RUN**, never PASS.
- A normal unsandboxed run is an expected negative oracle: it can read and write synthetic private/protected fixtures, and must fail verification.
- GitHub Actions must have **actual finished success** for SRT and Docker jobs at exact PR head before a source-only merge. A green job that skips a sandbox stage does not satisfy Issue #585.
- E2E outputs are 7-day synthetic CI artifacts. Do not store tokens, real keys, signed auth headers or private paths.
- Container-specific security configuration stays in its existing ownership (#371/#454); this experiment does not replace it.
- No production adoption just because this source PR merges.

## Adoption decision

**PENDING REAL CI EVIDENCE.** If SRT produces no additional kernel-enforced security benefit over existing Docker BRC, prefer **NO_ADOPT for resident Hermes**: avoid complexity, extra OS dependencies, user namespace behavior and Windows alpha WFP side effects. If it demonstrably improves a user-requested trusted boundary, separately evaluate it under #371/#454 and require owner approval for any native host changes.

## Status and chronology

2026-10-25: Hermes BRC sandbox preflight (device h15-win-05be75515428) confirmed an unprivileged Linux Docker checkout; neither bwrap nor srt nor Docker daemon available inside that particular container. This is not equivalent to the GitHub Actions runner with Docker installed. See #585 issue comment for evidence.

Release only after the **real** workflow results and associated revision are linked in Issue #585. No claim about live Windows SRT testing without a separate isolated VM proof.
