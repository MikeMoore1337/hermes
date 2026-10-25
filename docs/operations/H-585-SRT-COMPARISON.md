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

## Verified pilot results (25 October 2026)

| Evidence | Exact result |
| --- | --- |
| PR #588 candidate, SHA c139881db14f3a26ef2bf0590d49fbb383989127 | GitHub Actions quality and comparison checks both SUCCESS |
| [Real Ubuntu 22.04 comparison](https://github.com/MikeMoore1337/hermes/actions/runs/40201324841) | All steps PASS: build from pinned SHA, actual SRT negative probes, invalid-config fail-closed, Docker negative probes |
| [Synthetic artifact 12601623139](https://github.com/MikeMoore1337/hermes/actions/runs/40201324841/artifacts/12601623139) | 760-byte ZIP, sha256:ebfcb3dd55824d38acf17b3c1bb6bfc165a6cac9c0d6f25b8b5e9f0bbbdbcc5f |
| [Hermes repository checks](https://github.com/MikeMoore1337/hermes/actions/runs/40201324840) | All repository quality steps SUCCESS |
| Initial Ubuntu 24.04 attempt | SRT FAILED at bwrap network namespace setup: RTM_NEWADDR Operation not permitted; no security PASS claimed |
| Ubuntu 22.04 fixed attempt | SRT PASS; first Docker test only failed on synthetic test-file ownership collision (SRT and Docker shared names) |
| Separate-output-root corrected attempt | Both SRT and Docker PASS with independent disposable workspaces |
| Native Windows SRT, genuine production devices, p95/CPU comparison | NOT_RUN / NOT_MEASURED - no claim of security or performance equivalence outside exact CI |

The upstream SRT workflow itself documents that Ubuntu 24.04 restricts unprivileged user namespace capabilities through AppArmor and therefore needs a sysctl adjustment on ephemeral runners. This comparison selected Ubuntu 22.04 instead of weakening the Ubuntu 24.04 runner policy. The old failure is genuine environment incompatibility without that configuration, not proof of an SRT defect.

Docker's explicit cgroup controls (256 MiB, 0.5 CPU, max 64 PIDs) are exercised by the comparison step. SRT's process is limited by the GitHub Actions job timeout and command timeout; this does **not** establish equivalent per-process cgroups. Hosted runner step durations are not controlled latency benchmarks. In particular, SRT's successful direct TCP connection failure does not prove every external address is unreachable; net namespace policy and dedicated network red-team cases are independent concerns.

## Final adoption decision for Hermes BRC: NO_ADOPT

The **tested restricted file/network capabilities** pass for both SRT and Docker. No missing BRC capability or measurable additional enforcement has been established to justify installing another process sandbox in resident Hermes. Existing Docker has separate UID, read-only mounts, no network, Linux capability restrictions and explicit cgroups. Additional SRT introduces beta APIs, bubblewrap/userns/AppArmor compatibility requirements and, for native Windows, WFP/ACL account provisioning with documented platform limitations. Therefore do **not** install SRT in Hermes resident runtime or on the owner's Windows host.

Keep the isolated source-only CI comparison as a reproducible research record. Do not modify H-15 #371 or #454 to require SRT. Revisit adoption only when a specific uncovered BRC threat can be reproduced and when an isolated negative test proves SRT improves enforcement over Docker. Such a future choice is a separate owner gate.

The comparison is not a permission grant, a security certification, nor an activation of untrusted MCP servers. No paid APIs, Codex CLI, resident runtime changes or real secrets were used.

## Release gate

This document records the verified pre-document-update pilot SHA. After incorporating this decision, the final PR head must **again** pass exact-head quality and comparison checks. Merge only after success and ensure merged-main CI is independently verified. Issue #585 can close as completed for its **comparative pilot**, not as a claim that SRT was adopted into production.

## Automatic production deploy isolation for this PR

Hermes production-deploy.yml normally runs after a green main push even if the change is documentation/CI only. PR #588 therefore adds a **positive allowlist** in the existing deployment workflow: it skips the resident deploy only when the exact merge commit contains solely H-585 test, CI, documentation and the gate file itself, and contains at least one H-585 file. Empty, unknown, oversized or mixed application diff is not granted this exemption. All normal application deploy paths remain unchanged. The skip is evaluated by GitHub Actions against the actual merged SHA; the issue must record that exact run before declaring production unchanged. This is a safety gate, not an authorization to change production infrastructure.
