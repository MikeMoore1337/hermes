# H-01 #33 - v0.22.2 immutable image and native tool-policy negative evidence

Date: 2026-10-16. Execution host: **separate Windows Docker Desktop**.
Official release: https://github.com/NousResearch/hermes-agent/releases/tag/v0.22.2
Mode: bounded isolated **offline Docker only**; no VPS/YFC/Cloudflare/real-model,
third-party connector, shell executor, secrets, database or production service.
The official image is unmodified. All tool and model calls use synthetic stubs.

## Exact source and image identities

- Official tag peeled source: `d923a5eb487a17c0a68801bba9ef0f56c81040a8`.
- Docker Hub immutable Linux/AMD64:
  `nousresearch/hermes-agent@sha256:a11574b7fe8e1631d7d88d556677dac693bc058abf558cdeb899155688c1bf05`.
- Real `docker pull --platform linux/amd64` of **that exact digest**:
  completed; reported digest matches, no :latest/:stable.
- Real read-only `docker image inspect` verifies digest and architecture.
- Real immutable Docker `/opt/hermes/install-stamp.json`:
  `commit` matched official source; Python interpreter **3.14.7**.
- **Important:** an image-embedded stamp can be set by an image builder.
  Therefore source-to-build-to-image provenance remains **UNATTESTED**, even
  though this commit value matched. Signature, transparency log, CI builder
  attestation and full third-party dependency provenance remain **NO_DATA**.

## Real image, synthetic tool policy

Probe: `python -m scripts.verify_v0222_immutable --execute`; returns exit
code 2/NO-GO **intentionally**. Runs immutable image under
`--pull=never --network none --read-only --cap-drop ALL --security-opt
no-new-privileges --user 65534:65534 --cpus 0.5 --memory 768m
--memory-swap 768m --pids-limit 64` and a small noexec tmpfs.
No host mount, provider token, database credentials or Docker socket.

Existing 20-case v0.22.1 inspector was applied to the actual v0.22.2 code,
with `_execute_tool` / dangerous executor paths **replaced before dispatch**.
Original v0.22.2 returned:

- `status=OFFLINE_V0222_GAP_OBSERVED`;
- `direct_terminal_executor_reached=true`;
- `stale_agent_terminal_executor_reached=true`;
- `full_agent_loop_terminal_executor_reached=true`;
- `nested_terminal_allowed=true`;
- `parallel_restricted_executor_reached=true`;
- `model_executed=false`, `real_tool_executed=false`.

These flags mean forbidden requests reach **synthetic** executor stubs. It is
not proof that a forbidden OS command was executed. It is P0 evidence of
insufficient direct native dispatch authorization in the official build.

## Local candidate patch on exact new base

An isolated derivative is built only from **that exact pinned v0.22.2** and
existing reviewed v0.22.1 patch via
`docker build --pull=false --network none -f
docker/v0222-native-tool-policy-test/Dockerfile -t
hermes-v0222-native-policy-candidate:20261016 .`.
`git apply --unidiff-zero --check` and actual apply both succeeded.
Local candidate image ID:
`sha256:dc5d2836470bb49f9ffe5e173fd28ce26736370bca5d26959744f95f2980618b`.
This is **not** an official upstream image and not approved for production.

Command `python -m scripts.verify_v0222_immutable --execute --compare-patched`
runs the same inspector against original and local derivative with identical
no-network/nonroot/read-only constraints. **Observed**:
`PATCHED_NATIVE_TOOL_POLICY_BOUNDED_PASS`,
`original_gap_reproduced=true`,
`patched_checked_paths_blocked=true`,
`allowed_synthetic_paths_work=true`,
`model_executed=false`, `real_tool_executed=false`,
`resident_agent_allowed=false`.

This is a checked synthetic tool-path fix candidate, **not** full MCP API /
plugins/hooks / network / production or complete threat model certification.
Upstream source review/patch acceptance or reviewed locally maintained
derivative, independent attestation and regression tests are still required.

## Vulnerabilities / supply chain

The exact v0.22.2 `pm/lock.json` pins Python
`3.14.7+20260901`, Node `26.7.0`, npm `12.0.2`.
The real image returned Python 3.14.7. Official Python 3.14.8 security
release on 2026-09-30 fixed CVE-2026-15310, CVE-2026-19672,
CVE-2026-15806, CVE-2026-19445, CVE-2026-19553,
CVE-2026-17084. Actual exploitability of each CVE in Hermes was **NOT
ASSESSED**, nor was a complete dependency/OS CVE or licensing scan. Status
`POTENTIALLY_AFFECTED / NO_DATA`; no claim of an actual compromise.
Source: https://www.python.org/downloads/release/python-3148/

## Next P0 gates / disposition

1. Independent release receipt, signed source-to-build-to-image attestation,
   full SBOM and dependency/license/CVE assessment.
2. Patch correctness and complete OS/native/MCP scope proof on **v0.22.2**;
   clarify direct native dispatch, hooks and out-of-session tools.
3. Strict Free billing enforcement, no paid fallback, admission for load,
   restart and failure recovery with production services protected.
4. Owner GO of exact reviewed image, model, permissions and host.

**Result: offline original GAP OBSERVED; local patch BOUNDED PASS;
official immutable image resident `NO-GO`.** Never deploy it as resident
because a synthetic regression suite passed.
