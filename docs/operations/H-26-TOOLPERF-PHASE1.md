# H-26 Toolperf: baseline and first narrow fix (Issue #463)

Status: **PARTIAL / OFFLINE ONLY**. This document records code-level coverage, not measured performance of real Hermes MCP, ChatGPT, Codex, or upstream NousResearch.

## Reuse before adding another benchmark

- `hermes_toolperf/` **already includes all nine deterministic H-26 cases** (`tp-01` through `tp-09`), baseline/candidate comparisons, SHA256 fixture IDs, negative tests in `tests/test_hermes_toolperf.py` and a dedicated exact-SHA CI step. The new change here is a separate validation improvement in the older `hermes_benchmark` path guard, **not** creation of the original Toolperf suite.
- Existing `hermes_benchmark/core.py` owns the 16 pinned synthetic cases and independent file-state verification. Cases `hb-02`, `hb-03`, `hb-09`, `hb-14`, `hb-15`, and `hb-16` already reject incorrect patches, forged CI, duplicate dispatch after uncertain start, partial failure, forbidden tools, and false delivery claims.
- `hermes_benchmark/canary.py` and `canary_admission.py` are a separate live-admission workstream (#291), not sources of actual tool performance measurements.
- Hermes device tooling belongs to `device_fabric/` and the H-15 scoped BRC connection. Offline tests cannot establish native Windows process, filesystem or MCP permissions, latency, usage, or measured provider cost.
- No copied upstream code or additional runtime/benchmark framework.

## Phase 1: reproducible defect

The existing fixture path guard converted a path to `PurePosixPath` **before** checking its type. Certain inputs (including `.`) could produce an unintended exception, while aliases such as `src//task.txt`, `src/./task.txt`, or `src/task.txt/` collapsed to the same filesystem location but retained a different literal allowlist identity.

`_path` now rejects non-strings, empty/dot paths, NUL, noncanonical POSIX spelling, absolute/traversal, Windows separators and drive-like colons. It retains the existing policy rejecting hidden *top-level* names. The mocked writer still has to pass `allowed_operations`; rejection does not modify files. This is **input normalization of the offline benchmark**, not an OS-level filesystem boundary for Hermes BRC.

Targeted checks: `python3 -m unittest tests.test_toolperf_path_canonicalization -v`.

## Existing H-26 coverage and remaining live gaps

All nine classes have **pre-existing, passing synthetic coverage** in `hermes_toolperf/cases.py` and `tests/test_hermes_toolperf.py`. Their in-memory scripts do not measure real MCP, OS, Codex or model tool use.

| Class | Already tested offline | Not yet independently verified |
| --- | --- | --- |
| Python environment mismatch | `tp-01-python-environment` | Real client/toolchain versions and retries |
| Repeated patch | `tp-02-duplicate-patch` | Real write idempotency and file receipts |
| Ambiguous edit | `tp-03-ambiguous-patch`; this PR additionally rejects malformed benchmark paths | Real ambiguous text-replacement tool behavior |
| Case-sensitive lookup | `tp-04-case-sensitive-path`; this PR adds a benchmark name-distinction test | Windows host vs POSIX sandbox behavior |
| Hidden files | `tp-05-hidden-file` | Actual BRC discovery, permissions and hidden-path scope |
| Oversized output | `tp-06-large-output` | Real output truncation and safe continuation |
| Multiple directories | `tp-07-multiple-directories` | Actual allowed roots, symlink and device boundaries |
| Inline scripts | `tp-08-inline-script` | Real tool command/argument enforcement |
| Large-file reads | `tp-09-large-file-read` | Real paginated/ranged reads and integrity |

The new `tests/test_toolperf_path_canonicalization.py` is **supplementary**: it tests path spelling/validation in `hermes_benchmark`, not the existing nine-case `hermes_toolperf` oracles.

## Next stages, not claimed complete

1. Map the existing nine Toolperf classes to actual scoped BRC tool contracts and independently observed outcomes. Keep fixture IDs, expected end-state hashes, and baseline/candidate commits pinned.
2. Add or extend a deterministic offline oracle **only when a real gap is demonstrated** beyond `hermes_toolperf` and `hermes_benchmark`. Keep synthetic counts distinct from real tool observations.
3. Only after authoritative execution traces exist, compare tool call counts, retries, sanitized bytes and elapsed times. Tokens, paid cost and real model behavior remain `NOT_MEASURED` / `NOT_RUN` without trusted evidence.
4. Run exact-head CI, inspect PR diff, and follow existing GitHub Flow. No new scheduler, credentials, live model requests, resident agent activation or production service changes.

Toolkit methods: `change-impact-analysis`, `contract-testing` from the pinned development-only `.agents/skills` library. Source-reuse decision: **extend existing verifier, do not fork NousResearch's toolperf engine**.
