# H-26 Toolperf: baseline and first narrow fix (Issue #463)

Status: **PARTIAL / OFFLINE ONLY**. This document records code-level coverage, not measured performance of real Hermes MCP, ChatGPT, Codex, or upstream NousResearch.

## Reuse before adding another benchmark

- Existing `hermes_benchmark/core.py` owns the 16 pinned synthetic cases and independent file-state verification. Cases `hb-02`, `hb-03`, `hb-09`, `hb-14`, `hb-15`, and `hb-16` already reject incorrect patches, forged CI, duplicate dispatch after uncertain start, partial failure, forbidden tools, and false delivery claims.
- `hermes_benchmark/canary.py` and `canary_admission.py` are a separate live-admission workstream (#291), not sources of actual tool performance measurements.
- Hermes device tooling belongs to `device_fabric/` and the H-15 scoped BRC connection. Offline tests cannot establish native Windows process, filesystem or MCP permissions, latency, usage, or measured provider cost.
- No copied upstream code or additional runtime/benchmark framework.

## Phase 1: reproducible defect

The existing fixture path guard converted a path to `PurePosixPath` **before** checking its type. Certain inputs (including `.`) could produce an unintended exception, while aliases such as `src//task.txt`, `src/./task.txt`, or `src/task.txt/` collapsed to the same filesystem location but retained a different literal allowlist identity.

`_path` now rejects non-strings, empty/dot paths, NUL, noncanonical POSIX spelling, absolute/traversal, Windows separators and drive-like colons. It retains the existing policy rejecting hidden *top-level* names. The mocked writer still has to pass `allowed_operations`; rejection does not modify files. This is **input normalization of the offline benchmark**, not an OS-level filesystem boundary for Hermes BRC.

Targeted checks: `python3 -m unittest tests.test_toolperf_path_canonicalization -v`.

## Toolperf gap matrix (nine upstream-inspired classes)

| Class | Evidence already present | Remaining gap |
| --- | --- | --- |
| Python environment mismatch | H-15 #445 describes real developer-image toolchain checks | Compare actual client environments on exact revisions, not fixture success |
| Repeated patch | `hb-02` incorrect patch, `hb-14` partial failure | Repeated *same* patch, idempotency and observed file state |
| Ambiguous path/edit | This PR rejects noncanonical aliases in benchmark paths | Ambiguous text replacement and BRC tool calls |
| Case-sensitive lookup | Offline path-name test preserves case | Windows host vs POSIX sandbox behavior |
| Hidden files | First-component hidden names denied | Scoped discovery and nested hidden paths |
| Oversized output | `MockBus.snapshot` rejects files above 4096 bytes | Actual truncation, output-limit evidence and safe continuation |
| Multiple directories | Absolute and traversal fixture paths denied | Real allowed-roots, symlinks and per-device permission boundaries |
| Inline scripts | Existing mock actions never execute shell commands | Real tool command/argument validation without unsafe execution |
| Large-file reads | Existing 4096-byte snapshot bound | Bounded range reads and caller-visible pagination |

## Next stages, not claimed complete

1. Select actual relevant BRC tool contracts and independently observed outcomes for the remaining nine classes. Keep fixture IDs, expected end-state hashes, and baseline/candidate commits pinned.
2. Add an instrumented deterministic offline oracle **only for gaps not already represented** in `hermes_benchmark`, and label synthetic counts separately from real tool use.
3. Only after authoritative execution traces exist, compare tool call counts, retries, sanitized bytes and elapsed times. Tokens, paid cost and real model behavior remain `NOT_MEASURED` / `NOT_RUN` without trusted evidence.
4. Run exact-head CI, inspect PR diff, and follow existing GitHub Flow. No new scheduler, credentials, live model requests, resident agent activation or production service changes.

Toolkit methods: `change-impact-analysis`, `contract-testing` from the pinned development-only `.agents/skills` library. Source-reuse decision: **extend existing verifier, do not fork NousResearch's toolperf engine**.
