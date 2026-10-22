# H-26 (#463) - Hermes tool-use performance, offline-only

## Scope / authority

This is a **synthetic, in-memory** performance and correctness comparison.
Run: `python3 -m hermes_toolperf --sha "$(git rev-parse HEAD)"`.
For machine-readable evidence use `--format json`. Neither command invokes an
LLM, Codex CLI, Hermes BRC, subprocess, a network connection or any host tools.
The Python standard library is sufficient. The CLI writes only to stdout.

Reference methodology: NousResearch/hermes-toolperf-evals,
upstream `main@4e13ec24fafe94f48c9d96f4bdadb6b5577ebc02` (review snapshot).
**No code, data, prompts, benchmarks, fixtures or assets were copied** from
upstream. License permission for source reuse has **not** been established;
this implementation is original, based solely on broad test categories.

## Gap matrix and ownership

| Existing Hermes area | Already implemented | H-26 gap / decision |
| --- | --- | --- |
| #273, `hermes_benchmark/` | 16 pinned generic agent lifecycle/evidence cases, trusted mock receipts | Reuse design principles, **do not change existing 16** |
| #291 | Offline evidence/canary admission with separate live owner gate | No model canary here; measured model performance stays **NOT_MEASURED** |
| #445, BRC DevTools | Hermetic workspaces and device-routing constraints | Run **no** live BRC/Windows/VPS tool calls |
| #480 | Typed dispatch/schema/permission enforcement contract | H-26 tests efficiency/outcomes only; #480 remains the authority for live dispatch |
| H-26 | Nine new independent in-memory task traces and state oracle | Implemented as `hermes_toolperf/`; no new runtime |

## Synthetic corpus (v1)

| Task ID | Failure class | Independent oracle |
| --- | --- | --- |
| tp-01-python-environment | repeated Python environment probe | require a valid environment receipt and a read of fixed project metadata |
| tp-02-duplicate-patch | retrying an already-applied patch | exact final file and no silently successful mismatched patch |
| tp-03-ambiguous-patch | replacing nonunique text | exact expected file; ambiguous patch fails |
| tp-04-case-sensitive-path | editing incorrect path case | exact-case allowlist and expected final state |
| tp-05-hidden-file | false inventory of dotfiles | actual hidden-file read, not an agent's `claim` |
| tp-06-large-output | oversize stdout | hard 128-byte output budget and a real read receipt |
| tp-07-multiple-directories | wrong-repository edit | only approved project-b file may change |
| tp-08-inline-script | arbitrary Python/script execution | inline commands are always refused; only trusted in-memory check qualifies |
| tp-09-large-file-read | whole-file dump | bounded chunk reads at pinned offsets 0 and 4064 |

Every case has a versioned task ID, SHA-256 of the canonical fixture,
a fixed starting state, two predefined candidate traces, an expected final
state, allowed write paths, required observations and a step/output budget.
**The SHA-256 identifies the fixture within an exact Git commit**; it is
not a signed external attestation. Fixture mutations change the hash.

The independent oracle reads the virtual post-state and actual receipts.
`claim: success` is **never** evidence. Unauthorized paths, excess calls,
missing reads/checks, ambiguous or repeated patches, oversize output and
false success claims fail closed.

## Interpreting the report

- `PASS/FAIL`: a synthetic trace satisfied or violated its oracle.
- `FIXED`: baseline failed, candidate passed.
- `IMPROVED`: both passed, but candidate needed fewer calls or emitted fewer bytes.
- `NO_GAIN`: no measured improvement under these deterministic conditions.
- `REGRESSED`: candidate did not pass the oracle.
- `tool_calls`, `retries`, `error_classes`, `output_bytes`: counts observed in
  the **in-memory interpreter only**, not actual device/tool telemetry.
- `elapsed_ms`: measured local simulation CPU time; it is **not live tool
  latency**. Do not treat it as a reliable speedup percentage.
- `model`, `tokens`, `actual_cost` are `null` for these synthetic scripts;
  real LLM performance/latency, billing and quota are **NOT_MEASURED**.

CI runs the existing unit suite and this standalone tool in the repository
quality workflow. Reports may be read in Actions summary. No new scheduled
task, model provider, private data, owner key, production worker or UI is added.

## Follow-up

Only propose a targeted tool implementation change when a genuine Hermes
failure is reproduced outside this model. The baseline/candidate labels
do **not** claim that the Hermes production toolset was improved. The
live performance/usage part of #463 remains **NOT_MEASURED**.
