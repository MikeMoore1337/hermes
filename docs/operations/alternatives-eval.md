# H-31 / #476 — Autoreason / Nomos: evidence-first A/B/AB comparison

**Decision: CONDITIONAL**: keep the narrow **synthetic offline comparator**.
**DEFER** model generation or LLM judge panels; **NO_GO** automatic skill
rewrites, PR approval, merge/deploy, paid APIs, long-running loops, BRC
permissions or a separate plugin/runtime framework.

## Upstream and licenses (reviewed 22 October 2026)

| Reference | exact reviewed main SHA | reuse |
| --- | --- | --- |
| NousResearch/autoreason | `538f8817550e7c76c92355a967c5363d55ef9659` | Repository license metadata **UNKNOWN**; methodology only, no files copied |
| NousResearch/nomos | `f7008a065072d11088878e2f499776a5ae4b5c95` | Repository metadata MIT, individual-file rights unverified; methodology only, no files copied |

Autoreason describes *unchanged incumbent A*, adversarial revision B,
synthesis AB, blinded independent choice and termination on no gain. Its
paper's Borda/CodeContests results are **not metrics for Hermes**.
Nomos focuses on mathematical proof-writing: use only independent checking,
bounded comparison and stop conditions, **not** its mathematics benchmark
or GPU/large model execution. No upstream source/data/assets or dependencies
are imported.

Toolkit methods used, read-only: `ai-engineering-qa`,
`test-analysis-design`, `quality-gate-assessment`.

Existing Hermes components: `hermes_benchmark` (#273) checks agent lifecycle,
`hermes_toolperf` (#463/#480) checks individual tools, `hermes_context_eval`
(#466) preserves decision facts and `hermes_reasoning_eval` (#477)
checks planned state transitions. **The new gap is choosing between already
available candidate conclusions**, including "do nothing", without self-grading
or a fake approval. #465 self-evolution remains a separate manual-review task.

## Synthetic protocol, not a model evaluator

Twelve original cases in `hermes_decision_eval/cases.py` have unique ID,
version 1, synthetic baseline SHA, fixed factual truth IDs/weights,
mandatory facts, allowed scope `review`, evaluation budget, judge-trust
condition, fixed candidates `A/B/AB` and **independently authored expected**
winner/stop reason.

The external-candidate-facing fields `self_score` and
`claimed_approval` are explicitly ignored by the oracle. It first rejects
unsupported claims, missing mandatory facts, incorrect synthetic proof IDs,
out-of-scope actions and step budgets. It then scores only eligible candidates
from independently specified facts; verified score must be **strictly
greater than A** to change the incumbent. Equal gains prefer fewer synthetic
steps, then B. If no verified gain, **choose A**.

Evaluation order permutations cannot change verdicts. A fake majority
(B and AB agree) cannot override the fact-and-proof oracle. With evaluation
budget fewer than three or untrusted judge, **evaluate only A** and mark B/AB
`NOT_RUN`. The fixture proof strings `proof:<fact_id>` and baseline SHA
are **invented synthetic values, not actual signed GitHub/source receipts**.
The test does **not** check scientific meaning from natural-language papers:
real research conclusions require independently inspected primary sources,
not LLM voting.

| Fixture | Risk and expected outcome |
| --- | --- |
| ar-01 | Imaginary defect: keep A, unsupported claims |
| ar-02 | Required owner gate/tests lost: keep A, regression |
| ar-03 | Root-cause improvement with facts: choose B |
| ar-04 | Architecture synthesis with verified extra facts: choose AB |
| ar-05 | False majority/false self-grade: keep A |
| ar-06 | Unverified scientific citation: keep A |
| ar-07 | Request for root/MCP scope: keep A, forbidden scope |
| ar-08 | Same result, more steps: keep A, no gain |
| ar-09 | Insufficient review budget: keep A; B/AB NOT_RUN |
| ar-10 | Untrusted judge: keep A; B/AB NOT_RUN |
| ar-11 | Excessive iteration steps: keep A |
| ar-12 | Claimed owner approval: keep A (not a merge authorization) |

Unit tests mutate expected winners, proofs, facts, permissions and inputs;
the independent oracle must refuse fabricated success. Fixture and dataset
SHA-256 checksums identify exact static input bytes (not signed attestations).

## Evidence, cost and applicability

Run entirely with Python standard library:

```bash
python3 -m unittest discover -s tests -v
python3 -m hermes_decision_eval.core --sha "$(git rev-parse HEAD)"
python3 -m hermes_decision_eval.core --format json
```

The existing GitHub quality check runs the offline corpus and emits counts
to the step summary, without new required checks or standalone workflows.

- `PASS/FAIL`: only correctness of the synthetic choices against fixed
  independently specified expected results.
- `NOT_RUN`: challengers never evaluated due to failed budget/judge gate.
- `UNKNOWN`: real provider cost, real approval and any real-world fact.
- `NOT_MEASURED`: LLM competence, provider latency/tokens and real-tool
  performance. Simulated step counts are **not** timing or model costs.
- `model_calls=0`: no model, BRC, Codex CLI, VPS agent, API or paid provider
  is invoked by this evaluation; no production side effect is attempted.

Applicable to contested architecture/PR decisions and QA root causes with
independent fact checks; scientific summaries require separate primary-source
verification. Stop on no improvement, lost requirements, unsupported proof,
unauthorized scope, exhausted budget, step overrun or an untrustworthy judge.
Do **not** use to authorize production changes, real incidents or autonomous
skill updates. A winning candidate is a **recommendation for review** only.

Normal source-only production deployment, if observed separately, delivers
test code and documentation, not an activated multi-model decision agent.
