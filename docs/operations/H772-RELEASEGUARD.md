# ReleaseGuard v1 - offline precheck (#772)

This implementation is a **read-only, deterministic evidence consistency checker** inside the existing Hermes QA Advisor package. It does **not** fetch GitHub data, verify trust of its input, bypass branch protection, merge PRs, deploy or authorize a release. A code review or runtime release requires separate evidence and owner approval.

## Purpose and coverage

- Allowed repositories: \`MikeMoore1337/hermes\`, \`MikeMoore1337/ai-development-toolkit\`, \`MikeMoore1337/your-fitness-coach\`.
- Strict target branch policy: Hermes/Toolkit \`main\`; YFC PR \`dev\`, YFC release \`master\`.
- Explicit candidate SHA, observed branch SHA, observed-at timestamp, required workflow IDs, per-workflow run ID/status/conclusion/head SHA, and PR draft/review/mergeability states.
- Checks must be exact-SHA, successfully completed, and in a declared required-workflow list. A missing, pending, cancelled, neutral or skipped check **never** proves success. Unknown mergeability and stale evidence never become green.
- A YFC release is always \`INCONCLUSIVE\` until its separate \`dev → master\` gate is independently verified by an authorized component.
- Source URLs are synthesized only from an allowlisted repository plus numeric run IDs; arbitrary GitHub text/links are not echoed.

## Input

Example **synthetic** \`release-evidence.json\` for an offline PR consistency check:

\`\`\`json
{
  "schema": "hermes-releaseguard-evidence-v1",
  "repo": "MikeMoore1337/hermes",
  "stage": "PR",
  "branch": "main",
  "candidate_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "observed_head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
  "observed_at": "2026-11-05T08:55:00Z",
  "required_workflows": [381262090],
  "checks": [
    {
      "workflow_id": 381262090,
      "run_id": 12345,
      "head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "status": "completed",
      "conclusion": "success"
    }
  ],
  "review": {
    "state": "approved",
    "head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "mergeability": "clean",
  "draft": false
}
\`\`\`

Only a source-bound, authenticated caller can attest the required-workflow inventory and whether GitHub metadata describes this specific candidate. The example intentionally contains invented test values. **Do not use it as evidence for a real release.**

## Commands

\`\`\`bash
python3 -m unittest tests.test_release_guard -v
python3 -m qa_advisor.release_guard
python3 -m qa_advisor.release_guard --input /path/to/sanitized/release-evidence.json
\`\`\`

Without \`--input\` the CLI prints \`{"status": "NOT_EXECUTED"}\` and does not read any files/network. With \`--input\` it reads at most 32 KiB from a non-symlink regular file. On refusal it emits a fixed error code, not supplied text, and exits \`2\`.

## Output semantics

- \`BLOCKED\`: at least one evidenced blocker such as red required CI, draft PR, changes requested, or reported merge conflict.
- \`INCONCLUSIVE\`: absent/stale/conflicting evidence, unknown mergeability, non-proving CI, missing review confirmation or unverified YFC release chain.
- \`READY_FOR_OWNER_REVIEW\`: **only the supplied fields are internally consistent**; it does **not** establish that those fields came from GitHub or that required checks are exhaustively enumerated. No automated release action may consume this status as a GO.

All outputs fix \`evidence_verified=false\`, \`required_workflow_policy_verified=false\`, \`owner_approval=NOT_GRANTED\`, \`deploy_authorized=false\`, \`execution_authorized=false\`, \`production_evidence=NOT_VERIFIED\`. These cannot be overridden by input.

## Integration still required for Issue #772

- Independently obtain **live** GitHub evidence for exact commit SHA (Actions/checks, policies, reviews/mergeability), using existing authorized integration and no new permission scope.
- Verify required workflows against target branch policy and verify whether the captured snapshot remains current before giving an operator-facing readiness recommendation.
- Reuse the existing QA Advisor / Operator Inbox rather than inventing a new scheduler or UI. Any visual changes require separate owner approval.
- Run repository and UI CI on the exact PR SHA; the existing release contract requires a separate owner authorization for the exact cumulative production SHA, server health, actual installed files, and rollback evidence. Do not treat this module's offline tests as production proof.

## Boundaries

No production changes, writes to YFC/Toolkit repositories, private vault access, new credentials, LLM calls or additional resident services. The old SBOM/CVE backlog remains independent of the release-candidate functional gates.
