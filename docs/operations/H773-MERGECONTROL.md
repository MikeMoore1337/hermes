# MergeControl v1 - offline PR risk review (#773)

MergeControl extends the existing Hermes **QA Advisor** with deterministic, read-only analysis of supplied PR evidence. It **does not** fetch live GitHub data, execute agents, rebase branches, merge PRs or establish that an overlap is a real Git conflict.

## What is checked

- Only \`MikeMoore1337/hermes\`, \`MikeMoore1337/ai-development-toolkit\`, and \`MikeMoore1337/your-fitness-coach\` are supported.
- Allowed base branches: \`main\` for Hermes and Toolkit; \`dev\`/\`master\` for YFC. A proposed order never bypasses YFC \`dev → master\`.
- A bounded snapshot of at most 24 PRs, each with at most 120 changed file records, pinned PR/base SHA, known \`files_complete\` and \`window_complete\` flags.
- Path overlap includes rename origins and new paths, and deletions. The only classification for that overlap is **\`POTENTIAL_OVERLAP_NOT_PROVEN_CONFLICT\`**. Two PRs can both edit one file and merge cleanly.
- GitHub \`mergeable=dirty\` supplied through this offline input is reported as \`github_dirty_reported_input_only\`, **not** independent confirmation of a real conflict.
- Explicit PR dependency links are treated as unverified claims; topological order is only a proposal. Missing dependencies, cycles, different base SHAs, unknown mergeability, pagination gaps and stale snapshots are identified separately.
- User-controlled PR bodies, arbitrary URLs and instructions are not parsed or executed. Output PR URLs are synthesized only from the allowlisted repository and numeric PR numbers.

## Synthetic input format

\`\`\`json
{
  "schema": "hermes-mergecontrol-evidence-v1",
  "repo": "MikeMoore1337/hermes",
  "observed_at": "2026-11-05T08:55:00Z",
  "window_complete": true,
  "prs": [
    {
      "number": 11,
      "head_sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "base_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "base_branch": "main",
      "draft": false,
      "mergeable": "clean",
      "files_complete": true,
      "files": [
        {"path": "qa_advisor/core.py", "previous_path": null, "status": "modified"}
      ],
      "depends_on": []
    },
    {
      "number": 12,
      "head_sha": "cccccccccccccccccccccccccccccccccccccccc",
      "base_sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
      "base_branch": "main",
      "draft": false,
      "mergeable": "unknown",
      "files_complete": true,
      "files": [
        {"path": "qa_advisor/core.py", "previous_path": null, "status": "modified"}
      ],
      "depends_on": [11]
    }
  ]
}
\`\`\`

This example is **synthetic** and is not a verification of any real PR.

## Commands

\`\`\`bash
python3 -m unittest tests.test_merge_control -v
python3 -m qa_advisor.merge_control
python3 -m qa_advisor.merge_control --input /path/to/sanitized-pr-snapshot.json
\`\`\`

Without \`--input\`, the program prints \`NOT_EXECUTED\` and accesses no files/network. Input must be a non-symlink regular JSON file no larger than 64 KiB. Any malformed evidence is rejected with a fixed code and nonzero exit.

## Status

- \`REVIEW_REQUIRED\`: at least one input-based risk signal (overlapping paths, dirty reported state, draft in window, or detected dependency cycle).
- \`INCONCLUSIVE\`: no risk observed, but data is stale, incomplete, ambiguous or references unavailable PRs.
- \`NO_OVERLAP_IN_SUPPLIED_WINDOW\`: **only** the complete, fresh, internally consistent provided snapshot has no reported risks. It cannot establish absence of conflicts across all GitHub PRs without authenticated source verification.

All results fix \`evidence_verified=false\`, \`window_exhaustive_verified=false\`, \`merge_authorized=false\`, \`execution_authorized=false\`, \`owner_approval=NOT_GRANTED\`. Order and dependencies are unverified.

## Remains for Issue #773

- Authorized, bounded read-only GitHub ingestion of open PR metadata, actual complete changed-file pages and exact HEAD/base SHA (no unapproved tokens or broad OAuth scopes).
- Reliable GitHub mergeability verification and stale/synchronize handling, including a reviewed approach for fork/rename cases.
- Wiring the sanitized result into the existing QA/Operator Inbox contract and any approved UI (no unauthorized redesign).
- Mainline focused regression and full exact-HEAD GitHub CI, independent review, separate owner authorization for production release and its runtime verification.

## Exclusions

No Codex chat observation, no agent scheduler, no background file access, no direct YFC/Second Brain writes, no private vault or paid model calls.
