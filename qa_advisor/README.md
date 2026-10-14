# Hermes QA Advisor - offline GitHub CI triage

**Only metadata classification, not deployed and no live GitHub connector.**

Partial [Issue #5](https://github.com/MikeMoore1337/hermes/issues/5).
For now the module accepts already-provided synthetic/scoped GitHub Actions
metadata for two explicitly allowlisted repositories: Hermes and YFC.
No Second Brain data is authorized by this module.

Allowed input fields: repo, workflow name, run id, full SHA, status,
conclusion, list of bounded job names and conclusions. All other fields,
including unredacted logs/tokens, are rejected.

Output is a deterministic list of suspected failure categories, not a
claim of verified root cause. If the SAME repo+workflow+SHA has both success
and failure, label **possible flakiness, compare environments**. No reliable
flake diagnosis can be made from metadata alone.

Not done: scoped read-only GitHub API tokens, fetching sanitized CI logs,
live monitoring or Telegram alerts. These require separate owner-approved
permissions, authentication, quota/egress and tested data-redaction controls.
No code here can write Issues, change branches, rerun CI, merge PRs or deploy.
