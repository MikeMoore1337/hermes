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


## Public metadata retrieval (separate manual diagnostic)

`python3 -m qa_advisor.github_public --repository MikeMoore1337/hermes`

The optional module downloads at most three **public** GitHub Actions run metadata
objects via a single exact GET to api.github.com, with no GitHub token, no logs,
no redirects, no proxy environment, no writes, no retries, 12s timeout and a
700 KiB body limit. It reduces the response to allowlisted fields before the
no-network analyzer sees it. Rate limit, HTTP, schema and DNS failures are
`UNKNOWN`, not healthy. This component is NOT wired to the Cloudflare-only
agent container, Ops Watch timer, or autonomous alerts. Network deployment
requires separate egress review. Public metadata alone cannot prove root cause.
