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


## Opt-in metadata retrieval (manual only, not deployed)

Public YFC: `python3 -m qa_advisor.github_public --repository MikeMoore1337/your-fitness-coach`

Private Hermes: `python3 -m qa_advisor.github_public --repository MikeMoore1337/hermes`

Hermes is **private** and cannot be fetched anonymously. Its command fails closed
before network unless an explicitly owner-installed fine-grained GitHub PAT or
GitHub App installation token exists at `/etc/hermes-agent/github-actions-read.token`.
The dedicated file must be a non-symlink regular file, 0600 and owned by the
running UID; the token must be scoped ONLY to Hermes with repository Actions:
read and no write permissions. Do not use a broad classic `repo` token,
the YFC editorial token, or an unscoped environment variable. No token is
created or installed by the code, and no periodic access is enabled.

The optional module fetches at most three GitHub Actions run metadata records
via one exact GET to api.github.com, no logs, redirects, proxies, retries
or GitHub writes (12-second timeout, 700 KiB bound). HTTP errors, absent
permissions, schema faults and rate limits yield `UNKNOWN`, never healthy.
Only allowlisted metadata reaches offline triage; no token or raw response is
printed. The code is not connected to the Cloudflare-only AI agent, Ops Watch
or scheduled monitoring. Network egress and permission scopes require separate
approval and verification before live use.
