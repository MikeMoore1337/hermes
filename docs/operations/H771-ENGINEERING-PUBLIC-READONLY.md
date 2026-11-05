# Hermes Engineering Control - opt-in public readers (Epic #771)

## What this release candidate adds

One **opt-in CLI** using fixed public metadata endpoints (no new GitHub/registry credentials) for:
- **ReleaseGuard #772:** PR or release-branch exact SHA, bounded Actions run metadata and current-commit PR review/draft/mergeability checks.
- **MergeControl #773:** up to 10 open GitHub PRs, changed-path overlap, rename/delete and declared \`Depends-on: #123\` relationships. Partial pagination and head changes never imply a safe merge.
- **OpenSource Radar #775:** public repository identity, pinned SHA, archive/fork state, declared license, releases and public advisory signals.
- **DepPilot #774:** *explicitly selected* packages from a local \`uv.lock\` or npm \`package-lock.json\`, current candidate metadata from official PyPI/npm endpoints and a conservative numeric runtime-bound assessment.

This is **not** a new resident agent, scheduler, source mirror, general-purpose HTTP client or GitHub workflow.

## Commands

All four commands are inert without \`--execute\`. When executed, they perform only bounded GETs. They **never write** to GitHub, install packages, run code from a foreign project, change lockfiles or authorize production.

\`\`\`bash
# No network by default
python3 -m qa_advisor.engineering_public
python3 -m qa_advisor.deppilot_registry

# Public GitHub metadata; human-triggered only
python3 -m qa_advisor.engineering_public release-pr --repository MikeMoore1337/hermes --pr 781 --execute
python3 -m qa_advisor.engineering_public release-main --repository MikeMoore1337/hermes --execute
python3 -m qa_advisor.engineering_public merge-prs --repository MikeMoore1337/hermes --execute
python3 -m qa_advisor.engineering_public radar --repository MikeMoore1337/hermes --source pypa/sampleproject --execute

# Public registry candidate metadata for explicitly selected lockfile names
python3 -m qa_advisor.deppilot_registry --lockfile /isolated/checkout/uv.lock --repository MikeMoore1337/ai-development-toolkit --runtime 3.14.0 --package pytest --execute
\`\`\`

The last command is **illustrative** and requires that the selected package actually occurs in the supplied lockfile. It does not assert any version is compatible or safely upgradable.

## Data boundaries

GitHub public API uses only \`https://api.github.com\` with a hard-coded, bounded path whitelist. It refuses external hosts, arbitrary query arguments, redirects, environment proxies, tokens, cookies, retries, large bodies and API response identity mismatches. Public registry reads are restricted to \`https://pypi.org/pypi/<project>/json\` or \`https://registry.npmjs.org/<package>/latest\`; there are no package downloads.

No content from Issue, PR descriptions, README, package metadata or Github comments is interpreted as instructions. For MergeControl only bounded \`Depends-on: #<integer>\` lines are parsed as **unverified** graph suggestions. URLs are constructed from validated repository names and numeric IDs.

All safety-relevant fields remain \`owner_approval=NOT_GRANTED\`, \`execution_authorized=false\`, \`merge_authorized=false\` or \`production_authorized=false\`. \`READY_FOR_OWNER_REVIEW\` means that the observed fields are internally consistent, **not** actual approval.

- Public GitHub access can be incomplete or rate-limited; incomplete windows, missing workflow runs, \`mergeable=null\`, stale reviews and changed SHA cause conservative output or refusal.
- GitHub Actions workflow IDs were confirmed against existing runs at development time, but **branch protection policy completeness is not proven** by listing these workflows. Current CI and approval gates must be checked separately.
- GitHub's license metadata is a **claim**, not independent license/NOTICE verification. The source SHA alone is not proof of upstream build provenance.
- \`NONE_OBSERVED\` security advisories do **not** prove absence of vulnerabilities.
- PyPI/npm release metadata comes from the package publisher or registry; numeric version/range checks are not dependency resolution, semantic-version guarantees, PEP 440 validation, transitive compatibility checks or security scans. Unknown syntax stays \`UNKNOWN\`.
- The readers do not expose Second Brain vault or call any nonpublic service or paid AI/model API.

## Checks, operating mode, and remaining gates

Targeted offline regression (no real network):
\`\`\`bash
python3 -m unittest tests.test_engineering_public tests.test_deppilot_registry tests.test_merge_control -v
\`\`\`

The adapter can only be counted as **LIVE_VERIFIED** after the *actual implementation* executes a real public API GET from an authorized runner and produces a sanitized observable report. GitHub connector reads performed in ChatGPT to verify endpoint/field examples **are not** execution of the new Python code. Without such invocation, report \`NETWORK_NOT_VERIFIED\`.

Existing \`qa_advisor/watch_once.py\`, systemd timers, root-owned state, Control Center snapshot/Operator Inbox and frontend are **unchanged**. This release does not automatically surface Engineering Control findings in the owner UI or replace #747 physical owner browser UAT. Any future production activation needs an approved cumulative main SHA and runtime/service/rollback evidence; new UI visuals must be approved separately.

## GitHub Flow

Issue → branch → PR → exact HEAD quality and relevant UI checks → reviewed merge. Deployment is a distinct owner-approved manual action, never implied by code merged to \`main\`. See repository \`AGENTS.md\`.
