# Engineering Control → existing Operator Inbox (Epic #771)

**Scope:** sanitized data-only integration, not a new UI, scheduler, agent, API endpoint, credential, deployment action, or autonomous GitHub client. The existing protected Control Center \`/api/operator/inbox\` remains read-only and authenticates via the same owner session. Frontend source and styles are **unchanged**.

## Data flow

\`\`\`text
Explicit owner operation (not a timer)
  qa_advisor.engineering_once --execute [optional --source / --lockfile]
      ├── Existing ReleaseGuard exact SHA / CI observation
      ├── Existing MergeControl bounded open-PR overlap analysis
      ├── Optional OpenSource Radar public source
      └── Optional DepPilot official registry check for selected packages
  qa_advisor.engineering_feed.build()  [fixed enums, counts, timestamps]
  qa_advisor.engineering_feed.save()   [only with explicit --save]
      └── /var/lib/hermes-qa-watch/engineering-inbox.json (root 0700, file 0600)
            Existing root control_center.snapshot collector (no network)
              └── overview.json (owner-only group projection)
                   └── existing Operator Inbox route + React component
\`\`\`

The root collector independently validates the file through \`control_center.engineering_view\` because the web release does **not** deploy the \`qa_advisor\` package with the Control Center server. No raw GitHub PR/Issue text, script, URL, package content, license text, secret, source code or authorization is present in the feed. Only enum status, fixed module key, reason count and checked-at time cross the boundary.

## Run only after an explicit operator action

\`\`\`bash
# Purely inert by default
python3 -m qa_advisor.engineering_once

# Bounded public GitHub inspection, no persistence
python3 -m qa_advisor.engineering_once --execute --repository MikeMoore1337/hermes

# Optional public OSS assessment (source identity/commit, declared license, advisory signals)
python3 -m qa_advisor.engineering_once --execute --repository MikeMoore1337/hermes --source pypa/sampleproject

# Selected lockfile candidate: metadata only, no install/manifest changes
python3 -m qa_advisor.engineering_once --execute --repository MikeMoore1337/hermes \
  --lockfile /approved/isolated/project/uv.lock --runtime 3.14.0 --package pytest

# Root-owned QA watcher state (only authorized Linux operator with pre-existing 0700 directory)
python3 -m qa_advisor.engineering_once --execute --repository MikeMoore1337/hermes --save
\`\`\`

There is **no network access in the web process** and no UI button that starts this operation. The \`--save\` form is an explicit write of a minimal root-owned sanitized JSON file to the existing QA watcher directory, not a write to GitHub/YFC or a new service. When a network source is unavailable, it is marked \`NOT_AVAILABLE\`; if *all* sources fail, an old snapshot is preserved and the command fails safely.

## What a visible status means

- \`READY_FOR_OWNER_REVIEW\`: ReleaseGuard says **review evidence**, never an authorized release.
- \`BLOCKED\`, \`REVIEW_REQUIRED\`, \`INCONCLUSIVE\`: investigate reasons in the separate source CLI/PR and independently verify exact SHA and required CI.
- \`NO_OVERLAP_IN_SUPPLIED_WINDOW\`: a bounded, source-incomplete GitHub window is not proof that all PRs will merge.
- \`PILOT_REVIEW\` or \`HOLD_FOR_REVIEW\`: no license, security, compatibility, installation or publication approval.
- \`NOT_AVAILABLE\` / \`STALE\`: no current proof. Stale record content is hidden from the Inbox.

The Inbox's source coverage remains \`PARTIAL\` even when some provided reports claim a positive result. Operator action never creates \`owner_approval\`, \`merge_authorized\`, \`install_authorized\`, \`execution_authorized\`, or \`production_authorized\`.

## Testing and release gates

- \`python3 -m unittest tests.test_engineering_feed tests.test_engineering_once tests.test_control_center_operator_inbox -v\` plus baseline repository/UI tests.
- Negative cases: forged approval, unknown source/status, prompt injection in raw report data, stale/future evidence, root-owned file permissions, symlink inputs, network failure and preservation of previous state, no implicit execution, zero raw data in Inbox, existing services unchanged.
- Owner authenticated browser UAT remains independently OPEN as #747: synthetic tests are **not** owner session or proof of actual production UI.
- Source-only/CI success is not a production release. Existing \`main\` release requires exact SHA quality + UI checks, separate owner approval and installed/runtime/rollback verification. **No production changes** are authorized by this Issue alone.

**Limit:** The published feed uses manually invoked on-demand observations. Automatic periodic collection has intentionally NOT been added to the existing 22-second QA watcher, whose source and latency budgets already exist. Scheduling/enabling new network or production behavior requires a separately reviewed change.
