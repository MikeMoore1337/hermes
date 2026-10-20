---
name: change-impact-analysis
description: "Map a change to affected contracts, callers, state and regression tests. Use before modifying shared code, contracts, migrations or agent tools."
metadata:
  pack: "qa"
  version: "1.0.0"
---

# Change Impact Analysis

1. Identify changed behavior and affected API, event schema, database tables, UI routes, clients and operational workflows.
2. Search the repository for references and callers; inspect tests and documentation. External code graphs are optional, never mandatory.
3. Classify each impact as direct, downstream, compatibility, deployment or uncertain; provide an evidence link or path for each.
4. Choose targeted regression tests and smoke checks, including negative/rollback paths for high-risk changes.
5. Escalate risk for auth, PII, data migration, irreversible actions and cross-service contracts. Unknown callers are a limitation, not proof of safety.

Deliver: `change -> affected surface -> failure mode -> test -> remaining uncertainty`. Avoid blanket full-suite recommendations for trivial isolated changes.


## Hermes development-only integration

Toolkit source revision: 3a9bf14772ab579d37c6f4f9615db505ab6ac259 ([original](https://github.com/MikeMoore1337/ai-development-toolkit/blob/3a9bf14772ab579d37c6f4f9615db505ab6ac259/extensions/qa/skills/change-impact-analysis/SKILL.md)).
Use case: Changes crossing agents, scheduled units, boundaries or deployments.
This is guidance for the coding client, not a tool, runtime skill, authorization, or deployment permission. Follow `AGENTS.md`, the current Issue, boundary ownership, free-only requirements and production approvals. Never transfer it into `skills/` without a separate approved task and safety review.
