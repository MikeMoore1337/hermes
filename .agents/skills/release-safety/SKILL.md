---
name: release-safety
description: Prepare and verify a release or production deployment based on the real project pipeline and granted authorization. Use for release readiness, merge or deployment work.
---


# Release safety
1. Discover current release mechanism and base branch from the repository. Never hardcode branch names or CI providers.
2. Establish exact commit/revision, required checks, migration order, rollout requirements and ownership.
3. Review backwards compatibility, data backups when necessary, feature flags and rollback or forward-fix.
4. Define verifiable smoke checks for changed critical paths and observe health beyond successful pipeline completion.
5. A clean local test or user approval of a screenshot does not itself prove a deployment happened.
6. Obtain and respect the authorization actually granted; don't infer rights from a generic skill.
7. Record PR/commit/deployment evidence and distinguish what was attempted, verified and blocked.
**Output:** readiness, executed actions, exact versions, post-release evidence, outstanding risks.


## Hermes development-only integration

Toolkit source revision: 3a9bf14772ab579d37c6f4f9615db505ab6ac259 ([original](https://github.com/MikeMoore1337/ai-development-toolkit/blob/3a9bf14772ab579d37c6f4f9615db505ab6ac259/.agents/skills/release-safety/SKILL.md)).
Use case: Exact SHA and production evidence only for existing approved services; does not grant activation.
This is guidance for the coding client, not a tool, runtime skill, authorization, or deployment permission. Follow `AGENTS.md`, the current Issue, boundary ownership, free-only requirements and production approvals. Never transfer it into `skills/` without a separate approved task and safety review.
