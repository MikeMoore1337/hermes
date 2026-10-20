---
name: browser-workflow-evidence
description: Run browser-based tasks with verifiable outcomes and transparent limitations. Use for UI automation, browser agents and externally hosted flows.
---

# Browser workflow evidence
1. Write a concrete goal and end-state assertion before clicking.
2. Prefer existing Playwright or browser tooling. Do not replace stable tests with a research prototype because a demo is faster.
3. Observe the current DOM/accessibility tree before actions; avoid guessed coordinates and stale element handles.
4. Use deterministic waits for conditions; bound retries and record error states.
5. Distinguish action performed from outcome verified: a success message or agent `DONE` alone is not proof.
6. For authenticated sites, restrict session scope and never export browser cookies or API keys into third-party tools by default.
7. Record environment, relevant screenshots/traces and assertions, without storing secrets or private page content unnecessarily.
8. Document unsupported iframe, shadow-root, canvas, uploads and cross-tab behavior rather than claiming broad automation coverage.

**Output:** goal, actions, independent assertions, failures/limits, evidence artifact locations.


## Hermes development-only integration

Toolkit source revision: 3a9bf14772ab579d37c6f4f9615db505ab6ac259 ([original](https://github.com/MikeMoore1337/ai-development-toolkit/blob/3a9bf14772ab579d37c6f4f9615db505ab6ac259/.agents/skills/browser-workflow-evidence/SKILL.md)).
Use case: Approved Control Center/browser tasks with actual DOM outcomes and sanitized evidence.
This is guidance for the coding client, not a tool, runtime skill, authorization, or deployment permission. Follow `AGENTS.md`, the current Issue, boundary ownership, free-only requirements and production approvals. Never transfer it into `skills/` without a separate approved task and safety review.
