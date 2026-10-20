---
name: agent-framework-fit
description: Evaluate whether an agent orchestration framework is justified before proposing LangGraph, CrewAI, DeerFlow or a complete agent runtime. Use for multi-agent architecture tasks.
---

# Agent framework fit
1. Decide whether the task needs a library, a standalone agent product, a task scheduler, or just a simple Python function.
2. Record real requirements: durable state, resume after failure, deterministic routing, human approvals, traceability, parallelism, multi-channel interface and deployment footprint.
3. Compare the status quo to a thin task runner before considering LangGraph, CrewAI, DeerFlow or an existing agent runtime.
4. Treat similarly named agent runtimes as independent products, not drop-in updates to existing repositories. Never overwrite an existing implementation.
5. Prefer focused patterns over adopting an entire framework for one small workflow; quantify integration and migration costs.
6. Test interrupts/retries/idempotency, state serialization, error handling, observability and budget caps for serious runtime changes.
7. Do not automatically install or migrate to a framework based on benchmark, popularity or repository name.

**Output:** requirement matrix, build-vs-integrate options, compatibility risk, minimal proof-of-concept recommendation.


## Hermes development-only integration

Toolkit source revision: 3a9bf14772ab579d37c6f4f9615db505ab6ac259 ([original](https://github.com/MikeMoore1337/ai-development-toolkit/blob/3a9bf14772ab579d37c6f4f9615db505ab6ac259/.agents/skills/agent-framework-fit/SKILL.md)).
Use case: Assess need for agent runtime/orchestration changes instead of adding frameworks by default.
This is guidance for the coding client, not a tool, runtime skill, authorization, or deployment permission. Follow `AGENTS.md`, the current Issue, boundary ownership, free-only requirements and production approvals. Never transfer it into `skills/` without a separate approved task and safety review.
