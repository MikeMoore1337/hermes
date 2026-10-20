---
name: provider-reality-check
description: Evaluate current LLM provider free tiers and API compatibility using official sources and reproducible checks. Use for API routing, budget estimates and free-provider selection.
---

# Provider reality check
1. Treat community 'free LLM' collections as leads, not authoritative guarantees of permanent commercial availability.
2. For each candidate verify official pricing, terms, model IDs, quota/reset, rate limits, region, data retention, key requirements and modality.
3. Distinguish free trial credits, perpetual rate-limited tiers, non-commercial-only use and paid-only endpoints.
4. Compare expected token requests, output limits, concurrency, availability, and routing/fallback behavior.
5. Test actual provider identity and response compatibility only through authorized non-production keys, with explicit spending caps.
6. Never infer absence of cost from 'OpenAI-compatible'; compatibility is a protocol claim, not financial assurance.
7. Record observation timestamp and expiry window; revalidate before making production decisions.

**Output:** provider evidence table, latest source dates, viability and failover constraints, unresolved facts.


## Hermes development-only integration

Toolkit source revision: 3a9bf14772ab579d37c6f4f9615db505ab6ac259 ([original](https://github.com/MikeMoore1337/ai-development-toolkit/blob/3a9bf14772ab579d37c6f4f9615db505ab6ac259/.agents/skills/provider-reality-check/SKILL.md)).
Use case: Evaluate Free tier, model compatibility and quota via read-only research; no paid calls.
This is guidance for the coding client, not a tool, runtime skill, authorization, or deployment permission. Follow `AGENTS.md`, the current Issue, boundary ownership, free-only requirements and production approvals. Never transfer it into `skills/` without a separate approved task and safety review.
