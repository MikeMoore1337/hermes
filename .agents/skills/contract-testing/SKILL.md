---
name: contract-testing
description: "Protect service interfaces and message schemas from incompatibility. Use when API/event payloads, versions or providers change."
metadata:
  pack: "qa"
  version: "1.0.0"
---

# Contract Testing

1. Identify producer and consumer expectations, supported versions and compatibility policy.
2. Include required fields, types, enum handling, defaults, optional fields and unknown field behavior.
3. Exercise actual serialization/deserialization boundaries where possible; schema-only checks may miss semantic compatibility.
4. Verify backwards compatibility and deployment ordering, or explicitly document the coordinated breaking change.
5. Track consumer evidence, not just provider assumptions.

Use `contract -> consumer -> compatibility claim -> observed verification -> rollout constraint`. For event systems, cover duplicate/reordered delivery where the contract promises tolerance.


## Hermes development-only integration

Toolkit source revision: 3a9bf14772ab579d37c6f4f9615db505ab6ac259 ([original](https://github.com/MikeMoore1337/ai-development-toolkit/blob/3a9bf14772ab579d37c6f4f9615db505ab6ac259/extensions/qa/skills/contract-testing/SKILL.md)).
Use case: Hermes/YFC/Second Brain producer-consumer API contracts in approved scopes only.
This is guidance for the coding client, not a tool, runtime skill, authorization, or deployment permission. Follow `AGENTS.md`, the current Issue, boundary ownership, free-only requirements and production approvals. Never transfer it into `skills/` without a separate approved task and safety review.
