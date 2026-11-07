---
name: impeccable
description: "Primary development-only UX/UI design critique, shaping and quality skill for Hermes Control Center React/Vite. Not for resident Hermes Agent, backend operations, VPS automation or research runtime."
metadata:
  version: "4.7.0"
  origin: "pbakaus/impeccable@dad8dbb3aac21ad1fa236c110315ef4abece23e8"
---

# Impeccable for Hermes Control Center

**ONLY use for developing `control_center/frontend/` in Codex/IDE.** Do not create resident Hermes skills, permissions or VPS changes.

1. Verify that `.impeccable/.agents/skills/impeccable/SKILL.md` exists at the exact pinned commit `dad8dbb3aac21ad1fa236c110315ef4abece23e8`. If absent, the upstream source is **not ready**: `git submodule update --init -- .impeccable`. Never present generic advice as evidence of running Impeccable.
2. Read the original upstream `.impeccable/.agents/skills/impeccable/SKILL.md`, then only the relevant `reference/<command>.md`. This guidance grants no permissions and does not require running the upstream binary.
3. Read `AGENTS.md`, `docs/ux/control-center-ui-evidence.md`, the approved Control Center design and `control_center/frontend` code. Preserve graphite/blue colors, forms, the winged H monogram, Russian localization, PWA, OAuth UX and status semantics. Generic anti-template advice cannot override the approved design.
4. Start with `critique` and `audit` on the actual route/state: status clarity, navigation and hierarchy, forms and empty states, avoidance of arbitrary card walls, readability, mobile and accessibility. Then select `shape`, `distill`, `polish` or `harden` only when the task calls for it; never redesign without owner visual approval.
5. Test real interfaces with Playwright under `control_center/frontend/qa/` using synthetic data. Never use private telemetry, secrets, real OAuth sessions or cookies. Record route/state/viewport, PNG, focus, overflow, reduced-motion and compliance with the approved design. Without a real render, report `NOT_VERIFIED`, not `PASS`.
6. **Do not install** Impeccable scripts under `skills/`, enable hooks/auto-updates, launch `npx`, launchers, network access or binaries, or use paid APIs without a separate explicit review. For design guidance use static upstream instructions; the launcher may fetch a binary.

Workflow: `docs/ux/impeccable-control-center.md`. Browser QA may use `browser-workflow-evidence` additionally, but do not introduce a second orchestrator.
