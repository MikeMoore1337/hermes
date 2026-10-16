# H-15 / Design V3 — Redesign after owner feedback

**Status: PROPOSALS, NO APPROVAL / NO PRODUCTION CHANGE**

## Owner feedback — 2026-10-16

- V2 design rejected as too similar to the user's separate fitness product YFC, especially navigation icons and repeated SaaS cards.
- Keep graphite and blue.
- Visual logo reference: uploaded orange circular equestrian letter-H seal; recolor is **reference only**, not a production-approved mark.
- Review `https://21st.dev/community/components` and `https://github.com/serafimcloud/21st`; apply previously nominated Taste Skill, Emil Kowalski Skills, Impeccable and UI UX Pro Max methods.
- Preserve separate GitHub OAuth login plan #180 and runtime read-only constraints #33/#163.

## 21st.dev inspection

21st.dev is a community React component registry, with Tailwind/Radix/shadcn conventions. Its app source is MIT, **individual community component licenses and third-party dependencies still require review**. Hermes Control Center currently uses Python standard-library server and static HTML/JS. Bringing in a complete Next.js/React runtime would create needless dependencies and widen the security surface. Borrow deliberate component geometry, interaction patterns and accessibility principles; no unreviewed `npx shadcn` execution in the production agent/VPS.

Verified reference examples:
- [Dashboard Sidebar, Arun Dass](https://preview.21st.dev/%40arunjdass/components/dashboard-sidebar): collapsed navigation and active route patterns.
- [Builder OS Bento, Drew Sepeczi](https://preview.21st.dev/%40drewsephski/components/builder-os-bento): engineer-first command center, sparse panels and operations context. No transfer of its Framer Motion or remote-font dependency into current Hermes.
- [21st React Dashboard guide](https://docs.21st.dev/blog/react-dashboard-components): shell/table choices, stable metric widths and accessible tabular data. **Do not fabricate uptime, events, costs or historical trends without real source data.**
- [21st sign-in collection](https://21st.dev/community/components/s/sign-in): login geometry; implement owner-only GitHub OAuth separately with explicit security testing.

## Skills: principles applied to V3 proposals

- **Taste Skill v2:** applies specifically to *public landing/login*, not dashboards according to its own SKILL.md. Apply composition, non-template art direction and real visual anchors to future sign-in; avoid running its scripts against resident Agent.
- **Emil Kowalski:** default static operator UI, subtle state transitions only when interaction is useful, no perpetual visual effects, `prefers-reduced-motion` support.
- **Impeccable:** three different visual hierarchies; condensed information architecture, typographic structure, focus states, accessibility review and visual density without generic nested card grids.
- **UI UX Pro Max:** semantic tokens, professional graphite/blue system, clear operational states and checkable contrast.
- **Lucide / Tabler / Iconoir:** these remain candidate icon sources, but V3 intentionally avoids icon-led navigation. Numeric labels/typographic descriptions distinguish this product from YFC. Only meaningful small SVG affordances will be selected in final design.

## V3 distinct layouts

**A. Control Room / Operator:** compact *numeric* left rail (instead of wellness-product pictograms), hero status as large numbers, two wide operational panels, restrained blue signal trace, NO-GO block.

**B. Operations Atlas / Editorial:** no persistent left sidebar, horizontal text navigation, serif editorial title and large brand seal, tabular register with thin dividers, policy sidebar. Distinctive login brand style could match this direction.

**C. Signal Desk / Operator Cockpit:** dense three-column workbench: left subsystem index; central service state table; right activity log/timeline. Emphasizes scanability for an owner diagnosing incidents. Do not connect event examples to real backend until availability and provenance are verified.

All V3 screenshots contain **illustrative data**, explicitly labeled demo. Browser render verification: Chromium via `page.set_content`; 1440px desktop; horizontal scroll measurements PASS at 393px and 320px after responsive adjustment.

## Logo and rights warning

User-supplied equestrian ring with central H appears highly similar to the recorded **HERMES-PARIS H** trademark (US registration 1929530; horse, carriage and trainer, circular ornament and H). Recoloring from orange to blue does not remove trademark or copyright concerns. Do **not** commit, install as favicon, or publish an exact recolor without rights verification. Alternative prototype: new winged H orbital seal that does not copy the horse/carriage/trainer. Final identity remains owner design approval + rights check. The name Hermes Agent is upstream project nomenclature, not a declaration of relationship with the luxury brand.

## Approval and security gates

- [ ] Owner selects a V3 direction or requests a hybrid. Old V2 visuals are superseded, **not approved**.
- [ ] Owner approves an original logo and favicon (separate rights/licensing gate for reference mark).
- [ ] After approval: build a login page and dashboard screens, mobile and desktop screenshots, contrast tests and interaction QA; no YFC icon composition.
- [ ] GitHub OAuth #180 remains separate: owner-created dedicated OAuth App, fail-closed sessions, Basic Auth preserved until successful authenticated public E2E.
- [ ] Do not merge visual drafts or deploy production changes, do not start resident Agent (#33).
