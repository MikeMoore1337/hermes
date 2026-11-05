# Hermes Aero Glass 27 - Design Contract

<!-- visual authority: owner-approved Aero Glass 27 v0.1, 2026-11-05 -->

## Visual world

Hermes Command Center is an operational web/PWA interface visually aligned with contemporary macOS/iOS design conventions without imitating a native OS application. Preserve real Aero winged-H SVG, product identity and exact security language. The signed-off preview showed desktop 1440 dark/light and mobile 393 dark/light.

- Dark: navy backdrop `#101a29`, primary window `#142033`, panels `#1d2a3d`, blue accent `#81aeff`, text `#f5f8ff`.
- Light: page `#e6eaf3`, window `#f7f9fc`, white panels, blue accent `#236bde`, text `#17243a`.
- UI font is native system `-apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif`; monospace for technical identifiers only. No CDN.
- Semantic status colours must never replace explicit text and source; unknown, offline and old snapshots stay explicit.
- Desktop sidebar 240-260px, compact toolbar, 10-16px rounded content surfaces with thin neutral borders. No fake macOS traffic-light buttons.
- Mobile (<=980px) bottom dock with Overview / Inbox / Commander / More, drawer for all remaining existing routes, floating appearance, safe-area padding. All touch targets >=44px where possible. Adapt 320, 393, 430, 768, 1024, 1440, 1920.
- Glass is a material effect limited to chrome (navigation and toolbar), not text-heavy data panels. Support reduced-transparency with opaque backgrounds and reduced-motion with no decorative animation.
- Icons: use existing pinned lucide-react 0.468.0 with consistent sizing/stroke. SF Symbols are not bundled. Aero logo asset stays unchanged.
- The real apps and widgets (Ops, Research, QA, Agent, Codex, Inbox, YFC editor, Hermes Commander) remain functional and use existing routes, API contracts and authorization.

## First screen

Header "Рабочий стол", subtitle and existing Commander/refresh actions; four honest KPIs: protected snapshot source, active units, attention, access. Two cards for verified attention signals and quick links to real sections. Registry and optional existing architecture topology below. No synthetic metrics outside tests.

## Responsive states

Selected, hover, keyboard focus, disabled, loading, no data, API error, stale/offline, light/dark, OS theme changes, PWA standalone, expanded menu and Escape.

## Limits

Do not change OAuth, endpoints, residents, authorizations, command execution, Systemd, article publishing, caching of sensitive data or deployment. Do not claim pixel parity or native iOS behaviour without real device evidence.

## Implementation evidence

Issue #779. Design methods: original Impeccable (context + concept-seed), original Taste (software palettes + layout draw), original UI UX Pro Max (design-system + UX), plus Toolkit design-system-consistency, screenshot-fidelity, motion-quality and QA skills. Adopt the user-pinned Aero Glass direction even if generated alternatives differ.
