# H-15 GitHub OAuth: immutable-ish offline staging evidence, 16.10.2026

**Status:** staging tested / production OAuth **NOT ENABLED**. **Owner approval, GitHub OAuth App, and restricted network egress still required.**

## Source and CI

- [PR #207](https://github.com/MikeMoore1337/hermes/pull/207) merged at `5858e306479275a1d3555d0fd9bfb45a1f8ea901`.
- Last required checks on the branch: [Hermes repository CI #38935260202](https://github.com/MikeMoore1337/hermes/actions/runs/38935260202) success, [Hermes Control Center UI CI #38935260067](https://github.com/MikeMoore1337/hermes/actions/runs/38935260067) success.
- Isolated Windows worktree: Python 27/27 (14 OAuth-specific), node 3/3 and Chromium 10/10, including owner logout, browser redirect to GitHub sign-in, anonymous API denial and no document overflow. The official GitHub.com OAuth API documents PKCE S256; **tests use a fake provider**, not real credentials or GitHub API calls.
- Build artifacts versioned in GitHub; compiled React frontend is static, no Node runtime on VPS.

## VPS staged artifact (no public switch)

- VPS: `vps1777112993`.
- Source SHA: `5858e306479275a1d3555d0fd9bfb45a1f8ea901`.
- Archive `/opt/hermes-control-center/incoming/h15-oauth-5858e306.zip`; SHA-256 `8e1b4e346b6ad53e661fe9d31d9298e6968cbb102ae8f1955b6693b8c5f688fa` (verified before extraction).
- Staged release: `/opt/hermes-control-center/releases/h15-oauth-5858e306`. Exactly 11 allowlisted source/assets/tests replaced, with source and file digests in `stage-receipt.json`.
- Stage Python compilation PASS. The `hermes-control` user ran the 14 isolated OAuth tests on VPS: PASS.
- An isolated web process under `hermes-control`, on loopback port **9134 only during checks**, passed real HTTP probes:
  - `GET /healthz`, `/`, `/app.js`, `/favicon.png`, `/brand.webp`, `/api/overview` → 200.
  - `GET /api/auth/session` in the default `proxy` mode → 200 with `{"mode":"proxy","authenticated":true}`. **This assumes the real public Caddy Basic Auth perimeter and is NOT itself an independent authentication claim**.
  - `GET /src/main.jsx`, `/auth/github/start`, `/.env` → 404 (OAuth endpoint remains unavailable in proxy mode).
  - `HEAD /api/overview` → 200 with no body; `POST /auth/logout` → 501 in proxy mode.
  - CSP remains `default-src 'none'`, exact static allowlist, no write endpoints.
- The isolated 9134 process was stopped after checks. `/opt/hermes-control-center/current` **did not change** and continued to point to `/opt/hermes-control-center/releases/h15-ui-1f516566`. The live `hermes-control-center.service` remained active with existing Caddy Basic Auth. No OAuth secrets or external provider calls.

## Network isolation blocker

Current production unit contains `IPAddressDeny=0.0.0.0/0 ::/0` and `IPAddressAllow=127.0.0.0/8 ::1/128`. Existing general-purpose `squid`/`danted` services on VPS are **not an approved OAuth egress channel**, and the special `hermes-cloudflare-proxy.service` remains intentionally inactive. **Do not remove the network sandbox** or route owner credentials through an unapproved proxy. Follow [Issue #208](https://github.com/MikeMoore1337/hermes/issues/208) for a bounded, independently reviewed GitHub-only OAuth exchange path.

## Remaining gates

1. Owner creates a **dedicated Hermes Control Center GitHub OAuth App** with callback `https://hermes.mikemoore.top/auth/github/callback` and no optional scopes.
2. Secrets and owner numeric GitHub ID are provisioned in a separate restricted server file/credential store, not repo/CI/chat.
3. Egress helper/isolation + callback query log redaction and denial tests pass (#208).
4. Real owner login, rejected unauthorized account, protected API, revocable session and rollback are verified in staging. Only then a separately approved Caddy change may remove Basic Auth.
5. Resident AI Agent remains P0 **NO-GO** (#33).

**Do not equate successfully merged OAuth source or offline staging with production sign-in readiness.**
