# H-15 Security contract: owner-only GitHub login for Control Center

**Issue:** #180; **Design:** #179; **Current production:** separate read-only service behind Caddy Basic Auth.  
**Status:** specification only. **No runtime auth changes or new provider credentials in this PR.**

## User journey

Unauthenticated visitor on `https://hermes.mikemoore.top` sees the Russian branded login page; presses `Войти через GitHub` -> exact GitHub OAuth authorize flow -> callback -> server-side code exchange and GitHub `GET /user` identity verification -> signed session cookie -> read-only dashboard. Logout clears cookie and brings login page. Any unauthenticated API / protected asset returns 401 or redirects as appropriate, never JSON with system data. Denied account remains denied even with a valid GitHub login.

## Existing Second Brain model (inspected on authorized VPS)

`/srv/second-brain/second-brain/docs/deployment/web-auth.md` and `src/second_brain/entrypoints/web/auth.py` describe/implement: separate OAuth App, numeric allowlisted owner GitHub ID (not username), state TTL 600s, session TTL 43200s, session HMAC + HttpOnly/SameSite=Lax/Secure cookie, provider token used only to retrieve identity and dropped, no OAuth scopes, process-local bounded one-time state store. Leverage patterns by implementation review, do **not** reuse its client secret, signing secret, session cookie or private repository data.

## Separate application and required owner action

GitHub user/settings -> Developer settings -> OAuth Apps -> New OAuth App.

- App name: `Hermes Control Center`
- Homepage: `https://hermes.mikemoore.top`
- Callback: `https://hermes.mikemoore.top/auth/github/callback`
- Disable wildcard matching for callback URLs.
- Device flow not enabled.
- No repository/email/org/write OAuth scopes; if reauthorization returns unexpectedly broad scopes, deny and audit.
- Store new client ID, client secret and a fresh session secret of >=32 bytes in owner-managed root-only runtime secret file / service credentials outside repo, not in ticket/PR.
- Allowed GitHub **numeric** user ID must be pinned in runtime configuration. Do not authorize by mutable login or email.

Official docs: https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app and https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps

## Implementation contract and tests (before enabling)

1. Start fails closed if auth mode=github but client ID, client secret, expected numeric owner ID, fixed HTTPS origin, strong session secret or trusted-host list is missing/malformed.
2. Browser session is a bounded HMAC-signed, versioned, HttpOnly Secure SameSite=Lax cookie with 12h or shorter max TTL, fresh random state, no token in cookie/localStorage/sessionStorage/URL.
3. OAuth state is random >=128 bits, stored only as digest in bounded process-memory pending store, one-time consumable with <=600s expiration. PKCE S256 verifier per flow when supported; external requests bounded timeout, JSON size, no redirects, TLS verification, mandatory identity numeric ID check, discard token after callback.
4. Strict canonical URLs and request authority checks; only declared routes. No browser-defined next/redirect target, no X-Forwarded spoofing, no duplicate code/state query params, no leaking callback query in access logs.
5. Static protected app, API and all GET/HEAD requests must be denied without a valid session. Minimal public login page and self-hosted logo/icons only. Security headers and cache-control no-store for all authentication/session/state endpoints.
6. Logout invalidates the session if using server-side session store or rotates/clears server-side nonce as needed; at minimum clears cookie. Meaningful alerts and rate limits for repeated denied attempts without leaking provider details.
7. Negative test matrix: denied ID, forged token JSON, replay, missing/wrong/multiple state values, expired state/session, swapped cookies, session signature tampering, fake Host/Origin, redirect injection, callback length bounds, session routes HEAD/POST/OPTIONS, concurrency state exhaustion, network/API timeouts, no token logging.
8. Keep Caddy Basic Auth in place until staged owner OAuth credentials and HTTPS owner-only E2E checks PASS. Test 401 external probes. Replace only the Hermes virtual host protection using reversible configuration change. Do not touch Second Brain OAuth, xray :443, other Hermes timers or resident P0 #33.
9. All decisions about whether to deploy production require current owner security approval and rollback plan. After login is switched, the existing Basic Auth password must not be silently treated as an OAuth credential.

## Acceptance

Separate auth implementation PR, CI and test evidence, reviewed security state machine, owner's manual OAuth app, owner-only browser login E2E on `hermes.mikemoore.top`, denied unauthorized account, then Caddy cutover; never link production enablement to UI visual approval alone.
