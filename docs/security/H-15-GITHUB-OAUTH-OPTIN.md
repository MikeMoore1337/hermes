# H-15: GitHub OAuth — opt-in owner-only rollout

**Issue:** #180. **Production state:** Caddy Basic Auth unchanged.  
**Version:** staged software only until owner creates a *separate* Hermes OAuth App and explicitly approves a security cutover.

## Why opt-in

The existing read-only Control Center on `hermes.mikemoore.top` already works in **proxy mode** (default). Its public security boundary remains Caddy Basic Auth; `GET /api/auth/session` in proxy mode returns authenticated **only because the reverse proxy itself enforces authorization**. NEVER remove Basic Auth in proxy mode; this would allow the static app and read-only snapshot API to be accessed anonymously.

GitHub mode is activated **only** by setting `HERMES_CC_AUTH_MODE=github` with all required secrets; missing, invalid or weak values prevent server startup. This implementation has no write endpoints and does not start the resident Hermes Agent.

## Dedicated GitHub OAuth App — owner's action

Official documentation:
- https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app
- https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps

Create an OAuth App separate from Second Brain:

| Field | Value |
|---|---|
| Application name | `Hermes Control Center` |
| Homepage URL | `https://hermes.mikemoore.top` |
| Authorization callback URL | `https://hermes.mikemoore.top/auth/github/callback` |
| Wildcard matching | **Disabled** |
| Device Flow | **Disabled** |
| Extra scopes | **None** (`repo`, `user:email`, `org` are unnecessary) |

Use GitHub OAuth web authorization-code flow with PKCE **S256**. The server uses this code only to fetch `GET https://api.github.com/user`; it verifies the **numeric owner ID**, then discards the provider access token. Authorization scopes other than an empty scope list are rejected.

On the VPS create an owner-managed credential file readable by the web service, not Git, PR, CI or shell command argv. Required environment variables:

```text
HERMES_CC_AUTH_MODE=github
HERMES_CC_PUBLIC_ORIGIN=https://hermes.mikemoore.top
HERMES_CC_GITHUB_CLIENT_ID=<owner-created OAuth client ID>
HERMES_CC_GITHUB_CLIENT_SECRET=<owner-created OAuth client secret>
HERMES_CC_ALLOWED_GITHUB_ID=<numeric owner GitHub ID>
HERMES_CC_SESSION_SECRET=<cryptographically random 32+ byte secret>
```

Use a root-managed `0600` secrets source and systemd credential injection / explicit ACL readable only by the `hermes-control` service where needed. **Do not reuse Second Brain's credentials**, cookie names, session key or identity state.

## Threat and security properties

- Authorization callback accepts **exactly one** `code` and `state`, length-bounded; full callback query is never logged by this web app.
- Login starts generate cryptographic random browser-binding cookie, short-lived one-time SHA256-hashed server-side state (10 min) and PKCE S256 verifier; provider must return the exact nonce/state.
- HTTPS/TLS is verified on outbound provider calls; timeout 5 seconds, max JSON response 16KiB, redirects denied.
- Session cookie uses 256-bit random bearer value + HMAC-SHA256 signature, `Secure; HttpOnly; SameSite=Lax`; only a hash is stored server-side; maximum lifetime 12 h. Sessions are revoked on POST logout or web service restart (intentionally non-persistent).
- `POST /auth/logout` requires the exact canonical `Origin` and a zero-length request body.
- GitHub mode: protected snapshot routes return 401 without a valid session; static login/brand assets are intentionally public.
- Both pending login attempts and active sessions have strict bounded capacity. Failed provider response, mismatched ID, missing cookie, tampered signature, replayed code/state or expired session fail closed.
- This implementation cannot guarantee protection from Caddy/Cloudflare access-logging callback parameters. Verify sanitized/no-query access logs at *every* outer proxy layer before enabling.
- The CSS/HTML login preview remains disabled when Basic Auth + proxy mode is active. The real GitHub button becomes enabled only when API `/api/auth/session` reports `mode=github,authenticated=false`.
- No automatic source-controlled credential creation, no Caddy edits, no Cloudflare edits, no current VPS deployment in this change.

## Offline tests

```sh
python3 -m unittest tests.test_control_center_oauth -v
python3 -m unittest tests.test_control_center tests.test_control_center_assets -v
cd control_center/frontend
npm ci --ignore-scripts
npm run test
npm run build
npm run test:e2e
```

No live OAuth requests in tests; provider is injected using a fake numeric ID. Negative tests include missing config, wrong origin, denied user ID, missing/wrong/replayed/expired state, tampered/revoked/expired session, broad scopes and API access denial.

## Cutover — separate change, manual owner checkpoint

1. Confirm signed-in user is the owner and Caddy Basic Auth is currently working. Keep a rollback copy of the current Hermes Caddy site, not of Second Brain.
2. Create OAuth App in owner's GitHub settings. Safely install credentials on VPS, with no stdout logs of keys. Keep `auth_mode=github` **only in an isolated staging instance** until tests and real owner browser flow pass.
3. In production, enable GitHub mode on the isolated web service **while retaining Basic Auth**; validate backend 401 from unauthenticated internal clients and owner OAuth sign-in using a controlled external test path. Because Caddy Basic Auth is still present, browser OAuth requires a separate safe test strategy to pass through it.
4. Only after proof of successful owner login, denied alternate account, protected API, short-lived/revoked session and rollback access: remove Hermes-specific Basic Auth in a separately approved Caddy change, preserving Cloudflare Full (strict), Origin Rule :8444, CSP and all other services.
5. Verify owner login, API auth denial/allowance, logout, session expiry, Second Brain unaffected, systemd sandbox still isolated and resident Agent #33 still **NO-GO**. On any failure restore prior Caddy site and `proxy` mode as one rollback unit.

**Gate:** No OAuth production activation based solely on passing offline tests. Owner must supply the dedicated App configuration and explicitly approve the live cutover after evidence.
