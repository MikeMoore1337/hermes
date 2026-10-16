# Hermes Control Center — installable PWA

Issue [#218](https://github.com/MikeMoore1337/hermes/issues/218).

The C+B Atlas layout with C+A typography and approved winged-H artwork becomes installable on supported desktop and mobile browsers via a local web manifest, PNG icons, and a deliberately restrictive service worker.

## Install

- **Android Chrome:** on `https://hermes.mikemoore.top`, open the browser menu and select **Install app** (if offered).
- **iPhone/iPad:** open the site, then Share → **Add to Home Screen** (wording depends on browser/iOS).
- **Desktop Chrome/Edge:** use the install icon in the browser address bar or Apps → **Install this site as an app**.

Login remains behind existing Caddy Basic Auth until separately approved GitHub OAuth #180/#208. Installation does not bypass authentication.

## Confidentiality rules

- The PWA caches only the *public, generic* `/offline.html` response in CacheStorage. This page displays **no user, service, snapshot, tokens, incident history or environment details**.
- API, OAuth, session, live HTML and all other resources are network-only, never written by the service worker to CacheStorage. The service worker does not intercept `/auth/*` or `/api/*`.
- Backend has an exact route allowlist for the manifest, worker, offline page and two PNG icons; no generic filesystem exposure. CSP includes `manifest-src 'self'` and `worker-src 'self'`.
- The service worker only intercepts same-origin **navigation**. A network failure can show a generic offline fallback; it cannot show old or misleadingly current operational metrics.
- Installed status does not imply availability offline: real system data always needs a live authenticated connection.
- Chromium localhost test runners may still reach loopback addresses under offline emulation; CI checks the offline resource and exact CacheStorage membership instead of claiming a full internet-disconnect simulation. A genuine remote-device offline transition remains a post-deploy manual acceptance check.

## Build and verification

```sh
cd control_center/frontend
npm ci --ignore-scripts
npm run test
npm run build
npm run test:e2e
cd ../..
python3 -m unittest tests.test_control_center_pwa -v
```

The static bundle and assets are committed to `control_center/web`. No Node/Vite server runs on VPS. `pwa-192.png` and `pwa-512.png` are resizes of the previously approved raster H (via the existing Apple touch PNG), not a new emblem.

## Release gates

Production deploy requires green CI and a reversible symlink-based release with exact SHA/file manifest. Check manifest/icons/SW content type, HTTP 401 for unauthenticated public requests, 200 for valid Basic Auth, 200 for authenticated API, CSP presence, and Second Brain unaffected. Test Android/iOS installation after rollout. Never make Basic Auth optional as part of PWA.
