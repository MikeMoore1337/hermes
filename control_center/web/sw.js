/* Hermes Control Center PWA — intentionally NO sensitive caching.
   Only the anonymous, unbranded offline fallback may live in CacheStorage.
   All API, login, OAuth redirects, snapshots and live HTML are network-only. */
const OFFLINE_VERSION = "h15-offline-v1";
const OFFLINE_URL = "/offline.html";
self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(OFFLINE_VERSION)
      .then((cache) => cache.add(new Request(OFFLINE_URL, {cache:"reload"})))
      .then(() => self.skipWaiting())
  );
});
self.addEventListener("activate", (event) => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter((key) => key.startsWith("h15-offline-") && key !== OFFLINE_VERSION)
      .map((key) => caches.delete(key)));
    await self.clients.claim();
  })());
});
self.addEventListener("fetch", (event) => {
  const request = event.request;
  if (request.mode !== "navigate" || request.method !== "GET") return;
  const url = new URL(request.url);
  if (url.origin !== self.location.origin || url.pathname.startsWith("/auth/") ||
      url.pathname.startsWith("/api/") || url.pathname.startsWith("/control-center/api/")) return;
  event.respondWith((async () => {
    try {
      return await fetch(new Request(request,{cache:"no-store"})); // network-only; never use browser HTTP cache
    } catch (_error) {
      const cache = await caches.open(OFFLINE_VERSION);
      return await cache.match(OFFLINE_URL) || Response.error();
    }
  })());
});
