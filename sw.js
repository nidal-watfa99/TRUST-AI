/* TRUST AI — offline cache (v3.0 hardened)
 * - Caches ONLY an explicit allow-list of same-origin static files (no cache poisoning
 *   through arbitrary URLs, no cross-origin / API traffic ever touches the cache).
 * - Only stores successful, same-origin ("basic") GET responses.
 * - Old caches are deleted on activation. */
const CACHE = "trust-ai-v3.1.0";
const ASSETS = [
  "./",
  "./index.html",
  "./css/styles.css",
  "./js/guard.js",
  "./js/app.js",
  "./js/ai-provider.js",
  "./js/risk-engine.js",
  "./js/i18n.js",
  "./js/examples.js",
  "./js/source-report.js",
  "./js/client.js",
  "./js/client-engine.js",
  "./js/client-data.js",
  "./js/security.js",
  "./js/shield-ui.js",
  "./js/fraud-db.js",
  "./js/phone-check.js",
  "./js/questnet.js",
  "./js/victim-help.js",
  "./js/sw-register.js",
  "./manifest.json",
  "./assets/logo.svg",
  "./assets/icon.svg",
  "./assets/icon-192.svg",
  "./assets/icon-512.svg",
  "./assets/icon-maskable.svg",
  "./assets/icon-16.png",
  "./assets/icon-32.png",
  "./assets/icon-48.png",
  "./assets/icon-180.png",
  "./assets/icon-192.png",
  "./assets/icon-512.png",
  "./assets/icon-maskable-192.png",
  "./assets/icon-maskable-512.png",
  "./assets/og-image.png",
  "./js/news-verdict.js",
  "./js/scam-numbers.js",
  "./js/phone-ui.js",
];
const ALLOWED = new Set(ASSETS.map((a) => new URL(a, self.location).pathname));

self.addEventListener("install", (e) => {
  e.waitUntil(
    caches.open(CACHE).then((c) => c.addAll(ASSETS)).then(() => self.skipWaiting())
  );
});

self.addEventListener("activate", (e) => {
  e.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)))
    ).then(() => self.clients.claim())
  );
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);

  // Cross-origin (AI providers, feeds, fonts): straight to the network, never cached.
  if (url.origin !== self.location.origin) return;

  // Same-origin but not on the allow-list: do not touch.
  if (!ALLOWED.has(url.pathname) || req.headers.has("range")) return;

  e.respondWith(
    caches.match(req).then((cached) => {
      const net = fetch(req)
        .then((res) => {
          if (res && res.ok && res.type === "basic") {
            const clone = res.clone();
            caches.open(CACHE).then((c) => c.put(req, clone));
          }
          return res;
        })
        .catch(() => cached || (req.mode === "navigate" ? caches.match("./index.html") : Response.error()));
      return cached || net;
    })
  );
});
