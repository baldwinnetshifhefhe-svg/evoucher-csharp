// e-PSS service worker — enables install + basic offline (runtime caching).
const CACHE = "epss-v3";

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil((async () => {
  // purge any older caches so stale pages can't be served
  const keys = await caches.keys();
  await Promise.all(keys.filter((k) => k !== CACHE).map((k) => caches.delete(k)));
  await self.clients.claim();
})()));

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  const isPage = req.mode === "navigate" || (req.headers.get("accept") || "").includes("text/html");
  e.respondWith(
    // HTML pages: always fetch the freshest copy from the network (bypass HTTP cache),
    // only falling back to a cached copy when truly offline.
    fetch(isPage ? new Request(req, { cache: "no-store" }) : req)
      .then((res) => {
        const copy = res.clone();
        caches.open(CACHE).then((c) => c.put(req, copy)).catch(() => {});
        return res;
      })
      .catch(() =>
        caches.match(req).then((r) => r || (req.mode === "navigate" ? caches.match("/index.html") : undefined))
      )
  );
});
