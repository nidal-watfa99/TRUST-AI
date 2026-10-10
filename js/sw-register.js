/* TRUST AI — service worker registration (external file: inline scripts are blocked by CSP) */
if ("serviceWorker" in navigator) {
  window.addEventListener("load", () => {
    navigator.serviceWorker.register("./sw.js").catch(() => {});
  });
}
