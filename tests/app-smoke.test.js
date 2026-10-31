/**
 * TRUST AI — boot smoke test: runs the REAL js/app.js against a tiny fake DOM, fires DOMContentLoaded,
 * then drives the phone-check screen like a person would. Catches boot-time errors (bad imports, TDZ, null access)
 * that unit tests of single modules cannot see.
 * Run: node tests/app-smoke.test.js
 */
let passed = 0, failed = 0;
const assert = (c, m) => (c ? (passed++, console.log("  ✓", m)) : (failed++, console.error("  ✗", m)));

const listeners = new Map();   // "selector|type" -> fn
const docListeners = [];
const els = new Map();
class El {
  constructor(sel) { this.sel = sel; this.children = []; this._attrs = {}; this.dataset = {}; this.style = {}; this.value = ""; this.innerHTML = ""; this.textContent = ""; this.checked = false; this.disabled = false; this.hidden = false; this.files = []; this.className = ""; this._cls = new Set();
    const self = this;
    this.classList = { add: (...c) => c.forEach((x) => self._cls.add(x)), remove: (...c) => c.forEach((x) => self._cls.delete(x)), toggle: (c, f) => { const on = f === undefined ? !self._cls.has(c) : !!f; on ? self._cls.add(c) : self._cls.delete(c); return on; }, contains: (c) => self._cls.has(c) }; }
  addEventListener(type, fn) { listeners.set(`${this.sel}|${type}`, fn); }
  removeEventListener() {}
  setAttribute(k, v) { this._attrs[k] = String(v); } getAttribute(k) { return this._attrs[k] ?? null; } removeAttribute(k) { delete this._attrs[k]; } hasAttribute(k) { return k in this._attrs; }
  querySelector(s) { return get(s); } querySelectorAll() { return []; } closest() { return null; } matches() { return false; }
  appendChild(c) { this.children.push(c); return c; } append() {} prepend() {} remove() {} replaceChildren() {} insertAdjacentHTML() {} contains() { return false; }
  focus() {} blur() {} click() {} scrollIntoView() {} select() {} scrollTo() {} dispatchEvent() { return true; } getBoundingClientRect() { return { top: 0, left: 0, width: 0, height: 0 }; }
  get offsetHeight() { return 0; } get parentElement() { return null; } get firstChild() { return null; } get children_() { return []; }
}
const get = (sel) => { if (!els.has(sel)) els.set(sel, new El(sel)); return els.get(sel); };

const store = new Map();
const ls = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k), clear: () => store.clear(), key: () => null, get length() { return store.size; } };
globalThis.localStorage = ls; globalThis.sessionStorage = { getItem: () => null, setItem() {}, removeItem() {}, clear() {} };
const doc = {
  readyState: "loading", documentElement: new El("html"), body: new El("body"), head: new El("head"), title: "", visibilityState: "visible", activeElement: null, hidden: false, cookie: "", referrer: "",
  querySelector: get, getElementById: (id) => get("#" + id), querySelectorAll: () => [], createElement: (t) => new El(t), createTextNode: (t) => ({ textContent: t }), createDocumentFragment: () => new El("frag"),
  addEventListener: (type, fn) => { if (type === "DOMContentLoaded") docListeners.push(fn); else listeners.set(`document|${type}`, fn); }, removeEventListener() {}, dispatchEvent: () => true,
  execCommand: () => false, hasFocus: () => true,
};
doc.documentElement.lang = "ar"; doc.documentElement.dir = "rtl";
globalThis.document = doc;
globalThis.window = globalThis;
globalThis.addEventListener = (t, fn) => listeners.set(`window|${t}`, fn);
globalThis.removeEventListener = () => {};
globalThis.matchMedia = () => ({ matches: false, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} });
Object.defineProperty(globalThis, "navigator", { value: { language: "ar", languages: ["ar"], userAgent: "node", platform: "Linux", maxTouchPoints: 0, clipboard: { writeText: async () => {} }, onLine: true, serviceWorker: undefined, storage: undefined }, configurable: true });
globalThis.location = { href: "https://example.test/", origin: "https://example.test", search: "", hash: "", pathname: "/", protocol: "https:", host: "example.test", reload() {}, replace() {}, assign() {} };
globalThis.history = { pushState() {}, replaceState() {}, state: null, back() {} };
globalThis.scrollTo = () => {}; globalThis.requestAnimationFrame = (f) => setTimeout(f, 0); globalThis.cancelAnimationFrame = () => {};
globalThis.getComputedStyle = () => ({ getPropertyValue: () => "" });
globalThis.CSS = { escape: (s) => s, supports: () => false };
globalThis.IntersectionObserver = class { observe() {} disconnect() {} unobserve() {} };
globalThis.ResizeObserver = globalThis.IntersectionObserver;
globalThis.MutationObserver = globalThis.IntersectionObserver;
globalThis.Notification = undefined;
globalThis.fetch = async () => new Response("{}", { status: 503 });
globalThis.confirm = () => true; globalThis.alert = () => {};
globalThis.innerWidth = 400; globalThis.innerHeight = 800;
globalThis.HTMLElement = El; globalThis.Element = El; globalThis.Node = El;
const errors = [];
const origErr = console.error;
const quiet = (f) => { const l = console.log; console.log = (...a) => { if (!String(a[0]).includes("TRUST-AI-SEC")) l(...a); }; return () => { console.log = l; }; };

console.log("\n=== Boot ===\n");
let bootError = null;
const restore = quiet();
try { await import("../js/app.js"); } catch (e) { bootError = e; }
assert(!bootError, "js/app.js loads (all imports resolve)" + (bootError ? " — " + bootError.message : ""));
if (!bootError) {
  assert(docListeners.length > 0, "the app registers its DOMContentLoaded start-up");
  let startErr = null;
  for (const fn of docListeners) { try { await fn(); } catch (e) { startErr = e; } }
  assert(!startErr, "start-up runs without throwing" + (startErr ? " — " + (startErr.stack || startErr.message).split("\n").slice(0, 3).join(" | ") : ""));
  await new Promise((r) => setTimeout(r, 50));

  console.log("\n=== Phone check screen ===\n");
  assert(listeners.has("#btn-phone-run|click"), "the 'check number' button is wired");
  assert(listeners.has("#btn-phone-check|click"), "the home card that opens the phone screen is wired");
  const input = get("#phone-input"), out = get("#phone-result");
  try { listeners.get("#btn-phone-check|click")?.(); } catch (e) { errors.push(e); }
  input.value = "+963 944 123 456";
  try { listeners.get("#btn-phone-run|click")?.(); } catch (e) { errors.push(e); }
  assert(!errors.length, "tapping 'check' does not throw" + (errors[0] ? " — " + errors[0].message : ""));
  assert(!out._cls.has("hidden") && out.innerHTML.length > 500, "the result is rendered into the page (" + out.innerHTML.length + " chars)");
  assert(/سوريا/.test(out.innerHTML), "the result names the country (Syria)");
  input.value = "abc";
  listeners.get("#btn-phone-run|click")?.();
  assert(/غير صالح/.test(out.innerHTML), "an invalid number gets a clear message");
  input.value = "+225 0102030405";
  listeners.get("#btn-phone-run|click")?.();
  assert(/مشبوه|خطر|مرتفع|احتيال|wangiri|اتصال/i.test(out.innerHTML), "a risky pattern is flagged in the rendered page");
}
restore();
console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
