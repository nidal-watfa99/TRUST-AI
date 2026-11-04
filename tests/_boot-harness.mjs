// Helper for tests/app-persist.test.js — boots the REAL js/app.js in a fresh Node process against a fake DOM whose
// localStorage is a FILE, so two processes behave like "close the app, open it again". Not a test by itself.
import { readFileSync, writeFileSync, existsSync } from "node:fs";
const STORE = process.env.STORE_FILE, PHASE = process.env.PHASE, KEY = process.env.TEST_KEY || "";
const data = existsSync(STORE) ? JSON.parse(readFileSync(STORE, "utf8")) : {};
const flush = () => writeFileSync(STORE, JSON.stringify(data));
globalThis.localStorage = { getItem: (k) => (k in data ? data[k] : null), setItem: (k, v) => { data[k] = String(v); flush(); }, removeItem: (k) => { delete data[k]; flush(); }, clear: () => { for (const k of Object.keys(data)) delete data[k]; flush(); }, key: () => null, get length() { return Object.keys(data).length; } };
globalThis.sessionStorage = { getItem: () => null, setItem() {}, removeItem() {}, clear() {} };

const listeners = new Map(); const docL = []; const els = new Map();
class El {
  constructor(sel) { this.sel = sel; this.children = []; this._attrs = {}; this.dataset = {}; this.style = {}; this.value = ""; this.innerHTML = ""; this.textContent = ""; this.checked = false; this.disabled = false; this.hidden = false; this.files = []; this.className = ""; this._cls = new Set(); const s = this;
    this.classList = { add: (...c) => c.forEach((x) => s._cls.add(x)), remove: (...c) => c.forEach((x) => s._cls.delete(x)), toggle: (c, f) => { const on = f === undefined ? !s._cls.has(c) : !!f; on ? s._cls.add(c) : s._cls.delete(c); return on; }, contains: (c) => s._cls.has(c) }; }
  addEventListener(t, fn) { listeners.set(`${this.sel}|${t}`, fn); } removeEventListener() {}
  setAttribute(k, v) { this._attrs[k] = String(v); } getAttribute(k) { return this._attrs[k] ?? null; } removeAttribute(k) { delete this._attrs[k]; } hasAttribute(k) { return k in this._attrs; }
  querySelector(s) { return get(s); } querySelectorAll() { return []; } closest() { return null; } matches() { return false; }
  appendChild(c) { this.children.push(c); return c; } append() {} prepend() {} remove() {} replaceChildren() {} insertAdjacentHTML() {} contains() { return false; }
  focus() {} blur() {} click() {} scrollIntoView() {} select() {} scrollTo() {} dispatchEvent() { return true; } getBoundingClientRect() { return { top: 0, left: 0, width: 0, height: 0 }; }
  get offsetHeight() { return 0; } get parentElement() { return null; } get firstChild() { return null; }
}
const get = (s) => { if (!els.has(s)) els.set(s, new El(s)); return els.get(s); };
const doc = { readyState: "loading", documentElement: new El("html"), body: new El("body"), head: new El("head"), title: "", visibilityState: "visible", activeElement: null, hidden: false, cookie: "", referrer: "",
  querySelector: get, getElementById: (id) => get("#" + id), querySelectorAll: () => [], createElement: (t) => new El(t), createTextNode: (t) => ({ textContent: t }), createDocumentFragment: () => new El("frag"),
  addEventListener: (t, fn) => { if (t === "DOMContentLoaded") docL.push(fn); else listeners.set(`document|${t}`, fn); }, removeEventListener() {}, dispatchEvent: () => true, execCommand: () => false, hasFocus: () => true };
doc.documentElement.lang = "ar"; doc.documentElement.dir = "rtl";
Object.assign(globalThis, { document: doc, window: globalThis, addEventListener: (t, fn) => listeners.set(`window|${t}`, fn), removeEventListener() {}, matchMedia: () => ({ matches: false, addEventListener() {}, removeEventListener() {}, addListener() {}, removeListener() {} }),
  scrollTo() {}, requestAnimationFrame: (f) => setTimeout(f, 0), cancelAnimationFrame() {}, getComputedStyle: () => ({ getPropertyValue: () => "" }), CSS: { escape: (s) => s, supports: () => false },
  IntersectionObserver: class { observe() {} disconnect() {} unobserve() {} }, Notification: undefined, confirm: () => true, alert() {}, innerWidth: 400, innerHeight: 800, HTMLElement: El, Element: El, Node: El,
  location: { href: "https://example.test/", origin: "https://example.test", search: "", hash: "", pathname: "/", protocol: "https:", host: "example.test", reload() {}, replace() {}, assign() {} }, history: { pushState() {}, replaceState() {}, state: null, back() {} } });
globalThis.ResizeObserver = globalThis.IntersectionObserver; globalThis.MutationObserver = globalThis.IntersectionObserver;
Object.defineProperty(globalThis, "navigator", { value: { language: "ar", languages: ["ar"], userAgent: "node", platform: "Linux", maxTouchPoints: 0, clipboard: { writeText: async () => {} }, onLine: true, serviceWorker: undefined, storage: undefined }, configurable: true });
globalThis.fetch = async (url) => (String(url).includes("generativelanguage") ? new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: "{\"ok\":true}" }] } }] }), { status: 200 }) : new Response("{}", { status: 200 }));

const realLog = console.log; console.log = () => {};
await import("../js/app.js");
for (const fn of docL) await fn();
await new Promise((r) => setTimeout(r, 120));
if (PHASE === "save") {
  get("#ai-key").value = KEY; get("#ai-model").value = process.env.TEST_MODEL_ID || "gemini-flash";
  await listeners.get("#btn-save-ai|click")?.();
  await new Promise((r) => setTimeout(r, 300));
}
const ai = await import("../js/ai-provider.js");
const st = ai.getAIStatus();
console.log = realLog;
console.log("RESULT " + JSON.stringify({ phase: PHASE, available: st.available, provider: st.provider, model: st.model, badge: get("#ai-status-badge").textContent, badgeClass: get("#ai-status-badge").className, keyFieldValue: get("#ai-key").value, stored: Object.keys(data).filter((k) => k.startsWith("trustai_")) }));
process.exit(0);
