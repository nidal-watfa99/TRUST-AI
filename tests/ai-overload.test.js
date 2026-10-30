/**
 * TRUST AI — provider overload (HTTP 503) behaviour
 * Run: node tests/ai-overload.test.js
 */
let passed = 0, failed = 0;
const assert = (c, m) => (c ? (passed++, console.log("  ✓", m)) : (failed++, console.error("  ✗", m)));
const store = new Map();
globalThis.localStorage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };
globalThis.sessionStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
const realSetTimeout = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...a) => realSetTimeout(fn, Math.min(ms, 5), ...a); // fast back-off for the test

const KEY = "AIzaSyTestKeyForUnitTests_1234567890";
const OVERLOAD = JSON.stringify({ error: { code: 503, message: "This model is currently experiencing high demand." } });
const OK = JSON.stringify({ candidates: [{ content: { parts: [{ text: "{\"ok\":true}" }] } }] });
const mk = (n) => import(`../js/ai-provider.js?o=${n}`);

console.log("\n=== Provider overload (503) ===\n");

// 1) transient: 503, 503, then success -> the call succeeds by itself, key untouched
let calls = 0;
globalThis.fetch = async () => (++calls <= 2 ? new Response(OVERLOAD, { status: 503 }) : new Response(OK, { status: 200 }));
let a = await mk(1);
const gem = a.getFreeModels().filter((m) => m.provider === "gemini");
a.initAIProvider({ apiKey: KEY, modelId: gem[0].id });
let r = await a.testConnection();
assert(r.ok === true && calls === 3, "temporary 503 is retried automatically and then succeeds");

// 2) the chosen model is overloaded for good but its sibling works -> falls back, choice unchanged
const seen = [];
globalThis.fetch = async (url) => { seen.push(String(url)); return /gemini-flash-lite/.test(String(url)) ? new Response(OVERLOAD, { status: 503 }) : new Response(OK, { status: 200 }); };
let b = await mk(2);
const lite = gem.find((m) => /lite/.test(m.model));
b.initAIProvider({ apiKey: KEY, modelId: lite.id });
r = await b.testConnection();
assert(r.ok === true && seen.some((u) => !/lite/.test(u)), "persistent 503 on Flash-Lite falls back to the sibling Gemini model");
assert(b.getAIStatus().model === lite.model && b.getAIStatus().modelId === lite.id, "person's selected model is not silently changed");

// 3) everything overloaded -> clear message, key is NOT rejected and NOT deleted
globalThis.fetch = async () => new Response(OVERLOAD, { status: 503 });
let c = await mk(3);
c.initAIProvider({ apiKey: KEY, modelId: lite.id });
await c.saveAIConfigAsync();
r = await c.testConnection();
assert(r.ok === false && r.status === 503 && r.rejected === false, "503 is reported as 'not rejected' (the key is fine)");
assert(/المفتاح سليم|Your key is fine/.test(r.error) && !/experiencing high demand/.test(r.error), "message says the key is fine, with no raw English text");
assert(store.has("trustai_ai_cfg") && c.isAIAvailable(), "key stays saved and connected after the outage");

// 4) a genuinely rejected key (401) is still detected as rejected
globalThis.fetch = async () => new Response(JSON.stringify({ error: { message: "API key not valid" } }), { status: 401 });
let d = await mk(4);
d.initAIProvider({ apiKey: KEY, modelId: lite.id });
r = await d.testConnection();
assert(r.rejected === true, "401 is still treated as a rejected key");

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
