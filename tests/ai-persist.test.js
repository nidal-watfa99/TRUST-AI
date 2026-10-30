/**
 * TRUST AI — API key persistence tests
 * Run: node tests/ai-persist.test.js
 */
let passed = 0, failed = 0;
const assert = (c, m) => (c ? (passed++, console.log("  ✓", m)) : (failed++, console.error("  ✗", m)));

const store = new Map();
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
};
globalThis.sessionStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };

const KEY = "AIzaSyTestKeyForUnitTests_1234567890";
// A fresh import = a fresh page load (module state is reset, localStorage survives)
const load = (n) => import(`../js/ai-provider.js?reload=${n}`);

console.log("\n=== API key persistence ===\n");

let a = await load(1);
const m = a.getFreeModels().find((x) => x.provider === "gemini") || a.getFreeModels()[0];
assert(a.initAIProvider({ apiKey: KEY, modelId: m.id }) === true, "key accepted");
assert(!store.has("trustai_ai_cfg"), "NOT saved before the connection test succeeds");
assert(a.saveAIConfig() === true && store.has("trustai_ai_cfg"), "saved after a successful connection");

let b = await load(2); // "leave the app and come back"
assert(b.getAIStatus().available === false, "fresh page load starts disconnected");
assert(b.restoreAIProvider() === true && b.getAIStatus().available === true, "key restored after reopening");
assert(b.isAIAvailable() === true, "AI is available again without re-entering the key");

b.clearAIProvider(); // manual disconnect
assert(!store.has("trustai_ai_cfg"), "manual disconnect removes the saved key");
let c = await load(3);
assert(c.restoreAIProvider() === false && c.getAIStatus().available === false, "after disconnect nothing is restored");

store.set("trustai_ai_cfg", "{not json");
let d = await load(4);
assert(d.restoreAIProvider() === false, "tampered storage is ignored");
store.set("trustai_ai_cfg", JSON.stringify({ v: 1, apiKey: "bad key\nx", modelId: m.id }));
let e = await load(5);
assert(e.restoreAIProvider() === false && !store.has("trustai_ai_cfg"), "invalid saved key is refused and removed");

// ── Regression: the saved key must survive failures, bad input and "internal navigation" ──
store.clear();
let f = await load(10);
f.initAIProvider({ apiKey: KEY, modelId: m.id });
await f.saveAIConfigAsync();
assert(store.has("trustai_ai_cfg"), "saveAIConfigAsync stores and read-back verifies the key");
assert((await f.saveAIConfigAsync()).ok === true, "save is confirmed (ok:true)");
assert(f.initAIProvider({ apiKey: "bad key", modelId: m.id }) === false, "invalid key refused in memory");
assert(store.has("trustai_ai_cfg"), "an invalid key does NOT erase the saved key");
f.initAIProvider({ apiKey: "AIzaSyAnotherKey_ABCDEFGHIJ12345678", modelId: m.id }); // a new, not-yet-verified key
await f.revertToSavedAI(); // provider rejected it (401)
assert(f.isAIAvailable() && store.has("trustai_ai_cfg"), "after a rejected new key the previous saved key is back");
assert(JSON.parse(store.get("trustai_ai_cfg")).apiKey === KEY, "saved key is still the original one");
store.delete("trustai_ai_cfg"); // browser evicted localStorage while the app is open
assert((await f.syncAIConfig()) === false && store.has("trustai_ai_cfg"), "evicted storage is healed on return to the app");
let g = await load(11);
assert((await g.restoreAIProviderAsync()) === true && g.isAIAvailable(), "key comes back after a new page load");
g.clearAIProvider();
assert(!store.has("trustai_ai_cfg") && !g.isAIAvailable(), "only the manual disconnect removes it");

console.log(`\n${passed} passed, ${failed} failed\n`);
if (failed) process.exit(1);
