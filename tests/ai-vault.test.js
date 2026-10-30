/**
 * TRUST AI — passphrase-protected key storage
 * Run: node tests/ai-vault.test.js
 */
let passed = 0, failed = 0;
const assert = (c, m) => (c ? (passed++, console.log("  ✓", m)) : (failed++, console.error("  ✗", m)));
const store = new Map();
globalThis.localStorage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };
globalThis.sessionStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };

const KEY = "AIzaSyVaultTestKey_ABCDEFGHIJKLMN123456";
const PASS = "correct horse battery";
const mk = (n) => import(`../js/ai-provider.js?v=${n}`);
const raw = () => store.get("trustai_ai_cfg") || "";

console.log("\n=== Passphrase-protected key ===\n");

let a = await mk(1);
const m = a.getFreeModels().find((x) => x.provider === "gemini");
a.initAIProvider({ apiKey: KEY, modelId: m.id });
await a.saveAIConfigAsync();
assert((await a.getKeyProtectionState()) === "plain", "starts as a plain saved key");
assert((await a.enableKeyProtection("short")).reason === "short", "passphrase under 8 chars is refused");
assert((await a.enableKeyProtection(PASS)).ok === true, "protection enabled");
assert(!raw().includes(KEY) && !raw().includes("AIza"), "the API key no longer appears in storage in clear text");
assert(JSON.parse(raw()).v === 2 && !!JSON.parse(raw()).ct, "stored record is AES-GCM ciphertext (v2)");
assert((await a.getKeyProtectionState()) === "unlocked", "state: unlocked for this session");
assert(a.isAIAvailable() === true, "AI stays connected in the current session");

// new visit: must be LOCKED, not silently restored
let b = await mk(2);
assert(b.restoreAIProvider() === false && b.isAIAvailable() === false, "new page load: key does NOT auto-connect");
assert((await b.restoreAIProviderAsync()) === false, "IndexedDB/async path cannot bypass the lock");
assert((await b.getKeyProtectionState()) === "locked", "state: locked");
assert(store.has("trustai_ai_cfg"), "locked key is still saved (not deleted)");

// wrong / right passphrase
let r = await b.unlockAIConfig("wrong passphrase");
assert(r.ok === false && r.reason === "wrong" && !b.isAIAvailable(), "wrong passphrase is rejected");
r = await b.unlockAIConfig(PASS);
assert(r.ok === true && b.isAIAvailable() === true, "correct passphrase unlocks and connects");
assert((await b.getKeyProtectionState()) === "unlocked", "state: unlocked after unlock");

// saving while locked must not silently replace the sealed key with a plain one
let c = await mk(3);
c.initAIProvider({ apiKey: "AIzaSyAnotherDifferentKey_ABCDEFGHIJ123456", modelId: m.id });
const sv = await c.saveAIConfigAsync();
assert(sv.ok === false && sv.locked === true, "saving a new key while the old one is locked is refused (no silent downgrade)");
assert(JSON.parse(raw()).v === 2, "sealed record is untouched");

// brute-force back-off
let d = await mk(4);
await d.unlockAIConfig("x1x1x1x1"); await d.unlockAIConfig("x2x2x2x2"); await d.unlockAIConfig("x3x3x3x3");
r = await d.unlockAIConfig(PASS);
assert(r.ok === false && r.reason === "wait", "after 3 wrong guesses further attempts are delayed (even the right one)");

// revert after a rejected new key keeps using the sealed saved key
let e = await mk(5);
await e.unlockAIConfig(PASS);
e.initAIProvider({ apiKey: "AIzaSyRejectedNewKey_ABCDEFGHIJKLMN123456", modelId: m.id });
await e.revertToSavedAI();
assert(e.isAIAvailable() && (await e.getKeyProtectionState()) === "unlocked", "after a rejected new key the sealed saved key is restored");

// turning protection off returns to plain
assert((await e.disableKeyProtection()).ok === true && JSON.parse(raw()).v === 1, "protection can be turned off (unlocked only)");
let f = await mk(6);
assert(f.restoreAIProvider() === true, "plain key auto-connects again");

// manual disconnect removes everything
await e.enableKeyProtection(PASS);
e.clearAIProvider();
assert(!store.has("trustai_ai_cfg") && (await e.getKeyProtectionState()) === "none", "manual disconnect deletes the sealed key too");

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
