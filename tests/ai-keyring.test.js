/**
 * TRUST AI — one saved key PER PROVIDER; keys leave only by the person's own hand
 * Run: node tests/ai-keyring.test.js
 */
let passed = 0, failed = 0;
const assert = (c, m) => (c ? (passed++, console.log("  ✓", m)) : (failed++, console.error("  ✗", m)));
const store = new Map();
globalThis.localStorage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };
globalThis.sessionStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };

const GEM = "AIzaSyGeminiKey_ABCDEFGHIJKLMNOPQRS1234";
const GROQ = "gsk_GroqKey_ABCDEFGHIJKLMNOPQRSTUVWXYZ12";
const OR = "sk-or-v1-OpenRouterKey_ABCDEFGHIJKLMNOPQRSTUV";
const PASS = "correct horse battery";
const mk = (n) => import(`../js/ai-provider.js?k=${n}`);
const allStored = () => [...store.values()].join("|");

console.log("\n=== New free OpenAI models ===\n");
let a = await mk(1);
const models = a.getFreeModels();
const oss = models.filter((m) => m.provider === "openrouter" && /openai\/gpt-oss/.test(m.model));
assert(oss.length === 2 && oss.every((m) => m.free && m.model.endsWith(":free")), "OpenRouter GPT-OSS 120B and 20B (':free') are available");
assert(models.filter((m) => m.provider === "groq" && /gpt-oss/.test(m.model)).length === 2, "Groq GPT-OSS models are still there");
assert(new Set(models.map((m) => m.id)).size === models.length, "model ids are unique");

console.log("\n=== Keyring ===\n");
const gem = models.find((m) => m.provider === "gemini");
const groq = models.find((m) => m.provider === "groq");
const orm = oss[0];
a.initAIProvider({ apiKey: GEM, modelId: gem.id });
await a.saveAIConfigAsync();
a.initAIProvider({ apiKey: GROQ, modelId: groq.id });
await a.saveAIConfigAsync();
a.initAIProvider({ apiKey: OR, modelId: orm.id });
await a.saveAIConfigAsync();
let list = await a.listSavedKeys();
assert(list.length === 3 && ["gemini", "groq", "openrouter"].every((p) => list.some((x) => x.provider === p)), "saving a key for a new provider does NOT replace the others");
assert(list.find((x) => x.provider === "openrouter").active && !list.find((x) => x.provider === "gemini").active, "the latest one is active");

// a new page load comes back with the active key, and the others are still listed
let b = await mk(2);
assert(b.restoreAIProvider() === true && b.getAIStatus().provider === "openrouter", "new visit restores the active key");
assert((await b.listSavedKeys()).length === 3, "all three keys survive a new visit");

// switch provider without typing anything
let r = await b.activateSavedKey("gemini");
assert(r.ok && b.getAIStatus().provider === "gemini", "one tap re-activates the saved Gemini key");
let c = await mk(3);
c.restoreAIProvider();
assert(c.getAIStatus().provider === "gemini" && (await c.listSavedKeys()).length === 3, "the switch is remembered and nothing was lost");

// choosing/inspecting never deletes; only an explicit remove does
await c.removeSavedKey("groq");
list = await c.listSavedKeys();
assert(list.length === 2 && !list.some((x) => x.provider === "groq") && list.some((x) => x.provider === "gemini"), "removing Groq removes ONLY Groq");
assert(c.isAIAvailable() && c.getAIStatus().provider === "gemini", "the active key is untouched by removing another one");

// disconnect removes only the active provider's key
await c.clearAIProvider();
let d = await mk(4);
list = await d.listSavedKeys();
assert(list.length === 1 && list[0].provider === "openrouter", "disconnect deletes only the active provider's key");
assert(!allStored().includes(GEM), "the deleted key is gone from every layer");

// legacy install: only the old single record exists -> still protected when another key is added
store.clear();
store.set("trustai_ai_cfg", JSON.stringify({ v: 1, apiKey: GEM, modelId: gem.id, customModel: "", savedAt: 1 }));
let e = await mk(5);
assert((await e.listSavedKeys()).some((x) => x.provider === "gemini"), "a key saved by the old version shows up in the list");
e.initAIProvider({ apiKey: GROQ, modelId: groq.id });
await e.saveAIConfigAsync();
assert((await e.listSavedKeys()).length === 2, "old key survived when a second provider was added");

console.log("\n=== Keyring + passphrase ===\n");
assert((await e.enableKeyProtection(PASS)).ok, "protection enabled with several saved keys");
assert(!allStored().includes(GEM) && !allStored().includes(GROQ), "NO saved key appears in clear text anywhere");
let f = await mk(6);
assert(f.restoreAIProvider() === false, "new visit: locked");
assert((await f.getKeyProtectionState()) === "locked", "state is locked");
assert((await f.activateSavedKey("gemini")).reason === "locked", "a sealed key cannot be activated before unlocking");
assert((await f.unlockAIConfig(PASS)).ok && f.isAIAvailable(), "passphrase unlocks the active key");
r = await f.activateSavedKey("gemini");
assert(r.ok && f.getAIStatus().provider === "gemini", "after unlocking, the other sealed key can be activated");
assert((await f.disableKeyProtection()).ok, "protection can be turned off");
assert(allStored().includes(GEM) && allStored().includes(GROQ), "all keys are plain again and still present");

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
