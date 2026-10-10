/**
 * TRUST AI — provider selection / connection-test tests
 * Run: node tests/ai-provider.test.js
 */
import { initAIProvider, clearAIProvider, getAIStatus, getFreeModels, detectProviderFromKey, testConnection } from "../js/ai-provider.js";

let passed = 0, failed = 0;
const assert = (c, m) => (c ? (passed++, console.log("  ✓", m)) : (failed++, console.error("  ✗", m)));

const KEYS = {
  gemini: "AIzaSyTestKeyForUnitTests_1234567890",
  groq: "gsk_TestKeyForUnitTests1234567890abcdef",
  openrouter: "sk-or-v1-testkeyforunittests1234567890abcdef",
  openai: "sk-proj-TestKeyForUnitTests1234567890abcdef",
};
const models = getFreeModels();
const firstOf = (p) => models.find((m) => m.provider === p);

console.log("\n=== Provider detection & connection test ===\n");

for (const [p, k] of Object.entries(KEYS)) assert(detectProviderFromKey(k) === p, `${p} key recognised by prefix`);
assert(detectProviderFromKey("something-else-123456") === null, "unknown prefix → null");

// A key must never be sent to the wrong provider because the dropdown was left on another model
for (const [p, k] of Object.entries(KEYS)) {
  const wrong = models.find((m) => m.provider !== p);
  assert(initAIProvider({ apiKey: k, modelId: wrong.id }) === true && getAIStatus().provider === p, `${p} key + wrong model selected → provider switched to ${p}`);
  clearAIProvider();
}
assert(initAIProvider({ apiKey: KEYS.groq, modelId: firstOf("groq").id }) && getAIStatus().modelId === firstOf("groq").id, "matching model is kept as chosen");
clearAIProvider();
assert(initAIProvider({ apiKey: KEYS.groq, modelId: firstOf("gemini").id, customModel: "gemini-2.5-flash" }) && getAIStatus().provider === "groq" && getAIStatus().model !== "gemini-2.5-flash", "custom model of the other provider is dropped");
clearAIProvider();

// Requests go to the right endpoint
let seen = null;
const reply = (obj, status = 200) => async (url, init) => { seen = { url: String(url), init }; return new Response(JSON.stringify(obj), { status }); };

initAIProvider({ apiKey: KEYS.groq, modelId: firstOf("gemini").id });
globalThis.fetch = reply({ choices: [{ message: { content: '{"ok":true}' } }] });
let r = await testConnection();
assert(r.ok === true && seen.url.startsWith("https://api.groq.com/"), "Groq key → api.groq.com endpoint, connected");

// Reasoning models may answer with empty / non-JSON text: key is fine → still connected
globalThis.fetch = reply({ choices: [{ message: { content: "" } }] });
r = await testConnection();
assert(r.ok === true, "HTTP 200 with empty content still counts as connected");

globalThis.fetch = reply({ choices: [{ message: { content: "Sure! pong" } }] });
r = await testConnection();
assert(r.ok === true, "HTTP 200 with non-JSON content still counts as connected");

// ...but real failures must fail and say why
globalThis.fetch = reply({ error: { message: "Invalid API Key" } }, 401);
r = await testConnection();
assert(r.ok === false && /401/.test(r.error), "HTTP 401 → failed, status shown: " + r.error);

globalThis.fetch = reply({ error: { code: 429, message: "Rate limit exceeded" } }, 200);
r = await testConnection();
assert(r.ok === false && /429/.test(r.error), "HTTP 200 carrying an error body (OpenRouter style) → failed, not 'connected'");

globalThis.fetch = async () => { throw new TypeError("Failed to fetch"); };
r = await testConnection();
assert(r.ok === false && /provider|المزوّد/i.test(r.error), "network/regional block → clear message: " + r.error);

console.log(`\n${passed} passed, ${failed} failed\n`);
if (failed) process.exit(1);
