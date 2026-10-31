/**
 * TRUST AI — news verification: evidence is tied to REAL retrieved pages, never to the model's memory
 * Run: node tests/news-grounding.test.js
 */
let passed = 0, failed = 0;
const assert = (c, m) => (c ? (passed++, console.log("  ✓", m)) : (failed++, console.error("  ✗", m)));
const mem = new Map();
globalThis.localStorage = { getItem: (k) => (mem.has(k) ? mem.get(k) : null), setItem: (k, v) => mem.set(k, String(v)), removeItem: (k) => mem.delete(k) };
globalThis.sessionStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };
const realST = globalThis.setTimeout;
globalThis.setTimeout = (fn, ms, ...a) => realST(fn, Math.min(ms, 3), ...a);

const { normalizeNewsVerdict } = await import("../js/news-verdict.js");
const ai = await import("../js/ai-provider.js");

const R = "https://vertexaisearch.cloud.google.com/grounding-api-redirect/";
const chunks = [{ url: R + "a1", title: "reuters.com" }, { url: R + "b2", title: "aljazeera.net" }, { url: R + "c3", title: "example-blog.xyz" }];
const sources = chunks;

console.log("\n=== Linking the model's evidence to retrieved pages ===\n");
let v = normalizeNewsVerdict({ verdict: "false", confidence: 90, explanation: "x", evidence: [{ publisher: "Reuters", domain: "reuters.com", stance: "refutes", summary: "Reuters says the video is from 2019.", date: "2019-05-01" }] }, { grounded: true, sources, chunks });
assert(v.evidence[0].linked && v.evidence[0].url === R + "a1", "evidence is linked to the retrieved page by its domain");
assert(v.verdict === "false", "a verdict backed by a linked refuting source stands");

v = normalizeNewsVerdict({ verdict: "false", confidence: 90, evidence: [{ publisher: "Some Agency", domain: "nowhere.example", stance: "refutes", summary: "They refuted it." }] }, { grounded: true, sources, chunks });
assert(!v.evidence[0].linked && v.verdict === "unproven" && v.notes.includes("unlinked"), "evidence the model cannot tie to a retrieved page does NOT carry a verdict");
assert(v.balance.supports + v.balance.refutes === 0, "such evidence is not counted in the balance");

const supports = [{ text: "The footage was first posted in March 2019 in another country", idx: [1] }];
v = normalizeNewsVerdict({ verdict: "false", confidence: 88, evidence: [{ publisher: "Unnamed", stance: "refutes", summary: "The footage was first posted in March 2019 in another country" }] }, { grounded: true, sources, chunks, supports });
assert(v.evidence[0].linked && v.evidence[0].url === R + "b2" && v.verdict === "false", "Google's sentence→page grounding links evidence even without a domain");

v = normalizeNewsVerdict({ verdict: "true", confidence: 90, evidence: [{ publisher: "Reuters", domain: "reuters.com", stance: "supports", summary: "confirmed" }] }, { grounded: true, sources, chunks });
assert(v.verdict === "unproven" && v.notes.includes("single_source"), "'true' from a single independent source stays unproven");
v = normalizeNewsVerdict({ verdict: "true", confidence: 90, evidence: [{ publisher: "Reuters", domain: "reuters.com", stance: "supports", summary: "confirmed" }, { publisher: "Al Jazeera", domain: "aljazeera.net", stance: "supports", summary: "also confirmed" }] }, { grounded: true, sources, chunks });
assert(v.verdict === "true", "'true' with two independent linked sources is accepted");
v = normalizeNewsVerdict({ verdict: "true", confidence: 90, evidence: [{ publisher: "Reuters", domain: "reuters.com", stance: "refutes", summary: "denied" }] }, { grounded: true, sources, chunks });
assert(v.verdict === "unproven" && v.notes.includes("conflict"), "a 'true' verdict contradicted by its own linked evidence → conflict");

console.log("\n=== Claims, explanation, queries ===\n");
v = normalizeNewsVerdict({ verdict: "false", confidence: 80, explanation: "Reuters traced the clip to 2019 footage from Libya.", claims: [
  { claim: "The clip shows today's event", verdict: "false", explanation: "Reuters traced the clip to 2019 footage from Libya.", evidence: [0] },
  { claim: "Dozens were killed", verdict: "false", explanation: "no source", evidence: [] }],
  evidence: [{ publisher: "Reuters", domain: "reuters.com", stance: "refutes", summary: "Clip from 2019" }], manipulation_type: "old_content_recycled", first_seen: "2019-03 · Facebook" },
  { grounded: true, sources, chunks, queries: ["clip libya 2019 fact check"] });
assert(v.claims[0].verdict === "false" && v.claims[0].links.some((l) => l.url === R + "a1"), "a claim shows the real page that backs it");
assert(v.claims[1].verdict === "unproven" && v.claims[1].links.length === 0, "a claim with no real source behind it is demoted to unproven");
assert(v.manipulation === "old_content_recycled" && /2019/.test(v.firstSeen), "manipulation type and first appearance are passed through");
assert(v.queries.length === 1 && /fact check/.test(v.queries[0]), "the searches that were actually run are shown");
v = normalizeNewsVerdict({ verdict: "unproven", manipulation_type: "<script>", evidence: [] }, { grounded: true, sources, chunks });
assert(v.manipulation === "unknown", "unknown manipulation labels are rejected");
v = normalizeNewsVerdict({ verdict: "unproven", evidence: [] }, { grounded: true, sources, chunks });
assert(v.others.length === 3 && v.evidence.length === 0, "retrieved pages nobody used are kept apart (not shown as 'evidence')");

console.log("\n=== Resilient grounded call (503 / quota / search refused) ===\n");
const KEY = "AIzaSyNewsTestKey_ABCDEFGHIJKLMNOPQRS12345";
const ok = (extra = {}) => new Response(JSON.stringify({ candidates: [{ content: { parts: [{ text: JSON.stringify({ verdict: "unproven", confidence: 40, evidence: [], claims: [] }) }] }, groundingMetadata: { webSearchQueries: ["q one", "q two"], groundingChunks: [{ web: { uri: R + "z", title: "reuters.com" } }], groundingSupports: [{ segment: { text: "abc def ghi jkl mno" }, groundingChunkIndices: [0] }] } }] }), { status: 200, ...extra });
const gem = ai.getFreeModels().filter((m) => m.provider === "gemini");
ai.initAIProvider({ apiKey: KEY, modelId: gem[0].id });
const long = "تداول ناشطون مقطعًا يزعم أنه يوثّق حادثة وقعت اليوم في المدينة وأن عشرات الأشخاص قتلوا";

let urls = [], bodies = [];
globalThis.fetch = async (url, init) => { urls.push(String(url)); bodies.push(JSON.parse(init.body)); return urls.length <= 3 ? new Response("{}", { status: 503 }) : ok(); };
let r = await ai.verifyNewsWithAI({ text: long, lang: "ar", imageFacts: ["image 1 (png): METADATA SAYS AI-GENERATED: Stable Diffusion"] });
assert(r.raw && r.grounded && r.queries.length === 2 && r.sources.length === 1, "after 3×503 the call moves on and still returns grounded results with queries and sources");
assert(urls.length === 4 && urls[3] !== urls[0] && !urls[3].includes(gem[0].model), "it fell back to the sibling Gemini model");
assert(r.model === gem[1].model, "the model actually used is reported honestly");
assert(bodies[0].tools && bodies[0].tools[0].google_search && bodies[0].systemInstruction.parts[0].text.includes("RESEARCH PROTOCOL"), "live Google Search is enabled and the strict research protocol is the system instruction");
assert(/Never invent sources/.test(bodies[0].systemInstruction.parts[0].text), "the prompt forbids inventing sources");
assert(JSON.stringify(bodies[0].contents).includes("METADATA SAYS AI-GENERATED"), "image-file facts are handed to the model");

urls = []; bodies = [];
globalThis.fetch = async (url, init) => { const b = JSON.parse(init.body); urls.push(b.tools ? "search" : "nosearch"); return b.tools ? new Response("{}", { status: 400 }) : ok(); };
r = await ai.verifyNewsWithAI({ text: long, lang: "ar" });
assert(r.raw && r.grounded === false && r.searchUnavailable === true, "if the search tool is refused the result says so (searchUnavailable) instead of pretending");

globalThis.fetch = async () => new Response("{}", { status: 503 });
r = await ai.verifyNewsWithAI({ text: long, lang: "ar" });
assert(r.error && !r.raw, "total overload → a clear error, not a fake verdict");

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
