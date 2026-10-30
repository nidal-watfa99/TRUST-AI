/**
 * TRUST AI — transparency panel («الأدلة وحدود الفحص»)
 * Run: node tests/transparency.test.js
 */
let passed = 0, failed = 0;
const assert = (c, m) => (c ? (passed++, console.log("  ✓", m)) : (failed++, console.error("  ✗", m)));
const mem = new Map();
globalThis.localStorage = { getItem: (k) => (mem.has(k) ? mem.get(k) : null), setItem: (k, v) => mem.set(k, String(v)), removeItem: (k) => mem.delete(k) };
globalThis.sessionStorage = { getItem: () => null, setItem: () => {}, removeItem: () => {} };

const { analyze } = await import("../js/risk-engine.js");
const { buildTransparency } = await import("../js/transparency.js");
const { renderSourceReport } = await import("../js/source-report.js");

console.log("\n=== Transparency ===\n");
const text = "عاجل! حسابك PayPal موقوف، أدخل بياناتك الآن عبر https://paypal-secure.com/login";
const result = analyze({ text });
const ar = buildTransparency({ result, hosts: ["paypal-secure.com"], lang: "ar" });
assert(ar.evidence.some((e) => e.source === "local" && /paypal-secure\.com/i.test(e.text) && e.certainty === "high"), "names the look-alike domain, source 'local', certainty high");
assert(ar.evidence.some((e) => /حدّ أدنى/.test(e.text)), "discloses that a score floor was applied");
assert(ar.notChecked.some((x) => /السمعة/.test(x)) && ar.notChecked.some((x) => /الذكاء الاصطناعي/.test(x)), "lists what was NOT checked (reputation DBs, AI)");
assert(ar.notChecked.some((x) => /عمر النطاق/.test(x)), "says domain age was not checked while the opt-in is off");

const en = buildTransparency({ result, hosts: ["paypal-secure.com"], lang: "en" });
assert(en.notChecked.some((x) => /reputation/i.test(x)), "English version works");

const official = buildTransparency({ result: analyze({ text: "https://support.apple.com/en-us" }), hosts: ["support.apple.com"], lang: "en" });
assert(official.evidence.some((e) => /confirms the domain only/.test(e.text)), "an official domain is confirmed WITHOUT claiming the message is genuine");

const aged = buildTransparency({ result, hosts: ["paypal-secure.com"], lang: "en", netcheck: true, ageResults: { "paypal-secure.com": { ok: true, ageDays: 5, createdAt: "2026-10-25" } } });
assert(aged.evidence.some((e) => e.source === "web" && /5 days/.test(e.text)), "domain age (web lookup) is shown with its own source label");
const failedAge = buildTransparency({ result, hosts: ["paypal-secure.com"], lang: "en", netcheck: true, ageResults: { "paypal-secure.com": { ok: false, reason: "network" } } });
assert(failedAge.notChecked.some((x) => /Could not fetch the age/.test(x)), "a failed lookup is reported as not checked — never as safe");

// full report renders without a browser and without throwing
const fake = () => { const n = { innerHTML: "", _kids: {}, querySelector(sel) { return (this._kids[sel] ||= fake()); }, addEventListener() {} }; return n; };
const el = fake();
let threw = false;
try { renderSourceReport(el, { text, result, lang: "ar" }); } catch (e) { threw = true; console.error(e); }
assert(!threw && el.innerHTML.includes("sr-evidence"), "source report renders with the new evidence section");
assert(el._kids["#sr-evidence"] && el._kids["#sr-evidence"].innerHTML.includes("الأدلة وحدود الفحص"), "the evidence panel is mounted and filled");

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
