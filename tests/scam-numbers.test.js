/** Run: node tests/scam-numbers.test.js — foreign-number intelligence + news verdict rules */
let passed = 0, failed = 0;
const assert = (c, m) => { if (c) { passed++; console.log("  ✓", m); } else { failed++; console.error("  ✗", m); } };
const store = new Map();
globalThis.localStorage = { getItem: (k) => store.get(k) ?? null, setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };

const { profileNumber, searchScamNumbers, listScamNumberCards, normalizeIntl } = await import("../js/scam-numbers.js");
const { normalizeNewsVerdict, ratingToStance } = await import("../js/news-verdict.js");

console.log("\n=== foreign scam numbers ===\n");
let p = profileNumber("+225 07 12 34 56 78");
assert(p.ok && p.level === "high" && p.types.some((t) => t.id === "wangiri"), "Côte d'Ivoire → one-ring indicator, high");
p = profileNumber("00216 20 123 456");
assert(p.ok && p.country.code === "216" && p.explicitIntl, "00 prefix is read as international (+216)");
p = profileNumber("+1 876 555 0100");
assert(p.region?.area === "876" && p.level === "high", "+1 876 is Jamaica (not USA) and flagged");
p = profileNumber("+1 415 555 0100");
assert(p.country.code === "1" && !p.region && p.level !== "high", "regular US number is not flagged by prefix");
p = profileNumber("+882 1234 5678");
assert(p.special && p.level === "high", "satellite/international range → high");
p = profileNumber("٠٠٢٢٥٠٧١٢٣٤٥٦٧٨");
assert(p.ok && p.country?.code === "225", "Arabic-Indic digits are understood");
p = profileNumber("0933123456");
assert(p.ok && !p.intl && p.country?.code === "963" && p.level !== "high", "local Syrian format stays low (with spoofing caveat)");
assert(profileNumber("12").ok === false, "too short is rejected");
p = profileNumber("+225 07 12 34 56 78", { localReports: [{ phone: "+225071234567" + "8" }] });
assert(p.reports === 1 && p.score >= 85, "own local report raises the score");
assert(p.cannot_ar.length >= 3 && p.lookups.length >= 1, "dossier states what cannot be known + lookups");
assert(!JSON.stringify(listScamNumberCards()).match(/\+\d{9,}/), "database ships NO individual full phone numbers");
assert(searchScamNumbers("+225").length > 0, "search by prefix finds the range card");
assert(searchScamNumbers("واتساب").length > 0, "search by Arabic keyword works");
assert(normalizeIntl("+963 (933) 12-34").digits === "96393312" + "34", "normalizeIntl strips punctuation");

console.log("\n=== news verdict rules ===\n");
const src = [{ url: "https://example.org/a", title: "example.org" }];
let v = normalizeNewsVerdict({ verdict: "false", confidence: 92, evidence: [{ publisher: "P", stance: "refutes", url: "https://example.org/a" }] }, { grounded: true, sources: src });
assert(v.verdict === "false" && v.balance.urlBacked === 1, "false + real source URL → kept");
v = normalizeNewsVerdict({ verdict: "true", confidence: 95, evidence: [{ publisher: "P", stance: "supports", url: "https://invented.example/x" }] }, { grounded: true, sources: [] });
assert(v.verdict === "unproven" && v.notes.includes("no_sources"), "invented URL is dropped → verdict downgraded to unproven");
v = normalizeNewsVerdict({ verdict: "true", confidence: 99, evidence: [{ publisher: "P", stance: "supports" }] }, { grounded: false });
assert(v.verdict === "unproven" && v.notes.includes("model_only"), "model-only 'true' without enough evidence → unproven");
v = normalizeNewsVerdict({ verdict: "true", confidence: 90, evidence: [{ publisher: "A", stance: "supports" }, { publisher: "B", stance: "supports" }] }, { grounded: false });
assert(v.verdict === "true" && v.basis === "model" && v.confidence <= 75, "model-only verdict needs ≥80% & 2 items, and is capped at 75%");
v = normalizeNewsVerdict({ verdict: "true", confidence: 90, evidence: [] }, { grounded: true, sources: src, factChecks: [{ url: "https://fc.example/1", publisher: "FC", rating: "False", claim: "c" }] });
assert(v.verdict === "unproven" && v.notes.includes("conflict"), "fact-checker 'False' beats a model 'true' → conflict → unproven");
assert(ratingToStance("مضلل") === "refutes" && ratingToStance("True") === "supports" && ratingToStance("Mostly false") === "refutes", "ratings map to stances in AR/EN");
v = normalizeNewsVerdict({ verdict: "weird", claims: [{ claim: "x", verdict: "true" }] }, { grounded: false });
assert(v.verdict === "unproven" && v.claims[0].verdict === "unproven", "bad enum / uncited claim → unproven");
assert(v.explanation === "" && Array.isArray(v.evidence), "output is always well-formed");

console.log(`\n${passed} passed, ${failed} failed`);
process.exit(failed ? 1 : 0);
