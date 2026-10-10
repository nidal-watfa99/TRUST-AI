/**
 * TRUST AI Client engine — tests
 * Run: node tests/client-engine.test.js
 */
import { buildDossier, detectKind, extractEntities, mergeAI, normalizeUniversal, dossierToText } from "../js/client-engine.js";

let passed = 0, failed = 0;
const assert = (c, m) => { if (c) { passed++; console.log("  ✓", m); } else { failed++; console.error("  ✗", m); } };

console.log("\n=== TRUST AI Client Engine Tests ===\n");

console.log("1. Kind detection");
assert(detectKind("https://example.com/a") === "url", "url");
assert(detectKind("bit.ly/abc123") === "url", "bare short link is url");
assert(detectKind("QNET") === "name", "single word is a name");
assert(detectKind("Mohamed Ali") === "name", "title-case name");
assert(detectKind("", 1) === "image", "image only");
assert(detectKind("hello", 1) === "mixed", "text + image is mixed");
assert(detectKind("Hello how are you today my friend") !== "name", "sentence is not a name");

console.log("\n2. Phishing message");
{
  const d = buildDossier({ text: "عزيزي العميل، سيتم إغلاق حسابك خلال 10 دقائق. أدخل رمز التحقق OTP عبر http://bank-secure-login.tk/verify", lang: "ar" });
  assert(d.score >= 50, `score >= 50 (got ${d.score})`);
  assert(d.event.type === "phishing", `event phishing (got ${d.event.type})`);
  assert(d.warnings.some((w) => w.level === "critical"), "has a critical warning");
  assert(d.entities.urls.length === 1, "extracts the url");
  assert(Object.keys(d.dims).length === 6, "6 risk dimensions");
}

console.log("\n3. Pyramid scheme with secrecy");
{
  const d = buildDossier({ text: "ادفع رسوم اشتراك 1500 دولار واجلب 3 أشخاص من عائلتك لدخل سلبي شهري. لا تخبر أحداً.", lang: "ar" });
  assert(d.event.type === "pyramid", `pyramid (got ${d.event.type})`);
  assert(d.score >= 75, `severe (got ${d.score})`);
  assert(d.warnings.some((w) => w.key === "secrecy"), "secrecy warning");
}

console.log("\n4. Names");
{
  const d = buildDossier({ text: "QNET", lang: "en" });
  assert(d.kind === "name" && d.score >= 75, "watch-listed name flagged high");
  const n = buildDossier({ text: "Ahmed Khalil", lang: "en" });
  assert(n.score === -1 && n.level === "unknown", "ordinary name → needs verification, not 'safe'");
  assert(n.warnings.some((w) => w.key === "name_only"), "explains that a name alone cannot be verified");
}

console.log("\n5. News");
{
  const bad = buildDossier({ text: "BREAKING!!! Insiders say everyone will lose money tomorrow. Share this before they delete it!", lang: "en" });
  assert(bad.event.type === "fake_news" && bad.score >= 50, `fake news flagged (got ${bad.event.type}/${bad.score})`);
  const ok = buildDossier({ text: "The central bank announced on 3 March 2025 a 0.25% rate cut, according to Reuters.", lang: "en" });
  assert(ok.score < 25, `sourced news stays low (got ${ok.score})`);
  assert(ok.unverified === true, "still marked as unverified");
}

console.log("\n6. Images without a vision model");
{
  const d = buildDossier({ text: "", images: 2, lang: "en", visionOn: false });
  assert(d.score === -1, "no judgement without vision");
  assert(d.warnings.some((w) => w.key === "image_no_vision"), "tells the user the image was not analyzed");
}

console.log("\n7. Sensitive paste");
{
  const d = buildDossier({ text: "my password: Hunter2!x and OTP 482913", lang: "en" });
  assert(d.warnings.some((w) => w.key === "sensitive_paste"), "warns about secrets in the input");
}

console.log("\n8. Model merge");
{
  const base = buildDossier({ text: "Ahmed Khalil", lang: "en" });
  const ai = normalizeUniversal({ score: 70, event_type: "romance", dims: { urgency: 40 }, warnings: [{ level: "high", text: "x" }], credibility: { source: 20 } }, "groq", "m");
  const m = mergeAI(base, ai);
  assert(m.score === 70 && m.mode === "hybrid", "AI score replaces unknown");
  assert(m.event.type === "romance", "AI event type applied");
  assert(m.warnings.some((w) => w.text === "x"), "AI warnings appended");
  assert(normalizeUniversal(null) === null, "bad AI output → null");
  assert(typeof dossierToText(m, "en") === "string", "text export");
}

console.log("\n9. Entities");
{
  const e = extractEntities("Write to help@scam-bank.com or call +963 944 123 456, pay $500 to 0x1234567890abcdef1234567890abcdef12345678 via @fake_agent");
  assert(e.emails.length === 1 && e.phones.length >= 1 && e.amounts.length >= 1 && e.crypto.length === 1 && e.handles.length === 1, "email, phone, amount, wallet, handle");
}

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
