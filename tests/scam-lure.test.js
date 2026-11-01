/**
 * TRUST AI — regression for a real miss: a "spin-to-earn / fake winnings / referral" crypto-casino page
 * (slotcoiner-style) used to score 0–20 ("low"). Run: node tests/scam-lure.test.js
 */
let passed = 0, failed = 0;
const assert = (c, m) => (c ? (passed++, console.log("  ✓", m)) : (failed++, console.error("  ✗", m)));
const mem = new Map();
globalThis.localStorage = { getItem: (k) => (mem.has(k) ? mem.get(k) : null), setItem: (k, v) => mem.set(k, String(v)), removeItem: (k) => mem.delete(k) };
globalThis.sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
const realLog = console.log; console.log = (...a) => { if (!String(a[0]).includes("TRUST-AI-SEC")) realLog(...a); };
const { analyze } = await import("../js/risk-engine.js");
const { KNOWN_SCAM_DOMAINS, lookupKnownScam } = await import("../js/known-scams.js");
const { buildTransparency } = await import("../js/transparency.js");

const URL1 = "https://slotcoiner.com/?email=nidalwatfa99%40gmail.com&src=em";
const SCREEN = `Welcome to Slot Coiner. 182,409.00 $ Coiner Won. 7425.9092 $ Coiner Sign Up Bonus. 10 signed up from your link. Total earned 189934.9092 $ Coiner. Spins left 0. Free spins renew at 00:00 within 24 hours. Withdraw your winnings to your wallet 189,934.91 $ Coiner available. Click Here to Share and Get 1 Spin for each Share Instantly! Andrew D. just withdrew $ Coiner 1,468,355 1 minute ago. Share your link with Friends / Social networks and get for every friend that register. جائزة بيبي دوج بقيمة مليون دولار متاحة الآن! انقر هنا لتجربة حظك!`;

console.log("\n=== The real case ===\n");
let r = analyze({ text: URL1 });
assert(r.level === "severe" && r.score >= 85 && r.transparent.floor.kind === "known_scam", "the documented scam domain is rated severe even as a bare link");
assert(r.reasons.includes("known_scam") && r.links[0].flags.includes("email_in_url") && r.links[0].flags.includes("gambling_keywords"), "flags: documented scam, YOUR email inside the link, gambling-style domain name");
r = analyze({ text: SCREEN });
assert(r.categories.lure >= 35 && r.score >= 55 && ["high", "severe"].includes(r.level), "the page text alone (no link, no blocklist) is now HIGH risk — it used to be 20/100 'low'");
assert(r.transparent.floor?.kind === "lure", "the lure floor is declared openly in the result");

console.log("\n=== Works on scam sites nobody has listed yet ===\n");
r = analyze({ text: "https://spin-win-coiner.xyz/?email=someone%40example.com\n" + SCREEN });
assert(!lookupKnownScam("spin-win-coiner.xyz") && r.score >= 55, "a brand-new look-alike site with the same lure is caught by patterns, not by a list");
r = analyze({ text: "جائزة بيبي دوج بقيمة مليون دولار متاحة الآن! انقر هنا لتجربة حظك!" });
assert(r.score >= 25, "the Arabic prize banner alone is at least 'medium'");

console.log("\n=== A link nobody knows is never a green light ===\n");
r = analyze({ text: "https://some-unknown-shop-example.org/offer" });
assert(r.level === "unknown" && r.score === -1 && r.reasons.includes("unverified_link"), "an unknown bare link → 'unknown / needs verification', not 'low risk'");
r = analyze({ text: "https://support.apple.com/en-us/HT201994" });
assert(r.level === "low", "an official domain is still low");
r = analyze({ text: "Dinner at 8 tomorrow? Menu is here https://some-unknown-shop-example.org/menu — tell me what you think of the pasta." });
assert(r.level !== "unknown" || r.score < 0 === false, "a normal conversation that merely contains a link is not turned into 'unknown'");

console.log("\n=== No false alarms on honest text ===\n");
for (const t of ["Refer a friend and get a $10 credit on your next order.", "Congratulations on your promotion! See you at the team lunch.", "Your invoice #4521 is attached. Payment is due on the 15th.", "الاجتماع غدًا الساعة العاشرة في المكتب"]) {
  assert(analyze({ text: t }).score < 25, `low/none: "${t.slice(0, 48)}"`);
}

console.log("\n=== Evidence discipline of the built-in list ===\n");
assert(KNOWN_SCAM_DOMAINS.every((d) => d.sources.length >= 2 && d.sources.every((s) => s.url.startsWith("https://") && s.date && s.says)), "every built-in entry has ≥2 sources, each with URL, date and what it says");
assert(KNOWN_SCAM_DOMAINS.every((d) => /^[a-z0-9.-]+\.[a-z]{2,}$/.test(d.domain)), "only domains are listed (never people)");
mem.set("trustai_local_reports", JSON.stringify([{ url: "https://my-reported-scam.example/x", createdAt: "2026-11-01" }]));
assert(lookupKnownScam("my-reported-scam.example")?.origin === "local", "a site the person reported himself is recognised later");
assert(analyze({ text: "https://my-reported-scam.example/promo" }).score >= 85, "…and rated severe");

console.log("\n=== Explained to the person ===\n");
const tr = buildTransparency({ result: analyze({ text: URL1 + "\n" + SCREEN }), hosts: ["slotcoiner.com"], lang: "ar" });
assert(tr.evidence.some((e) => /Gridinsoft/.test(e.text) && /Trustpilot/.test(e.text)), "the evidence panel names the sources behind the listing");
assert(tr.evidence.some((e) => /حدّ أدنى/.test(e.text)), "the score floor is disclosed");

console.log = realLog;
console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
