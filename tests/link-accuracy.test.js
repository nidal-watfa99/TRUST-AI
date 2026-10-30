/**
 * TRUST AI — link-check accuracy on a hand-made reference set.
 * NOTE: these lists are SYNTHETIC examples written by the developers, not a sample of real-world traffic.
 * They guard against regressions (especially false alarms on real sites); they are not a measured accuracy claim.
 * Run: node tests/link-accuracy.test.js
 */
import { analyze, analyzeLink } from "../js/risk-engine.js";
const linkScore = (u) => analyze({ text: u }).score; // the score a person would actually see
import { analyzeDomain, punyDecode, toUnicodeHost, fetchDomainAge, registeredDomain } from "../js/domain-intel.js";
import { domainToUnicode } from "node:url";

let passed = 0, failed = 0;
const assert = (c, m) => (c ? (passed++, console.log("  ✓", m)) : (failed++, console.error("  ✗", m)));

const LEGIT = [
  "https://groups.google.com/forum", "https://www.paypal.com/signin", "https://support.apple.com/ar-sa", "https://www.amazon.de/",
  "https://github.com/", "https://www.bbc.co.uk/news", "https://help.netflix.com", "https://www.citibank.com", "https://taxfoundation.org",
  "https://www.wellsfargo.com", "https://store.steampowered.com", "https://www.irs.gov/refunds", "https://www.hsbc.com", "https://www.upsurge.org",
  "https://wise.com/", "https://accounts.google.com/signin", "https://www.microsoft.com/en-us", "https://login.microsoftonline.com", "https://www.facebook.com/login",
  "https://www.binance.com/en", "https://www.dhl.com/track", "https://en.wikipedia.org/wiki/Phishing", "https://www.applebees.com", "https://www.pineapple.com",
  "https://www.mozilla.org", "https://www.who.int", "https://www.un.org", "https://web.whatsapp.com", "https://t.me/telegram", "https://www.ups.com/track",
];
const SCAM = [
  "https://paypa1.com/login", "https://rnicrosoft.com/verify", "https://paypall.com/secure", "https://paypal-secure.com/signin", "https://secure-binance-login.xyz",
  "https://binancesupport.com", "https://paypal.xyz/account", "https://paypal.com.account-verify.top/login", "https://apple-support.com/unlock", "https://goog1e.com",
  "https://xn--pypal-4ve.com", "https://faceb00k-login.net", "https://amaz0n.co/refund", "https://netflix.verify-billing.click", "https://microsoft-support.top/alert",
  "https://coinbase-wallet-verify.xyz", "https://dhl-tracking-pay.shop", "https://instagram-help-center.click", "https://whatsapp-gold.cyou",   "http://192.168.12.5/paypal/login", "https://secure.paypal.com@evil-site.tk/login",
];

console.log("\n=== Link check on reference set ===\n");
const legitScores = LEGIT.map((u) => [u, linkScore(u)]);
const falseAlarms = legitScores.filter(([, sc]) => sc >= 25);
assert(falseAlarms.length === 0, `no real/legit site is raised to a warning (${LEGIT.length} checked)${falseAlarms.length ? " — " + JSON.stringify(falseAlarms) : ""}`);
const scamScores = SCAM.map((u) => [u, linkScore(u)]);
const missed = scamScores.filter(([, sc]) => sc < 30);
assert(missed.length === 0, `every scam-style link is flagged (${SCAM.length} checked)${missed.length ? " — missed: " + JSON.stringify(missed) : ""}`);

assert(analyzeLink("https://bit.ly/3xYzAbC").flags.includes("shortener"), "URL shorteners are flagged as hiding the destination (without calling them scams)");
assert(analyze({ text: "paypa1.com" }).transparent.floor?.kind === "homoglyph", "the score floor is reported openly in the result (transparency)");

console.log("\n=== Domain helpers ===\n");
assert(toUnicodeHost("xn--pypal-4ve.com") === domainToUnicode("xn--pypal-4ve.com"), "punycode decoder agrees with Node's reference decoder");
assert(punyDecode("bcher-kva") === "bücher", "punycode: bücher");
assert(registeredDomain("a.b.example.co.uk") === "example.co.uk", "registered domain with multi-part TLD");
assert(analyzeDomain("support.apple.com").official === "apple", "official brand domain is recognised (allow-list)");
assert(analyzeDomain("paypa1.com").findings[0]?.kind === "homoglyph", "digit-for-letter look-alike detected");

console.log("\n=== Domain age (RDAP, opt-in) with a simulated server ===\n");
const day = 86400000;
const mockOk = async () => new Response(JSON.stringify({ events: [{ eventAction: "registration", eventDate: new Date(Date.now() - 9 * day).toISOString() }] }), { status: 200 });
let r = await fetchDomainAge("new-shop-example.com", { fetchImpl: mockOk });
assert(r.ok && r.ageDays >= 8 && r.ageDays <= 10, "reads the registration date and computes the age");
r = await fetchDomainAge("x-y-z.example", { fetchImpl: async () => new Response("", { status: 404 }) });
assert(!r.ok && r.reason === "not-found", "404 is reported as unknown, never as 'safe'");
r = await fetchDomainAge("down.example.com", { fetchImpl: async () => { throw new TypeError("blocked"); } });
assert(!r.ok && r.reason === "network", "network failure degrades gracefully");
r = await fetchDomainAge("bad host!.com", { fetchImpl: mockOk });
assert(!r.ok && r.reason === "invalid", "invalid input is never sent over the network");

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
