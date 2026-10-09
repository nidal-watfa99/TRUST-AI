/**
 * TRUST AI Risk Engine — tests
 * Run: node tests/risk-engine.test.js
 */

import { analyze, analyzeLink, scoreToLevel } from "../js/risk-engine.js";

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    passed++;
    console.log("  ✓", message);
  } else {
    failed++;
    console.error("  ✗", message);
  }
}

console.log("\n=== TRUST AI Risk Engine v1.0 Tests ===\n");

// 1. Fake bank message (AR)
console.log("1. Fake bank message (Arabic)");
{
  const r = analyze({
    text: "عزيزي العميل، حسابك في البنك سيتم إغلاقه خلال 10 دقائق فقط. أدخل رمز التحقق OTP فوراً عبر الرابط: http://bank-secure-login.tk/verify",
  });
  assert(r.score >= 50, `score >= 50 (got ${r.score})`);
  assert(r.level === "high" || r.level === "severe", `level high/severe (got ${r.level})`);
  assert(r.reasons.includes("urgency"), "detects urgency");
  assert(r.reasons.includes("impersonation"), "detects impersonation");
  assert(r.reasons.includes("sensitive"), "detects sensitive request");
  assert(r.reasons.includes("link"), "detects link issues");
  assert(r.transparent?.breakdown?.length > 0, "has transparent breakdown");
  assert(typeof r.categoryPercents.urgency === "number", "has category percents");
}

// 2. OTP request
console.log("\n2. OTP request");
{
  const r = analyze({
    text: "Hi, this is Apple Support. Your account is at risk. Send me the OTP code you just received. Don't tell anyone.",
  });
  assert(r.score >= 25, `score >= 25 (got ${r.score})`);
  assert(r.reasons.includes("sensitive"), "detects sensitive");
  assert(r.reasons.includes("impersonation") || r.reasons.includes("socialEngineering"), "detects impersonation or SE");
}

// 3. Legitimate message
console.log("\n3. Legitimate normal message");
{
  const r = analyze({
    text: "Hi, reminder about tomorrow's meeting at 10 AM in the office. Thanks.",
  });
  assert(r.score <= 24, `score <= 24 (got ${r.score})`);
  assert(r.level === "low", `level low (got ${r.level})`);
}

// 4. Empty input
console.log("\n4. Empty input");
{
  const r = analyze({});
  assert(r.score === -1, "score is -1");
  assert(r.level === "unknown", "level unknown");
}

// 5. Suspicious link
console.log("\n5. Suspicious link analysis");
{
  const la = analyzeLink("http://paypal-secure-login.tk/verify?user=1");
  assert(la.score > 0, `link score > 0 (got ${la.score})`);
  assert(la.indicators.length > 0, "has link indicators");
}

// 6. Investment scam
console.log("\n6. Investment scam");
{
  const r = analyze({
    text: "Invest with us and get guaranteed 30% weekly returns, 100% risk-free. Transfer via USDT now!",
  });
  assert(r.score >= 15, `score >= 15 (got ${r.score})`);
  assert(r.reasons.includes("unrealistic") || r.reasons.includes("money"), "detects unrealistic or money");
}

// 7. scoreToLevel
console.log("\n7. scoreToLevel");
{
  assert(scoreToLevel(10).key === "low", "10 → low");
  assert(scoreToLevel(30).key === "medium", "30 → medium");
  assert(scoreToLevel(60).key === "high", "60 → high");
  assert(scoreToLevel(90).key === "severe", "90 → severe");
}

// 8. Image only
console.log("\n8. Image only (no text)");
{
  const r = analyze({ hasImage: true });
  assert(r.score === -1, "image-only → unknown score");
  assert(r.reasons.includes("image_unavailable"), "flags image_unavailable");
}

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`);
process.exit(failed > 0 ? 1 : 0);
