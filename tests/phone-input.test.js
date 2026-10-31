/**
 * TRUST AI — phone check: input robustness + the input field must be readable
 * Run: node tests/phone-input.test.js
 */
import { readFileSync } from "node:fs";
let passed = 0, failed = 0;
const assert = (c, m) => (c ? (passed++, console.log("  ✓", m)) : (failed++, console.error("  ✗", m)));
const store = new Map();
globalThis.localStorage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };
globalThis.sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
const log = console.log; console.log = (...a) => { if (!String(a[0]).includes("TRUST-AI-SEC")) log(...a); };
const { checkPhone, previewPhone } = await import("../js/phone-check.js");
const { normalizePhoneInput } = await import("../js/security.js");
const SYRIA = "+963944123456";

console.log("\n=== The same number, typed in every common way ===\n");
const variants = {
  "ASCII international": "+963 944 123 456",
  "Arabic-Indic digits": "+٩٦٣ ٩٤٤ ١٢٣ ٤٥٦",
  "Persian digits": "+۹۶۳ ۹۴۴ ۱۲۳ ۴۵۶",
  "full-width digits": "+９６３９４４１２３４５６",
  "00 prefix": "00963944123456",
  "no plus": "963 944 123 456",
  "dashes and brackets": "(+963) 944-123-456",
  "RTL plus at the end": "963944123456+",
  "invisible RTL marks": "\u200f+963 944 123 456\u200f",
  "with (0) trunk": "+963 (0) 944 123 456",
  "with 0 after code": "+963 0944 123 456",
  "tel: link": "tel:+963944123456",
};
for (const [name, v] of Object.entries(variants)) {
  const r = checkPhone(v);
  assert(r.ok && r.profile && r.profile.display === SYRIA && r.profile.country?.name_ar === "سوريا", `${name} → ${SYRIA} (Syria)`);
}

console.log("\n=== Local formats ===\n");
let r = checkPhone("٠٩٤٤١٢٣٤٥٦");
assert(r.ok && r.profile.display === "0944123456" && /^[\x20-\x7e]+$/.test(r.profile.display), "Arabic-digit local number is shown with ASCII digits");
r = checkPhone("0944123456");
assert(r.ok && r.profile.country?.name_ar === "سوريا", "local 09… number is read as Syrian");
r = checkPhone("+39 06 1234 5678");
assert(r.ok && r.profile.country?.iso === "it" && /06/.test(r.profile.e164 || r.profile.digits), "Italy keeps its leading 0 (not stripped)");

console.log("\n=== Rejects what is not a number, never throws ===\n");
for (const bad of ["abc", "12", "", "   ", "+", "++++", "<script>alert(1)</script>", "9".repeat(500)]) {
  let ok = true, res;
  try { res = checkPhone(bad); } catch (_) { ok = false; }
  assert(ok && res && typeof res.ok === "boolean", `handles ${JSON.stringify(bad.slice(0, 24))}`);
}
r = checkPhone("abc");
assert(!r.ok && /غير صالح/.test(r.title_ar), "gibberish gets a clear 'invalid number' message");
assert(normalizePhoneInput("+٩٦٣ ٩٤٤") === "+963944", "normalizePhoneInput understands Arabic digits (used by the report form too)");

console.log("\n=== Risk detection still works ===\n");
r = checkPhone("+225 0102030405");
assert(r.profile && r.profile.level === "high", "a callback-scam style number is still rated high");
r = checkPhone("+1 876 555 0100");
assert(r.profile && r.profile.score >= 60, "a Caribbean +1 range (callback scam pattern) is still flagged");

console.log("\n=== Live preview ===\n");
let p = previewPhone("٩٦٣٩٤٤١٢٣٤٥٦");
assert(p === null || p.display.startsWith("963") || p.display.startsWith("+963"), "preview accepts Arabic digits");
p = previewPhone("+963944123456");
assert(p && p.display === "+963 944 123 456" && p.country.name_ar === "سوريا", "preview shows the grouped number and its country");
p = previewPhone("0944123456");
assert(p && p.local === true, "preview says when a number is local-format");
assert(previewPhone("9") === null, "no preview for fewer than 3 digits");

console.log("\n=== The field is readable (CSS) ===\n");
const css = readFileSync(new URL("../css/styles.css", import.meta.url), "utf8");
const rule = /(^|\n|\})\s*\.text-input\s*\{([^}]*)\}/.exec(css);
assert(rule && /background\s*:/.test(rule[2]) && /(^|[;\s])color\s*:/.test(rule[2]), "`.text-input` has an explicit background AND text colour");
assert(/text-fill-color\s*:\s*var\(--text\)/.test(rule ? rule[2] : ""), "text colour is forced (some mobile browsers override it in dark mode)");
assert(/\.text-input::placeholder/.test(css) && /color-scheme\s*:\s*dark/.test(css) && /color-scheme\s*:\s*light/.test(css), "placeholder colour and native colour-scheme are set for both themes");
const html = readFileSync(new URL("../index.html", import.meta.url), "utf8");
const used = [...html.matchAll(/class="([^"]*\btext-input\b[^"]*)"/g)].length;
assert(used >= 6, `${used} fields use the now-styled .text-input class (phone, searches, report form)`);

console.log = log;
console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
