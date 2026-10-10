/**
 * TRUST AI — language auto-detection tests
 * Run: node tests/i18n.test.js
 */

let passed = 0;
let failed = 0;
function assert(cond, msg) {
  if (cond) { passed++; console.log("  ✓", msg); }
  else { failed++; console.error("  ✗", msg); }
}

// Minimal browser stubs (the module only touches these globals)
const store = new Map();
globalThis.localStorage = {
  getItem: (k) => (store.has(k) ? store.get(k) : null),
  setItem: (k, v) => store.set(k, String(v)),
  removeItem: (k) => store.delete(k),
};
const root = { lang: "", dir: "" };
globalThis.document = {
  documentElement: root,
  querySelectorAll: () => [],
  querySelector: () => null,
};
function setNavigator(languages, language) {
  Object.defineProperty(globalThis, "navigator", {
    value: { languages, language: language ?? (languages && languages[0]) },
    configurable: true,
    writable: true,
  });
}

const { detectLang, getSavedLang, setLang, initI18n, getLang } = await import("../js/i18n.js");

console.log("\n=== i18n auto-detection ===\n");

setNavigator(["en-US", "en"]);
assert(detectLang() === "en", "English device → en");

setNavigator(["ar-SY", "ar"]);
assert(detectLang() === "ar", "Arabic (Syria) device → ar");

setNavigator(["fr-FR", "ar"]);
assert(detectLang() === "ar", "first supported language in the list wins (fr, ar → ar)");

setNavigator(["fr-FR", "de"]);
assert(detectLang() === "en", "unsupported languages fall back to English");

setNavigator(undefined, "AR_EG");
assert(detectLang() === "ar", "falls back to navigator.language, case/underscore tolerant");

// Auto-detection must never be saved (old bug pinned the app to one language)
store.clear();
setNavigator(["en-GB"]);
initI18n();
assert(getLang() === "en" && root.lang === "en" && root.dir === "ltr", "init on English device → en / ltr");
assert(getSavedLang() === null && store.size === 0, "auto-detected language is NOT persisted");

// Legacy sticky value is ignored and removed
store.clear();
store.set("trustai_lang", "ar");
initI18n();
assert(getLang() === "en" && !store.has("trustai_lang"), "legacy trustai_lang value no longer pins the language");

// Device language changes are followed while no explicit choice exists
setNavigator(["ar-SA"]);
initI18n();
assert(getLang() === "ar" && root.dir === "rtl", "device switched to Arabic → ar / rtl");

// Explicit choice wins and persists
setLang("en", { persist: true });
assert(getSavedLang() === "en", "explicit choice is saved");
setNavigator(["ar-SA"]);
initI18n();
assert(getLang() === "en", "explicit choice overrides the device language");

console.log(`\n${passed} passed, ${failed} failed\n`);
if (failed) process.exit(1);
