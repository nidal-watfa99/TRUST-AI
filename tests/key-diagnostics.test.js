/**
 * TRUST AI — key diagnostics + encrypted backup + version consistency
 * Run: node tests/key-diagnostics.test.js
 */
import { readFileSync } from "node:fs";
let passed = 0, failed = 0;
const assert = (c, m) => (c ? (passed++, console.log("  ✓", m)) : (failed++, console.error("  ✗", m)));
const store = new Map();
globalThis.localStorage = { getItem: (k) => (store.has(k) ? store.get(k) : null), setItem: (k, v) => store.set(k, String(v)), removeItem: (k) => store.delete(k) };
globalThis.sessionStorage = { getItem: () => null, setItem() {}, removeItem() {} };
const realLog = console.log; console.log = (...a) => { if (!String(a[0]).includes("TRUST-AI-SEC")) realLog(...a); };
const mk = (n) => import(`../js/ai-provider.js?d=${n}`);
const GEM = "AIzaSyDiagGeminiKey_ABCDEFGHIJKLMNOPQRS1234";
const GROQ = "gsk_DiagGroqKey_ABCDEFGHIJKLMNOPQRSTUVWXYZ12";
const PASS = "backup passphrase 42";
const all = () => [...store.values()].join("|");

console.log("\n=== In-app browser detection ===\n");
const { detectInAppBrowser } = await mk(0);
assert(detectInAppBrowser("Mozilla/5.0 (Linux; Android 13; SM-A135F) AppleWebKit/537.36 Chrome/120 Mobile Safari/537.36").detected === false, "ordinary Chrome on Android is not flagged");
assert(detectInAppBrowser("Mozilla/5.0 (Linux; Android 13; SM-A135F; wv) AppleWebKit/537.36 Version/4.0 Chrome/120 Mobile Safari/537.36 Instagram 300.0").name === "Instagram", "Instagram's in-app browser is recognised");
assert(detectInAppBrowser("Mozilla/5.0 (Linux; Android 12; wv) AppleWebKit/537.36 Chrome/110 Mobile Safari/537.36 [FB_IAB/FB4A;FBAV/400.0]").name === "Facebook", "Facebook's in-app browser is recognised");
assert(detectInAppBrowser("Mozilla/5.0 (Linux; Android 12; Pixel 6; wv) AppleWebKit/537.36 Chrome/110 Mobile Safari/537.36").name === "WebView", "a bare Android WebView is recognised");

console.log("\n=== Event log & diagnostics never contain a key ===\n");
let a = await mk(1);
const m = a.getFreeModels();
const gem = m.find((x) => x.provider === "gemini"), groq = m.find((x) => x.provider === "groq");
a.initAIProvider({ apiKey: GEM, modelId: gem.id });
await a.saveAIConfigAsync();
a.initAIProvider({ apiKey: GROQ, modelId: groq.id });
await a.saveAIConfigAsync();
let d = await a.getKeyDiagnostics();
assert(d.saved.localStorage && d.saved.keys === 2 && d.active.provider === "groq" && d.active.tail === GROQ.slice(-4), "diagnostics report the saved layers, key count and the active key's last 4 characters");
assert(!JSON.stringify(d).includes(GEM) && !JSON.stringify(d).includes(GROQ) && !JSON.stringify(d).includes(GEM.slice(0, 12)), "no key (or key prefix) appears in the diagnostics");
assert(d.storage.localStorageWorks === true && d.version && d.firstSeen, "storage probe, version and first-use date are included");
assert(d.log.some((x) => x.e === "saved"), "saving is logged");
assert(!all().includes("trustai_keylog") || !/AIza|gsk_/.test(store.get("trustai_keylog")), "the stored event log contains no key material");

let b = await mk(2);
b.restoreAIProvider();
d = await b.getKeyDiagnostics();
assert(d.log.some((x) => x.e === "restored"), "a successful restore on start-up is logged");
await b.removeSavedKey("groq");
d = await b.getKeyDiagnostics();
assert(d.log.some((x) => x.e === "deleted_by_you" && x.d === "groq"), "a deletion by the person is logged as such");
await b.clearAIProvider();
d = await b.getKeyDiagnostics();
assert(d.log.some((x) => x.e === "disconnected_by_you"), "a manual disconnect is logged");

store.clear();
let c = await mk(3);
await c.restoreAIProviderAsync();
d = await c.getKeyDiagnostics();
assert(d.log.some((x) => x.e === "start_nothing_saved") && d.saved.keys === 0, "'nothing saved at start-up' is logged when storage is empty (so a wipe is visible)");

console.log("\n=== Encrypted backup & restore ===\n");
store.clear();
let e = await mk(4);
e.initAIProvider({ apiKey: GEM, modelId: gem.id }); await e.saveAIConfigAsync();
e.initAIProvider({ apiKey: GROQ, modelId: groq.id }); await e.saveAIConfigAsync();
assert((await e.exportKeyBackup("short")).reason === "short", "a weak passphrase is refused");
const ex = await e.exportKeyBackup(PASS);
assert(ex.ok && ex.count === 2 && /^TRUSTAI-BACKUP-1\./.test(ex.text), "export produces one text holding both keys");
assert(!ex.text.includes(GEM) && !ex.text.includes(GROQ) && !/AIza|gsk_/.test(Buffer.from(ex.text.split(".")[3], "base64").toString("latin1")), "the backup text contains no key in clear (AES-GCM)");

store.clear(); // the browser wiped everything
let f = await mk(5);
assert(f.restoreAIProvider() === false, "after the wipe the app has no key");
assert((await f.importKeyBackup(ex.text, "wrong passphrase 1")).reason === "wrong", "a wrong passphrase restores nothing");
assert((await f.importKeyBackup("TRUSTAI-BACKUP-1.AAAA.BBBB.CCCC", PASS)).reason === "wrong", "a tampered/garbage payload is rejected");
assert((await f.importKeyBackup("hello", PASS)).reason === "format", "text that is not a backup is rejected");
const im = await f.importKeyBackup(ex.text, PASS);
assert(im.ok && im.count === 2 && im.active === "groq" && f.isAIAvailable() && f.getAIStatus().provider === "groq", "the right passphrase restores BOTH keys and re-activates the one that was active");
assert((await f.listSavedKeys()).length === 2, "both providers are listed again");
let g = await mk(6);
assert(g.restoreAIProvider() === true, "and it survives the next start (it was written to storage)");

console.log("\n=== Backup with the passphrase lock ===\n");
let h = await mk(7);
h.restoreAIProvider();
assert((await h.enableKeyProtection("vault pass phrase")).ok, "protection enabled with the backup-restored keys");
let locked = await mk(8);
assert((await locked.importKeyBackup(ex.text, PASS)).reason === "locked", "importing while the key lock is closed asks to unlock first");
await locked.unlockAIConfig("vault pass phrase");
const ex2 = await locked.exportKeyBackup(PASS);
assert(ex2.ok && ex2.count === 2, "with the lock open, export still works (keys are read decrypted only in memory)");

console.log("\n=== Version is one number everywhere ===\n");
const { APP_VERSION } = await import("../js/version.js");
const pkg = JSON.parse(readFileSync(new URL("../package.json", import.meta.url), "utf8"));
const sw = readFileSync(new URL("../sw.js", import.meta.url), "utf8");
const i18n = readFileSync(new URL("../js/i18n.js", import.meta.url), "utf8");
assert(pkg.version === APP_VERSION, `package.json (${pkg.version}) = version.js (${APP_VERSION})`);
const sec = await import("../js/security.js");
assert(sec.APP_VERSION === APP_VERSION && sec.BUILD_ID.endsWith(APP_VERSION), "the security module reports the same version (no stale 3.1.0)");
assert(sw.includes(`trust-ai-v${APP_VERSION}`), "service-worker cache name carries the version (old copies are replaced)");
assert((i18n.match(new RegExp("TRUST AI v" + APP_VERSION.replace(/\./g, "\\."), "g")) || []).length === 2, "the footer (Arabic and English) shows the same version");

console.log = realLog;
console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
