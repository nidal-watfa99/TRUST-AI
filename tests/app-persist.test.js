/**
 * TRUST AI — the REAL app, closed and reopened: the AI key must still be there and connected.
 * Each phase runs in its own Node process; localStorage is a file shared between them (like a browser profile).
 * Run: node tests/app-persist.test.js
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, readFileSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
let passed = 0, failed = 0;
const assert = (c, m) => (c ? (passed++, console.log("  ✓", m)) : (failed++, console.error("  ✗", m)));
const dir = mkdtempSync(join(tmpdir(), "trustai-"));
const STORE = join(dir, "profile.json");
const KEY = "AIzaSyRealAppPersistKey_ABCDEFGHIJKLMNOPQ12345";
const run = (phase, extra = {}) => {
  const r = spawnSync(process.execPath, [new URL("./_boot-harness.mjs", import.meta.url).pathname], { env: { ...process.env, STORE_FILE: STORE, PHASE: phase, TEST_KEY: KEY, ...extra }, encoding: "utf8", timeout: 30000 });
  const line = (r.stdout || "").split("\n").find((l) => l.startsWith("RESULT "));
  if (!line) { console.error(r.stdout, r.stderr); return null; }
  return JSON.parse(line.slice(7));
};

console.log("\n=== Session 1: paste the key and press «Save & activate» ===\n");
let a = run("save");
assert(a && a.available && a.provider === "gemini", "key accepted and connected in session 1");
assert(a && a.stored.includes("trustai_ai_cfg"), "the key was written to storage");

console.log("\n=== Session 2: app closed and opened again (new process) ===\n");
let b = run("restore");
assert(b && b.available === true && b.provider === "gemini", "the key is restored and connected automatically — no pasting again");
assert(b && /متصل|connected/i.test(b.badge) && !/غير|not|dis/i.test(b.badge.replace("متصل", "")), "the status badge shows connected on start-up (badge: " + (b && b.badge) + ")");
assert(b && !b.keyFieldValue, "the key field stays empty for safety (the key is NOT shown) — connected state is what matters");

console.log("\n=== Sessions 3-5: repeated close/open never loses it ===\n");
for (let i = 3; i <= 5; i++) { const c = run("restore"); assert(c && c.available, `session ${i}: still connected`); }

console.log("\n=== Browser wiped localStorage but kept nothing else (worst case without IndexedDB) ===\n");
const before = JSON.parse(readFileSync(STORE, "utf8"));
writeFileSync(STORE, JSON.stringify({}));
const w = run("restore");
assert(w && w.available === false, "(documented limit) if the browser erases the site's storage the key is gone — IndexedDB backup only exists in a real browser");
writeFileSync(STORE, JSON.stringify(before));
rmSync(dir, { recursive: true, force: true });

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
