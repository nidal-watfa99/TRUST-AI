/**
 * TRUST AI — import integrity: every `import { x } from "./y.js"` must name something y.js really exports.
 * A single wrong name breaks the WHOLE app at load time in the browser (and node --check cannot see it).
 * Run: node tests/imports.test.js
 */
import { readFileSync, readdirSync } from "node:fs";
let passed = 0, failed = 0;
const assert = (c, m) => (c ? (passed++, console.log("  ✓", m)) : (failed++, console.error("  ✗", m)));
const dir = new URL("../js/", import.meta.url);
const files = readdirSync(dir).filter((f) => f.endsWith(".js"));
const src = Object.fromEntries(files.map((f) => [f, readFileSync(new URL(f, dir), "utf8")]));

const exportsOf = (code) => {
  const names = new Set();
  for (const m of code.matchAll(/export\s+(?:async\s+)?(?:function\*?|const|let|var|class)\s+([A-Za-z_$][\w$]*)/g)) names.add(m[1]);
  for (const m of code.matchAll(/export\s*\{([^}]*)\}/g)) for (const p of m[1].split(",")) { const n = p.trim().split(/\s+as\s+/).pop(); if (n) names.add(n); }
  if (/export\s+default/.test(code)) names.add("default");
  return names;
};
const exp = Object.fromEntries(files.map((f) => [f, exportsOf(src[f])]));

console.log("\n=== Named imports resolve ===\n");
let checked = 0; const problems = [];
for (const f of files) {
  for (const m of src[f].matchAll(/import\s*\{([^}]*)\}\s*from\s*["']\.\/([\w.-]+\.js)["']/g)) {
    const target = m[2];
    if (!exp[target]) { problems.push(`${f}: imports from missing file ${target}`); continue; }
    for (const part of m[1].split(",")) {
      const name = part.trim().split(/\s+as\s+/)[0].trim();
      if (!name) continue;
      checked++;
      if (!exp[target].has(name)) problems.push(`${f}: '${name}' is not exported by ${target}`);
    }
  }
}
assert(problems.length === 0, `${checked} named imports across ${files.length} modules all resolve${problems.length ? " — " + problems.join("; ") : ""}`);

const dyn = [];
for (const f of files) for (const m of src[f].matchAll(/import\(\s*["']\.\/([\w.-]+\.js)["']\s*\)/g)) if (!exp[m[1]]) dyn.push(`${f} → ${m[1]}`);
assert(dyn.length === 0, "dynamic imports point at existing files" + (dyn.length ? " — " + dyn.join("; ") : ""));

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
