#!/usr/bin/env node
/**
 * TRUST AI — single-file bundler (zero dependencies).
 *
 *   node scripts/bundle-single-file.mjs              → dist/trust-ai.standalone.html
 *   node scripts/bundle-single-file.mjs --embedded   → dist/trust-ai.embedded.html
 *
 * standalone : one portable HTML file (CSS, JS, icons inlined). The strict CSP is kept:
 *              inline scripts are allowed ONLY through their SHA-256 hashes.
 *              (No Service Worker — that needs its own file.)
 * embedded   : for previews inside an iframe / sandbox (no CSP meta, no frame guard).
 */
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { createHash } from "node:crypto";
import { join } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname;
const embedded = process.argv.includes("--embedded");
const read = (p) => readFileSync(join(ROOT, p), "utf8");

/* ── 1. Collect ES modules and order them by dependency ───────────────── */
const IMPORT_RE = /^import\s+([\s\S]*?)\s+from\s+["']\.\/([\w.-]+)["'];?[ \t]*$/gm;
const modules = new Map();
function load(name) {
  if (modules.has(name)) return;
  modules.set(name, null); // cycle guard
  const src = read("js/" + name);
  const deps = [...src.matchAll(IMPORT_RE)].map((m) => m[2]);
  deps.forEach((d) => { if (modules.get(d) === null) throw new Error(`Import cycle: ${name} ↔ ${d}`); load(d); });
  modules.set(name, src);
  order.push(name);
}
const order = [];
load("app.js");

function transform(name, src) {
  const exported = [];
  let out = src.replace(IMPORT_RE, (_, clause, file) => {
    const ns = /^\*\s+as\s+(\w+)$/.exec(clause.trim());
    if (ns) return `const ${ns[1]} = __M[${JSON.stringify(file)}];`;
    const inner = /^\{([\s\S]*)\}$/.exec(clause.trim())[1].replace(/\b(\w+)\s+as\s+(\w+)/g, "$1: $2");
    return `const {${inner}} = __M[${JSON.stringify(file)}];`;
  });
  out = out.replace(/^export\s+(async\s+function\*?|function\*?|class)\s+(\w+)/gm, (_, kw, id) => { exported.push(id); return `${kw} ${id}`; });
  out = out.replace(/^export\s+(const|let|var)\s+(\w+)/gm, (_, kw, id) => { exported.push(id); return `${kw} ${id}`; });
  out = out.replace(/^export\s*\{([^}]*)\};?[ \t]*$/gm, (_, list) => { list.split(",").map((s) => s.trim()).filter(Boolean).forEach((s) => { const [a, b] = s.split(/\s+as\s+/); exported.push(b ? `${b}: ${a}` : a); }); return ""; });
  if (/^export\s/m.test(out)) throw new Error(`Unsupported export form in ${name}`);
  const ret = exported.map((e) => (e.includes(":") ? e : `${e}`)).join(", ");
  return `__M[${JSON.stringify(name)}] = (() => {\n${out}\nreturn { ${ret} };\n})();`;
}

const js = `"use strict";\nconst __M = {};\n` + order.map((n) => transform(n, modules.get(n))).join("\n\n");

/* ── 2. Inline icons & CSS ─────────────────────────────────────────────── */
const svgUri = (f) => "data:image/svg+xml;base64," + Buffer.from(read("assets/" + f)).toString("base64");
let html = read("index.html");
const css = read("css/styles.css");

html = html
  .replace(/href="assets\/([\w-]+\.svg)"/g, (_, f) => `href="${svgUri(f)}"`)
  .replace(/src="assets\/([\w-]+\.svg)"/g, (_, f) => `src="${svgUri(f)}"`)
  .replace('<link rel="manifest" href="manifest.json" />\n', "")
  .replace('<link rel="stylesheet" href="css/styles.css" />', () => `<style>\n${css}\n</style>`)
  .replace('<script type="module" src="js/app.js"></script>\n', "")
  .replace('<script src="js/sw-register.js"></script>\n', "");

const hash = (s) => "sha256-" + createHash("sha256").update(s).digest("base64");
const guard = read("js/guard.js");

if (embedded) {
  html = html
    .replace(/<meta http-equiv="Content-Security-Policy"[\s\S]*?\/>\n/, "")
    .replace(/<style id="anti-clickjack">[\s\S]*?<\/style>\n/, "")
    .replace(/<noscript><style>[\s\S]*?<\/style><\/noscript>\n/, "")
    .replace('<script src="js/guard.js"></script>\n', "")
    .replace('content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no"', 'content="width=device-width, initial-scale=1, viewport-fit=cover"');
} else {
  // function replacers: the code contains "$&"-style sequences that String.replace would expand
  html = html.replace('<script src="js/guard.js"></script>', () => `<script>${guard}</script>`)
    .replace("script-src 'self';", () => `script-src 'self' '${hash(guard)}' '${hash("\n" + js + "\n")}';`);
}
html = html.replace("</body>", () => `<script>\n${js}\n</script>\n</body>`);

mkdirSync(join(ROOT, "dist"), { recursive: true });
const outName = embedded ? "dist/trust-ai.embedded.html" : "dist/trust-ai.standalone.html";
writeFileSync(join(ROOT, outName), html);
console.log(`✓ ${outName}  (${(html.length / 1024).toFixed(0)} KB, ${order.length} modules)`);
