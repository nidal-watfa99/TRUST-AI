#!/usr/bin/env node
/**
 * TRUST AI — static security audit (zero dependencies).
 * Run: npm run audit      Exit code 1 on any failure (used by CI).
 */
import { readFileSync, readdirSync, existsSync, statSync } from "node:fs";
import { join, relative } from "node:path";

const ROOT = new URL("..", import.meta.url).pathname;
const read = (p) => readFileSync(join(ROOT, p), "utf8");
let failed = 0, passed = 0;
const check = (ok, msg, detail = "") => {
  if (ok) { passed++; console.log("  ✓", msg); }
  else { failed++; console.error("  ✗", msg, detail ? "→ " + detail : ""); }
};

function walk(dir, out = []) {
  for (const f of readdirSync(join(ROOT, dir))) {
    if (["node_modules", ".git", "dist"].includes(f)) continue;
    const rel = join(dir, f);
    if (statSync(join(ROOT, rel)).isDirectory()) walk(rel, out); else out.push(rel);
  }
  return out;
}

const html = read("index.html");
const jsFiles = walk("js").filter((f) => f.endsWith(".js"));
const allFiles = walk(".").filter((f) => !/\.(png|jpg|ico|zip)$/i.test(f));

console.log("\n=== TRUST AI Security Audit ===\n");

console.log("1. Content Security Policy (index.html)");
const cspMeta = /http-equiv="Content-Security-Policy"\s+content="([^"]+)"/.exec(html)?.[1] || "";
const csp = Object.fromEntries(cspMeta.split(";").map((d) => d.trim().replace(/\s+/g, " ")).filter(Boolean).map((d) => { const [k, ...v] = d.split(" "); return [k, v]; }));
check(!!cspMeta, "CSP meta tag present");
check(csp["script-src"]?.join(" ") === "'self'", "script-src is exactly 'self' (no unsafe-inline / unsafe-eval / remote)", csp["script-src"]?.join(" "));
check(csp["script-src-attr"]?.[0] === "'none'", "inline event-handler attributes blocked (script-src-attr 'none')");
check(csp["object-src"]?.[0] === "'none'" && csp["base-uri"]?.[0] === "'self'", "object-src 'none' and base-uri 'self'");
check(csp["frame-src"]?.[0] === "'none'", "frame-src 'none'");
check(csp["form-action"]?.[0] === "'none'", "form-action 'none'");
check(!/(^| )\*( |$)/.test(cspMeta) && !/https?:\/\/\*/.test(cspMeta), "no wildcard sources in CSP");
check(!("frame-ancestors" in csp), "frame-ancestors not in <meta> (browsers ignore it there; lives in real headers)");
const hdr = read("headers-cloudflare.txt").replace(/\s+/g, " ");
const hdrConnect = /connect-src ([^;]+);/.exec(hdr)?.[1].trim().split(" ").sort().join(" ");
check(hdrConnect === csp["connect-src"]?.slice().sort().join(" "), "connect-src identical in index.html and headers-cloudflare.txt");
check(read("_headers").includes("frame-ancestors 'none'") && read("_headers").includes("Strict-Transport-Security"), "_headers carries frame-ancestors + HSTS");

console.log("\n2. Dangerous constructs");
const inlineScripts = [...html.matchAll(/<script\b(?![^>]*\bsrc=)[^>]*>/gi)];
check(inlineScripts.length === 0, "no inline <script> blocks in index.html");
check(!/\son[a-z]+\s*=\s*["']/i.test(html), "no inline on*= handlers in index.html");
check(!/javascript:/i.test(html), "no javascript: URLs in index.html");
for (const f of jsFiles) {
  const src = read(f).replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/.*$/gm, "$1");
  const bad = [/\beval\s*\(/, /new\s+Function\s*\(/, /document\.write\s*\(/, /setTimeout\s*\(\s*["'`]/, /setInterval\s*\(\s*["'`]/, /\.insertAdjacentHTML\s*\(/, /\bouterHTML\s*=/].filter((r) => r.test(src));
  check(bad.length === 0, `${f}: no eval/Function/document.write/insertAdjacentHTML`, bad.join(" "));
}

console.log("\n3. Secrets & storage");
const secretRe = [/AIza[0-9A-Za-z_-]{30,}/, /\bsk-[A-Za-z0-9_-]{24,}/, /\bgsk_[A-Za-z0-9]{24,}/, /-----BEGIN [A-Z ]*PRIVATE KEY-----/];
const hits = allFiles.filter((f) => !f.startsWith("tests/") && secretRe.some((r) => r.test(read(f))));
check(hits.length === 0, "no hard-coded API keys / private keys in repository", hits.join(", "));
check(!existsSync(join(ROOT, ".env")), "no real .env committed");
check(/^\.env$/m.test(read(".gitignore")), ".env is git-ignored");
// Design (v3.0.1): the key is saved on THIS device so it survives leaving the app, until the person
// disconnects. It must live in exactly one dedicated entry, written only by ai-provider.js.
const aiSrc = read("js/ai-provider.js");
const keyStore = jsFiles.filter((f) => f !== "js/ai-provider.js" && /(local|session)Storage\.setItem\([^)]*(apiKey|api_key|state\.apiKey)/i.test(read(f)));
check(keyStore.length === 0, "API key is never written to web storage outside js/ai-provider.js", keyStore.join(", "));
check(!/sessionStorage\.setItem\([^)]*(apiKey|api_key|state\.apiKey)/i.test(aiSrc), "API key is never written to sessionStorage");
check(/localStorage\.removeItem\(SAVED_KEY\)/.test(aiSrc), "disconnecting removes the saved API key");
check(/if \(res\.ok\) \{\s*saveAIConfig\(\)/.test(read("js/app.js")) && /if \(res\.ok\) saveAIConfig\(\)/.test(read("js/app.js")), "key is saved only after a successful connection test");
check(!/[?&]key=\$\{/.test(read("js/ai-provider.js")), "API key is never placed in a URL");

console.log("\n4. Links & transport");
const insecure = allFiles.filter((f) => /\.(js|html|json|css|md)$/.test(f) && !f.startsWith("tests/") && f !== "SECURITY.md" && f !== "js/examples.js")
  .flatMap((f) => [...read(f).matchAll(/["'(\s]http:\/\/(?!localhost|127\.0\.0\.1|www\.w3\.org|schemas\.|secure-bank|bank-|bit\.ly|t\.me)[^\s"')]+/g)].map((m) => `${f}: ${m[0].trim().slice(0, 60)}`));
check(insecure.length === 0, "no insecure http:// resources (outside demo scam samples / XML namespaces)", insecure.slice(0, 3).join(" | "));
const blankBad = allFiles.filter((f) => /\.(js|html)$/.test(f)).flatMap((f) => [...read(f).matchAll(/<a\b[^>]*target="_blank"[^>]*>/g)].filter((m) => !/rel="[^"]*noopener/.test(m[0])).map(() => f));
check(blankBad.length === 0, 'every target="_blank" link has rel="noopener"', [...new Set(blankBad)].join(", "));

console.log("\n5. Service worker");
const sw = read("sw.js");
const assets = [...sw.matchAll(/"\.\/([^"]*)"/g)].map((m) => m[1]).filter(Boolean);
const missing = assets.filter((a) => !existsSync(join(ROOT, a)));
check(missing.length === 0, "every cached asset exists on disk", missing.join(", "));
const notCached = jsFiles.map((f) => relative(".", f)).filter((f) => !assets.includes(f));
check(notCached.length === 0, "every js/ module is in the offline cache list", notCached.join(", "));
check(/ALLOWED\.has/.test(sw) && /res\.type === "basic"/.test(sw), "service worker only caches allow-listed same-origin basic responses");

console.log("\n6. Translations");
try {
  const { translations } = await import("../js/i18n.js");
  const ar = Object.keys(translations.ar), en = Object.keys(translations.en);
  const d = [...ar.filter((k) => !en.includes(k)), ...en.filter((k) => !ar.includes(k))];
  check(d.length === 0, `AR / EN key parity (${ar.length}/${en.length})`, d.slice(0, 5).join(", "));
} catch (e) { check(false, "i18n import", String(e.message)); }

console.log("\n7. Project hygiene");
["LICENSE", "SECURITY.md", "README.md", ".github/workflows/deploy.yml", ".github/workflows/security.yml", ".github/dependabot.yml", ".well-known/security.txt"].forEach((f) => check(existsSync(join(ROOT, f)), `${f} exists`));

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
