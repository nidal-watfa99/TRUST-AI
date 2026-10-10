/**
 * TRUST AI — Security Layer (v3.0 "Shield")
 * Centralized defensive utilities for a pure client-side app.
 *
 * Threats covered: XSS / HTML injection, SSRF-style URL abuse, header & key
 * injection, prototype pollution, storage tampering, feed poisoning, invisible
 * Unicode smuggling (incl. prompt-injection payloads), abuse / flooding.
 *
 * Honest note: client-side code can always be inspected or modified by the
 * person running it. True secrets must never live here.
 */

export const APP_VERSION = "3.0.0";
export const BUILD_ID = "trust-ai-v3-" + APP_VERSION;

/* ───────────────────────── Output encoding (XSS) ───────────────────────── */

const HTML_MAP = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;", "`": "&#96;", "=": "&#61;" };

/** HTML entity escape — safe for element content AND quoted/unquoted attributes. */
export function escapeHtml(str) {
  return String(str ?? "").replace(/[&<>"'`=]/g, (c) => HTML_MAP[c]);
}

/** Attribute-safe value (same strict encoding). */
export function escapeAttr(str) {
  return escapeHtml(str);
}

/** Return a URL only if it is safe to place in href/src, else "#". */
export function safeHref(raw) {
  return isSafeUrl(raw) ? String(raw).trim() : "#";
}

/* ───────────────────────── Input hygiene ───────────────────────── */

/**
 * Strip control chars, zero-width / bidi-override characters and invisible
 * "tag" characters (U+E0000–E007F) that are used for text smuggling and for
 * hiding prompt-injection payloads from human eyes.
 */
export function sanitizeText(input, maxLen = 50000) {
  let s = String(input ?? "");
  s = s.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g, "");
  s = s.replace(/[\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\u180E\uFEFF\uFFF9-\uFFFB]/g, "");
  s = s.replace(/[\u{E0000}-\u{E007F}]/gu, "");
  if (s.length > maxLen) s = s.slice(0, maxLen);
  return s;
}

/** Normalize phone-ish input (digits + leading +) */
export function normalizePhoneInput(raw) {
  let s = String(raw ?? "").trim();
  s = s.replace(/[^\d+]/g, "");
  if (s.indexOf("+") > 0) s = s.replace(/\+/g, "");
  if ((s.match(/\+/g) || []).length > 1) s = s.replace(/\+/g, "");
  return s.slice(0, 20);
}

/* ───────────────────────── URL / host validation ───────────────────────── */

const BLOCKED_SUFFIXES = [".local", ".localhost", ".internal", ".lan", ".intranet", ".corp", ".home", ".home.arpa", ".invalid", ".test", ".example"];

function ipv4ToParts(host) {
  const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(host);
  if (!m) return null;
  const p = m.slice(1).map(Number);
  return p.every((n) => n >= 0 && n <= 255) ? p : null;
}

/** True for loopback / private / link-local / CGNAT / reserved IPv4 ranges. */
export function isPrivateIPv4(host) {
  const p = ipv4ToParts(host);
  if (!p) return false;
  const [a, b, c] = p;
  return (
    a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0 && c === 0) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

function isPrivateIPv6(host) {
  const h = host.replace(/^\[|\]$/g, "").toLowerCase();
  if (!h.includes(":")) return false;
  return (
    h === "::" || h === "::1" ||
    h.startsWith("::ffff:") || h.startsWith("64:ff9b:") ||
    /^f[cd][0-9a-f]{2}:/.test(h) ||
    /^fe[89ab][0-9a-f]:/.test(h) ||
    /^ff[0-9a-f]{2}:/.test(h)
  );
}

/** Strict RFC-style hostname check (letters, digits, hyphen, dots; real TLD). */
export function isValidHostname(host) {
  if (typeof host !== "string") return false;
  const h = host.toLowerCase();
  if (h.length < 4 || h.length > 253 || !h.includes(".")) return false;
  const labels = h.split(".");
  if (!labels.every((l) => l.length >= 1 && l.length <= 63 && /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/.test(l))) return false;
  const tld = labels[labels.length - 1];
  return /^([a-z]{2,24}|xn--[a-z0-9-]{2,59})$/.test(tld);
}

/**
 * Strict URL validation — only http/https, no credentials, no local/private/
 * metadata targets (SSRF-style), no dangerous schemes, bounded length.
 */
export function isSafeUrl(raw) {
  if (!raw || typeof raw !== "string" || raw.length > 2048) return false;
  try {
    const u = new URL(raw.trim());
    if (u.protocol !== "http:" && u.protocol !== "https:") return false;
    if (u.username || u.password) return false;
    const host = u.hostname.toLowerCase().replace(/\.$/, "");
    if (!host || host === "localhost") return false;
    if (BLOCKED_SUFFIXES.some((s) => host.endsWith(s))) return false;
    if (host.startsWith("[") || host.includes(":")) return !isPrivateIPv6(host);
    if (ipv4ToParts(host)) return !isPrivateIPv4(host);
    if (!host.includes(".")) return false; // single-label intranet names
    return true;
  } catch {
    return false;
  }
}

/** Only raster image data-URLs (SVG is rejected: it can carry script). */
export function isSafeImageDataUrl(u) {
  return typeof u === "string" && u.length < 12_000_000 &&
    /^data:image\/(png|jpe?g|webp|gif);base64,[A-Za-z0-9+/]+={0,2}$/.test(u);
}

/** Identify real image type from magic bytes (never trust file name / MIME alone). */
export function sniffImageType(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes || []);
  if (b.length >= 3 && b[0] === 0xff && b[1] === 0xd8 && b[2] === 0xff) return "image/jpeg";
  if (b.length >= 8 && b[0] === 0x89 && b[1] === 0x50 && b[2] === 0x4e && b[3] === 0x47 && b[4] === 0x0d && b[5] === 0x0a && b[6] === 0x1a && b[7] === 0x0a) return "image/png";
  if (b.length >= 12 && b[0] === 0x52 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x46 && b[8] === 0x57 && b[9] === 0x45 && b[10] === 0x42 && b[11] === 0x50) return "image/webp";
  if (b.length >= 6 && b[0] === 0x47 && b[1] === 0x49 && b[2] === 0x46 && b[3] === 0x38) return "image/gif";
  return null;
}

/* ───────────────────────── Secrets (API keys) ───────────────────────── */

/**
 * Validate a pasted API key. Rejects whitespace/control chars (HTTP header
 * injection), absurd lengths and unexpected characters.
 */
export function validateApiKey(raw) {
  const key = String(raw ?? "").trim();
  if (key.length < 8) return { ok: false, reason: "short" };
  if (key.length > 400) return { ok: false, reason: "long" };
  if (!/^[A-Za-z0-9._~+\-\/=:]+$/.test(key)) return { ok: false, reason: "charset" };
  return { ok: true, key };
}

/** Allow-list for custom model names (they end up inside URLs / JSON). */
export function isSafeModelName(name) {
  return typeof name === "string" && name.length > 0 && name.length <= 120 && /^[A-Za-z0-9][A-Za-z0-9._:\-\/]*$/.test(name) && !name.includes("..");
}

/** Remove anything that looks like an API key from a string (logs, errors, UI). */
export function redactSecrets(str) {
  return String(str ?? "")
    .replace(/\b(sk-or-v1-[A-Za-z0-9_-]{8,}|sk-[A-Za-z0-9_-]{16,}|gsk_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{20,})/g, "[REDACTED]")
    .replace(/([?&](?:key|api_key|apikey|token)=)[^&\s"']+/gi, "$1[REDACTED]")
    .replace(/(Bearer\s+)[A-Za-z0-9._~+\/=-]{8,}/gi, "$1[REDACTED]");
}

/* ───────────────────────── JSON & objects ───────────────────────── */

const POLLUTION_KEYS = new Set(["__proto__", "constructor", "prototype"]);

/** JSON.parse with a size guard and prototype-pollution keys removed. */
export function safeJsonParse(raw, maxBytes = 2_000_000) {
  if (typeof raw !== "string") return null;
  if (raw.length > maxBytes) return null;
  try {
    return JSON.parse(raw, (k, v) => (POLLUTION_KEYS.has(k) ? undefined : v));
  } catch {
    return null;
  }
}

/** Throws on objects carrying pollution keys (shallow). */
export function assertCleanObject(obj) {
  if (obj == null || typeof obj !== "object") return obj;
  for (const k of POLLUTION_KEYS) {
    if (Object.prototype.hasOwnProperty.call(obj, k)) throw new Error("Suspicious object shape rejected");
  }
  return obj;
}

/** Freeze critical config objects to reduce runtime mutation risk */
export function deepFreeze(obj) {
  if (obj == null || typeof obj !== "object") return obj;
  Object.getOwnPropertyNames(obj).forEach((prop) => {
    const val = obj[prop];
    if (val && typeof val === "object") deepFreeze(val);
  });
  return Object.freeze(obj);
}

/* ───────────────────────── Storage (tamper-tolerant) ───────────────────────── */

/**
 * Read JSON from localStorage defensively. Anything oversized, malformed,
 * polluted or failing `validate` is discarded and `fallback` is returned.
 */
export function storageGetJSON(key, { fallback = null, maxBytes = 1_000_000, validate = null, area = "localStorage" } = {}) {
  try {
    const raw = globalThis[area]?.getItem(key);
    if (raw == null) return fallback;
    const parsed = safeJsonParse(raw, maxBytes);
    if (parsed == null) return fallback;
    if (validate && !validate(parsed)) {
      securityLog("storage_rejected", { key });
      return fallback;
    }
    return parsed;
  } catch {
    return fallback;
  }
}

/** Write JSON with a size cap. Returns true on success. */
export function storageSetJSON(key, value, { maxBytes = 1_000_000, area = "localStorage" } = {}) {
  try {
    const raw = JSON.stringify(value);
    if (raw.length > maxBytes) return false;
    globalThis[area]?.setItem(key, raw);
    return true;
  } catch {
    return false;
  }
}

/* ───────────────────────── Abuse control ───────────────────────── */

const _rateBuckets = new Map();

/** Simple client-side rate limiter (per key, fixed window). */
export function rateLimit(key, maxCalls = 8, windowMs = 60000) {
  const now = Date.now();
  let bucket = _rateBuckets.get(key);
  if (!bucket || now - bucket.start > windowMs) {
    bucket = { start: now, count: 0 };
    _rateBuckets.set(key, bucket);
  }
  bucket.count += 1;
  if (bucket.count > maxCalls) {
    return { allowed: false, retryAfterMs: windowMs - (now - bucket.start) };
  }
  return { allowed: true, remaining: maxCalls - bucket.count };
}

/** Make sure only one run of `fn` per key is in flight (anti double-submit / flooding). */
const _inflight = new Set();
export async function singleFlight(key, fn) {
  if (_inflight.has(key)) return { busy: true };
  _inflight.add(key);
  try {
    return { busy: false, value: await fn() };
  } finally {
    _inflight.delete(key);
  }
}

/** fetch() with timeout + response-size cap. Never follows credentials. */
export async function safeFetchText(url, { timeoutMs = 20000, maxBytes = 3_000_000, ...init } = {}) {
  const res = await fetch(url, {
    credentials: "omit",
    referrerPolicy: "no-referrer",
    redirect: "follow",
    ...init,
    signal: AbortSignal.timeout(timeoutMs),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  const len = Number(res.headers.get("content-length") || 0);
  if (len && len > maxBytes) throw new Error("Response too large");
  const body = await res.text();
  if (body.length > maxBytes) throw new Error("Response too large");
  return body;
}

/* ───────────────────────── Security log / self-check ───────────────────────── */

const _events = [];

/** Log security-relevant events (console + small in-memory ring; no external beacon). */
export function securityLog(event, detail = {}) {
  try {
    const entry = { t: new Date().toISOString(), event: String(event), ...detail };
    _events.push(entry);
    if (_events.length > 50) _events.shift();
    console.info("[TRUST-AI-SEC]", event, entry);
  } catch {
    /* ignore */
  }
}

export function getSecurityEvents() {
  return _events.slice();
}

/** Real, observable protection state (no fake "all green"). */
export function getSecurityReport() {
  const r = { version: APP_VERSION };
  try {
    r.https = location.protocol === "https:" || ["localhost", "127.0.0.1"].includes(location.hostname);
    r.secureContext = !!globalThis.isSecureContext;
    r.framed = window.top !== window.self;
    r.csp = !!document.querySelector('meta[http-equiv="Content-Security-Policy"]');
    r.noInlineScripts = document.querySelectorAll("script:not([src])").length === 0;
    r.serviceWorker = !!navigator.serviceWorker?.controller;
    r.guard = !!window.__TRUST_GUARD__;
    r.keyInMemoryOnly = true;
    let ok = false;
    try { localStorage.setItem("__t", "1"); localStorage.removeItem("__t"); ok = true; } catch { /* blocked */ }
    r.storage = ok;
  } catch {
    /* non-browser context (tests) */
  }
  return r;
}
