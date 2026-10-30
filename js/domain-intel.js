/**
 * TRUST AI — Domain intelligence (offline-first)
 *
 *  1) analyzeDomain(host)  — lookalike / brand-impersonation detection that works fully offline:
 *       · punycode decoding + confusable-character "skeleton" (Cyrillic/Greek/digits → Latin)
 *       · brand-in-subdomain tricks  (paypal.com.secure-login.xyz)
 *       · typos (paypall.com), combo-squatting (paypal-secure.com), same name on an abused TLD
 *       · official-domain allow-list so real sites (support.apple.com, amazon.de) are NOT flagged
 *  2) fetchDomainAge(domain) — OPTIONAL, opt-in network lookup of the registration date (RDAP).
 *       Off by default: it sends the domain name (only) to a third party.
 *
 * Honest limits: a name check cannot prove a site is safe, only that it imitates a known brand.
 */

// ── Brands: label → official registered domains (allow-list) ─────────────────
export const BRAND_DOMAINS = {
  paypal: ["paypal.com", "paypal.me", "paypal.in", "paypal.de", "paypal.fr", "paypal.it", "paypal.es", "paypal.co.uk"],
  apple: ["apple.com", "icloud.com", "apple.cn", "apple.news"],
  google: ["google.com", "gmail.com", "youtube.com", "goo.gl", "google.co.uk", "google.de", "google.fr", "google.ae", "google.com.sa", "google.com.eg"],
  microsoft: ["microsoft.com", "live.com", "office.com", "outlook.com", "windows.com", "xbox.com", "bing.com", "skype.com", "microsoftonline.com", "office365.com"],
  amazon: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.fr", "amazon.it", "amazon.es", "amazon.ae", "amazon.sa", "amazon.eg", "amazon.in", "amazon.co.jp", "amazon.ca", "amazon.com.au", "amazon.com.tr", "amazonaws.com", "aws.amazon.com"],
  facebook: ["facebook.com", "fb.com", "fb.me", "messenger.com", "meta.com"],
  instagram: ["instagram.com"],
  whatsapp: ["whatsapp.com", "whatsapp.net", "wa.me"],
  telegram: ["telegram.org", "telegram.me", "t.me"],
  netflix: ["netflix.com", "nflxvideo.net"],
  spotify: ["spotify.com", "scdn.co"],
  twitter: ["twitter.com", "x.com", "t.co"],
  tiktok: ["tiktok.com", "tiktokv.com"],
  linkedin: ["linkedin.com"],
  discord: ["discord.com", "discord.gg", "discordapp.com"],
  steam: ["steampowered.com", "steamcommunity.com"],
  binance: ["binance.com", "binance.us", "binance.org"],
  coinbase: ["coinbase.com"],
  kraken: ["kraken.com"],
  kucoin: ["kucoin.com"],
  bybit: ["bybit.com"],
  okx: ["okx.com"],
  revolut: ["revolut.com"],
  wise: ["wise.com"],
  stripe: ["stripe.com"],
  visa: ["visa.com"],
  mastercard: ["mastercard.com"],
  westernunion: ["westernunion.com"],
  moneygram: ["moneygram.com"],
  chase: ["chase.com"],
  wellsfargo: ["wellsfargo.com"],
  hsbc: ["hsbc.com", "hsbc.co.uk"],
  barclays: ["barclays.co.uk", "barclays.com"],
  citibank: ["citibank.com", "citi.com"],
  dhl: ["dhl.com", "dhl.de", "dhl.fr", "dhl.co.uk"],
  fedex: ["fedex.com"],
  ups: ["ups.com"],
  usps: ["usps.com"],
  aramex: ["aramex.com"],
  royalmail: ["royalmail.com"],
};

// Brand names that are also everyday words: only the unmistakable tricks (look-alike glyphs) are checked for them.
const AMBIGUOUS = new Set(["ups", "wise", "chase", "steam", "visa"]);

// TLDs that are heavily abused for throw-away phishing sites.
const ABUSED_TLDS = new Set(["tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "icu", "buzz", "cyou", "cfd", "sbs", "rest", "monster", "link", "work", "support", "zip", "mov", "live", "site", "online", "shop", "store", "vip", "cc", "ws"]);

// Words scammers append to a brand (paypal-SECURE, binance-SUPPORT…).
const SCAM_WORDS = ["secure", "security", "login", "signin", "verify", "verification", "account", "support", "help", "service", "services", "update", "wallet", "claim", "bonus", "official", "customer", "care", "refund", "billing", "payment", "pay", "recover", "recovery", "unlock", "alert", "id", "web", "online", "app", "center", "team"];

const MULTI_TLD = /\.(co|com|org|net|gov|edu|ac)\.[a-z]{2}$/i;

// ── Punycode (RFC 3492) decoder — browsers don't expose one ──────────────────
function adapt(delta, numPoints, first) {
  delta = first ? Math.floor(delta / 700) : delta >> 1;
  delta += Math.floor(delta / numPoints);
  let k = 0;
  while (delta > 455) { delta = Math.floor(delta / 35); k += 36; }
  return Math.floor(k + (36 * delta) / (delta + 38));
}

export function punyDecode(input) {
  const out = [];
  let i = 0, n = 128, bias = 72;
  let basic = input.lastIndexOf("-");
  if (basic < 0) basic = 0;
  for (let j = 0; j < basic; j++) {
    if (input.charCodeAt(j) >= 0x80) throw new Error("bad punycode");
    out.push(input.charCodeAt(j));
  }
  for (let idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
    const oldi = i;
    let w = 1;
    for (let k = 36; ; k += 36) {
      if (idx >= input.length) throw new Error("bad punycode");
      const cp = input.charCodeAt(idx++);
      const digit = cp - 48 < 10 ? cp - 22 : cp - 65 < 26 ? cp - 65 : cp - 97 < 26 ? cp - 97 : 36;
      if (digit >= 36) throw new Error("bad punycode");
      i += digit * w;
      const t = k <= bias ? 1 : k >= bias + 26 ? 26 : k - bias;
      if (digit < t) break;
      w *= 36 - t;
    }
    const len = out.length + 1;
    bias = adapt(i - oldi, len, oldi === 0);
    n += Math.floor(i / len);
    i %= len;
    out.splice(i++, 0, n);
  }
  return String.fromCodePoint(...out);
}

export function toUnicodeHost(host) {
  return String(host).split(".").map((l) => {
    if (/^xn--/i.test(l)) { try { return punyDecode(l.slice(4).toLowerCase()); } catch (_) { return l; } }
    return l;
  }).join(".");
}

// ── Confusable characters → Latin skeleton ───────────────────────────────────
const CONFUSABLE = {
  "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "һ": "h", "к": "k", "м": "m", "т": "t", "н": "h", "в": "b", "ԛ": "q", "ԝ": "w",
  "α": "a", "ε": "e", "ο": "o", "ρ": "p", "ν": "v", "ι": "i", "κ": "k", "τ": "t", "υ": "u", "χ": "x", "β": "b", "η": "n",
  "ɡ": "g", "ɑ": "a", "ɩ": "i", "ℓ": "l", "ǀ": "l", "І": "i", "Ι": "i", "Ο": "o", "Α": "a", "Ε": "e", "Ρ": "p", "С": "c", "Т": "t", "Х": "x", "Ѕ": "s", "Ј": "j", "Н": "h", "К": "k", "М": "m", "В": "b", "А": "a", "О": "o", "Р": "p",
  "0": "o", "5": "s", "3": "e", "$": "s", "@": "a",
};

/** Variants of a label with look-alike glyphs mapped to Latin ("1" may be l OR i; "rn"→m, "vv"→w). */
export function skeletons(label) {
  const base = [...String(label).toLowerCase().normalize("NFKD").replace(/[\u0300-\u036f]/g, "")].map((ch) => CONFUSABLE[ch] ?? ch).join("");
  const set = new Set();
  for (const one of ["l", "i"]) {
    const v = base.replace(/1/g, one).replace(/\|/g, "l");
    set.add(v);
    set.add(v.replace(/rn/g, "m").replace(/vv/g, "w").replace(/cl/g, "d"));
  }
  return [...set];
}

export function editDistance(a, b, max = 2) {
  if (Math.abs(a.length - b.length) > max) return max + 1;
  let prev = Array.from({ length: b.length + 1 }, (_, i) => i);
  for (let i = 1; i <= a.length; i++) {
    const cur = [i];
    let rowMin = i;
    for (let j = 1; j <= b.length; j++) {
      cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] === b[j - 1] ? 0 : 1));
      if (cur[j] < rowMin) rowMin = cur[j];
    }
    if (rowMin > max) return max + 1;
    prev = cur;
  }
  return prev[b.length];
}

export function registeredDomain(host) {
  const h = String(host).toLowerCase().replace(/\.$/, "");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return h;
  const parts = h.split(".");
  const n = MULTI_TLD.test(h) ? 3 : 2;
  return parts.slice(-n).join(".");
}

const OFFICIAL = new Map();
for (const [brand, doms] of Object.entries(BRAND_DOMAINS)) for (const d of doms) OFFICIAL.set(d, brand);

function officialBrandOf(host, registered) {
  if (OFFICIAL.has(registered)) return OFFICIAL.get(registered);
  for (const [d, b] of OFFICIAL) if (host === d || host.endsWith("." + d)) return b;
  return null;
}

function labelOf(reg) { return reg.split(".")[0]; }
function tldOf(reg) { return reg.split(".").slice(1).join("."); }

/**
 * Analyse a hostname. Returns:
 *  { host, registered, official: brand|null, findings: [{kind, brand, weight, confidence}], decoded }
 * kind: "homoglyph" | "typo" | "combo" | "subdomain" | "other_tld"
 */
export function analyzeDomain(hostOrUrl) {
  let host = String(hostOrUrl || "").trim().toLowerCase();
  try { host = new URL(/^[a-z]+:\/\//.test(host) ? host : "https://" + host).hostname; } catch (_) {}
  host = host.replace(/^www\./, "").replace(/\.$/, "");
  const registered = registeredDomain(host);
  const out = { host, registered, official: null, findings: [], decoded: toUnicodeHost(host) };
  if (!host || /^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return out;

  const official = officialBrandOf(host, registered);
  if (official) { out.official = official; return out; }

  const decodedReg = registeredDomain(out.decoded);
  const label = labelOf(decodedReg);
  const tld = tldOf(registered);
  const sub = out.decoded.slice(0, Math.max(0, out.decoded.length - decodedReg.length)).replace(/\.$/, "");
  const labelSkels = skeletons(label);
  const tokens = label.split("-").filter(Boolean);
  const best = new Map(); // brand → strongest finding
  const add = (brand, kind, weight, confidence) => {
    const cur = best.get(brand);
    if (!cur || weight > cur.weight) best.set(brand, { kind, brand, weight, confidence });
  };

  for (const brand of Object.keys(BRAND_DOMAINS)) {
    // 1) brand shown in the sub-domain part while the real domain is someone else's
    if (sub && !AMBIGUOUS.has(brand) && sub.split(/[.\-]/).some((p) => p === brand || skeletons(p).includes(brand)) && (brand.length >= 4 || sub.split(".").includes(brand))) {
      add(brand, "subdomain", 10, "high");
    }
    // 2) look-alike glyphs: the label LOOKS like the brand but isn't (paypa1, rnicrosoft, раураl)
    if (label !== brand && labelSkels.includes(brand)) { add(brand, "homoglyph", 10, "high"); continue; }
    if (AMBIGUOUS.has(brand)) continue;
    // 3) hyphenated combo: paypal-secure, secure-binance-login
    if (tokens.length > 1 && tokens.some((tk) => tk === brand || skeletons(tk).includes(brand))) { add(brand, "combo", 8, "high"); continue; }
    // 4) glued combo: paypalsecure, binancesupport (brand + known scam word, nothing else)
    if (label.startsWith(brand) || label.endsWith(brand)) {
      const rest = label.startsWith(brand) ? label.slice(brand.length) : label.slice(0, -brand.length);
      if (rest && SCAM_WORDS.includes(rest)) { add(brand, "combo", 8, "high"); continue; }
    }
    // 5) one-letter typo of a longer brand (paypall, gooogle). Short names are skipped on purpose (too many real words).
    if (brand.length >= 6 && label !== brand && label.length >= 5 && labelSkels.some((sk) => editDistance(sk, brand, 1) <= 1)) { add(brand, "typo", 7, "medium"); continue; }
    // 6) the exact brand name on a throw-away TLD that is not the brand's (paypal.xyz)
    if (label === brand && ABUSED_TLDS.has(tld.split(".").pop())) add(brand, "other_tld", 8, "high");
  }
  out.findings = [...best.values()].sort((a, b) => b.weight - a.weight).slice(0, 2);
  return out;
}

// ── Optional: registration date via RDAP (opt-in, network) ───────────────────
const NETCHECK_KEY = "trustai_netcheck";
export function isNetCheckEnabled() {
  try { return localStorage.getItem(NETCHECK_KEY) === "1"; } catch (_) { return false; }
}
export function setNetCheckEnabled(on) {
  try { on ? localStorage.setItem(NETCHECK_KEY, "1") : localStorage.removeItem(NETCHECK_KEY); } catch (_) {}
}

const ageCache = new Map();

/** Resolves { ok:true, createdAt, ageDays } or { ok:false, reason }. Never throws. */
export async function fetchDomainAge(domain, { fetchImpl, timeoutMs = 6000 } = {}) {
  const d = String(domain || "").toLowerCase().replace(/\.$/, "");
  if (!/^(?:[a-z0-9-]{1,63}\.)+[a-z0-9-]{2,63}$/.test(d)) return { ok: false, reason: "invalid" };
  if (ageCache.has(d)) return ageCache.get(d);
  const f = fetchImpl || (typeof fetch === "function" ? fetch : null);
  if (!f) return { ok: false, reason: "unavailable" };
  let result;
  try {
    const res = await f(`https://rdap.org/domain/${encodeURIComponent(d)}`, {
      method: "GET",
      headers: { Accept: "application/rdap+json, application/json" },
      credentials: "omit",
      referrerPolicy: "no-referrer",
      signal: typeof AbortSignal !== "undefined" && AbortSignal.timeout ? AbortSignal.timeout(timeoutMs) : undefined,
    });
    if (!res.ok) { result = { ok: false, reason: res.status === 404 ? "not-found" : "http-" + res.status }; }
    else {
      const j = await res.json();
      const ev = (j.events || []).find((e) => /regist/i.test(String(e.eventAction)));
      const t = ev && Date.parse(ev.eventDate);
      result = Number.isFinite(t)
        ? { ok: true, createdAt: new Date(t).toISOString().slice(0, 10), ageDays: Math.max(0, Math.floor((Date.now() - t) / 86400000)) }
        : { ok: false, reason: "no-date" };
    }
  } catch (_) {
    result = { ok: false, reason: "network" };
  }
  if (result.ok) ageCache.set(d, result);
  return result;
}
