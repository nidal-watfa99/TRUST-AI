/**
 * TRUST AI v2 — Global Fraud Database (client-side)
 * Sources: curated public warnings + optional live feeds (no secret keys).
 * Never presents incomplete coverage as "complete". Always shows source + date.
 */

import {
  escapeHtml,
  sanitizeText,
  isSafeUrl,
  rateLimit,
  safeJsonParse,
  securityLog,
  deepFreeze,
  isValidHostname,
  safeFetchText,
  storageGetJSON,
  storageSetJSON,
} from "./security.js";

/**
 * Feed-poisoning guard: a compromised/hostile feed must not be able to brand
 * well-known legitimate services as "phishing" (denial-of-trust). These apex
 * domains (and their subdomains) are never ingested from live feeds.
 */
const PROTECTED_APEX = new Set([
  "google.com", "gmail.com", "youtube.com", "microsoft.com", "live.com", "outlook.com", "office.com",
  "apple.com", "icloud.com", "amazon.com", "facebook.com", "instagram.com", "whatsapp.com", "meta.com",
  "x.com", "twitter.com", "telegram.org", "t.me", "linkedin.com", "github.com", "gitlab.com", "wikipedia.org",
  "paypal.com", "visa.com", "mastercard.com", "who.int", "un.org", "gov.sy", "gov.uk", "usa.gov",
]);
function isProtectedHost(host) {
  const h = String(host || "").toLowerCase();
  for (const apex of PROTECTED_APEX) if (h === apex || h.endsWith("." + apex)) return true;
  return false;
}
/** A feed host is ingestible only if it is a syntactically valid, non-protected hostname. */
function acceptFeedHost(host) {
  return isValidHostname(host) && !isProtectedHost(host);
}

const MAX_LOCAL_BYTES = 4_500_000;
const isStr = (v, n = 300) => typeof v === "string" && v.length <= n;
/** Drop malformed / tampered rows that could have been injected via localStorage. */
function cleanDbShape(data) {
  const entities = (Array.isArray(data.entities) ? data.entities : []).filter((e) => e && typeof e === "object" && isStr(e.id, 80) && Array.isArray(e.names) && e.names.every((n) => isStr(n, 200)));
  const domains = (Array.isArray(data.domains) ? data.domains : []).filter((d) => d && typeof d === "object" && isStr(d.domain, 253) && isValidHostname(d.domain));
  const phones = (Array.isArray(data.phones) ? data.phones : []).filter((p) => p && typeof p === "object");
  return { entities, domains, phones };
}

const DB_KEY = "trustai_fraud_db_v2";
const META_KEY = "trustai_fraud_meta_v2";

/** Seed: publicly documented warnings / patterns (not exhaustive). */
const SEED_ENTITIES = deepFreeze([
  {
    id: "seed-qnet-mlm",
    names: ["QNet", "Quest Net", "QuestNet", "Q-Net", "كويست نيت", "كيو نت"],
    type: "mlm_scheme",
    countries: ["global", "sy", "lb", "iq", "jo", "ae", "sa", "eg", "tr"],
    risk: "high",
    summary_ar: "كيان مرتبط بنموذج تسويق متعدد المستويات (MLM) أثار شكاوى وتحذيرات في عدة دول. يجب التمييز بين الكيانات المتشابهة في الاسم وعدم الاعتماد على الاسم وحده.",
    summary_en: "Entity associated with multi-level marketing (MLM) model that has drawn complaints and warnings in multiple countries. Distinguish similarly named entities; do not judge by name alone.",
    sources: [
      { title: "Public complaints & regulatory attention (various)", url: null, date: "2020-2024", kind: "public_reports" },
    ],
    aliases: ["QNet Ltd", "Quest Net"],
    tags: ["mlm", "investment_complaints", "middle_east"],
    updated: "2026-01-01",
    evidence_strength: "medium",
  },
  {
    id: "seed-fca-clone-example",
    names: ["Clone firm warnings (FCA pattern)"],
    type: "clone_firm",
    countries: ["gb", "global"],
    risk: "critical",
    summary_ar: "نمط شائع: جهات تنتحل أسماء شركات مرخصة. راجع دائماً سجل هيئة السلوك المالي البريطانية (FCA) قبل التعامل.",
    summary_en: "Common pattern: entities impersonating licensed firms. Always check the FCA register before engaging.",
    sources: [
      { title: "FCA Warning List", url: "https://www.fca.org.uk/consumers/warning-list-unauthorised-firms", date: "ongoing", kind: "regulator" },
    ],
    aliases: [],
    tags: ["clone", "regulator", "uk"],
    updated: "2026-01-01",
    evidence_strength: "high",
  },
  {
    id: "seed-crypto-pig-butchering",
    names: ["Pig butchering", "Romance + crypto investment", "ذبح الخنزير", "احتيال عاطفي استثماري"],
    type: "romance_crypto",
    countries: ["global"],
    risk: "critical",
    summary_ar: "نمط احتيال يجمع بين علاقة عاطفية وهمية ثم دفع نحو منصات تداول وهمية. خسائر كبيرة موثقة عالمياً.",
    summary_en: "Scam pattern combining fake romance with pressure toward fraudulent trading platforms. Large documented losses worldwide.",
    sources: [
      { title: "FBI / IC3 public advisories (pattern)", url: "https://www.ic3.gov/", date: "ongoing", kind: "law_enforcement" },
    ],
    aliases: [],
    tags: ["crypto", "romance", "investment"],
    updated: "2026-01-01",
    evidence_strength: "high",
  },
  {
    id: "seed-fake-delivery",
    names: ["Fake delivery SMS", "رسالة توصيل وهمية", "طردك في الجمارك"],
    type: "smishing",
    countries: ["global", "sy", "lb", "iq", "jo", "eg", "sa", "ae"],
    risk: "high",
    summary_ar: "رسائل تدّعي وجود طرد أو غرامة جمركية وتطلب فتح رابط أو دفع رسوم. غالباً تصيّد.",
    summary_en: "Messages claiming a package or customs fee, pushing a link or payment. Usually phishing.",
    sources: [
      { title: "Common smishing pattern (public)", url: null, date: "ongoing", kind: "pattern" },
    ],
    aliases: [],
    tags: ["smishing", "delivery", "customs"],
    updated: "2026-01-01",
    evidence_strength: "high",
  },
  {
    id: "seed-bank-impersonation-ar",
    names: ["انتحال البنوك", "Bank impersonation calls", "خدمة العملاء البنكية الوهمية"],
    type: "vishing",
    countries: ["sy", "lb", "iq", "jo", "eg", "sa", "ae", "global"],
    risk: "critical",
    summary_ar: "مكالمات تدّعي أنها من البنك وتطلب رموز OTP أو تحويل أموال عاجل. لا تُفصح عن رموز أبداً.",
    summary_en: "Calls claiming to be from the bank requesting OTP codes or urgent transfers. Never share codes.",
    sources: [
      { title: "Widespread public advisories", url: null, date: "ongoing", kind: "pattern" },
    ],
    aliases: [],
    tags: ["vishing", "bank", "otp"],
    updated: "2026-01-01",
    evidence_strength: "high",
  },
]);

/** Public feeds we may attempt (no API key required for basic access). */
const LIVE_FEEDS = [
  {
    id: "phishunt_feed",
    name: "Phishunt phishing domains (GitHub mirror)",
    url: "https://raw.githubusercontent.com/0xDanielLopez/phishunt-feed/main/feed.txt",
    type: "get_text",
    enabled: true,
    parse: "domain_lines",
  },
  {
    id: "gacs_scams",
    name: "GACS public scam list",
    url: "https://gacs.app/api/public/scams.json?limit=100",
    type: "get_json",
    enabled: true,
    parse: "gacs",
  },
];

function loadLocal() {
  try {
    const stored = storageGetJSON(DB_KEY, { fallback: null, maxBytes: MAX_LOCAL_BYTES });
    if (!stored || !Array.isArray(stored.entities)) {
      return { entities: [...SEED_ENTITIES], domains: [], phones: [] };
    }
    const data = cleanDbShape(stored);
    // Merge seed if missing
    const ids = new Set(data.entities.map((e) => e.id));
    for (const s of SEED_ENTITIES) {
      if (!ids.has(s.id)) data.entities.push(s);
    }
    data.domains = Array.isArray(data.domains) ? data.domains : [];
    data.phones = Array.isArray(data.phones) ? data.phones : [];
    return data;
  } catch {
    return { entities: [...SEED_ENTITIES], domains: [], phones: [] };
  }
}

function saveLocal(data) {
  try {
    const ok = storageSetJSON(DB_KEY, {
      entities: data.entities.slice(0, 5000),
      domains: (data.domains || []).slice(0, 20000),
      phones: (data.phones || []).slice(0, 5000),
    }, { maxBytes: MAX_LOCAL_BYTES });
    if (!ok) securityLog("fraud_db_save_skipped_size");
  } catch (e) {
    securityLog("fraud_db_save_fail", { err: String(e) });
  }
}

function loadMeta() {
  try {
    const m = storageGetJSON(META_KEY, { fallback: null, maxBytes: 200_000 });
    return m && typeof m === "object" && m.sources && typeof m.sources === "object" ? m : { lastUpdate: null, sources: {} };
  } catch {
    return { lastUpdate: null, sources: {} };
  }
}

function saveMeta(meta) {
  try {
    localStorage.setItem(META_KEY, JSON.stringify(meta));
  } catch {
    /* ignore */
  }
}

/** Search entities by name / alias (Arabic + English tolerant) */
export function searchEntities(query, opts = {}) {
  const q = sanitizeText(query, 200).toLowerCase().trim();
  if (!q || q.length < 2) return [];
  const data = loadLocal();
  const country = opts.country || null;
  const results = [];
  for (const e of data.entities) {
    const hay = [...(e.names || []), ...(e.aliases || []), e.id]
      .join(" ")
      .toLowerCase();
    if (!hay.includes(q) && !q.split(/\s+/).every((w) => hay.includes(w))) continue;
    if (country && e.countries && !e.countries.includes(country) && !e.countries.includes("global")) continue;
    results.push(e);
  }
  return results.slice(0, 50);
}

export function getEntityById(id) {
  const data = loadLocal();
  return data.entities.find((e) => e.id === id) || null;
}

export function listEntities(filter = {}) {
  const data = loadLocal();
  let list = data.entities;
  if (filter.country) {
    list = list.filter(
      (e) =>
        (e.countries || []).includes(filter.country) ||
        (e.countries || []).includes("global")
    );
  }
  if (filter.tag) {
    list = list.filter((e) => (e.tags || []).includes(filter.tag));
  }
  if (filter.risk) {
    list = list.filter((e) => e.risk === filter.risk);
  }
  return list;
}

export function getMeta() {
  return loadMeta();
}

export function getStats() {
  const data = loadLocal();
  const meta = loadMeta();
  return {
    entities: data.entities.length,
    domains: (data.domains || []).length,
    phones: (data.phones || []).length,
    lastUpdate: meta.lastUpdate,
    sources: meta.sources || {},
  };
}

/** Check if a domain appears in local malicious domain list */
export function checkDomain(domain) {
  if (!domain) return null;
  const d = String(domain).toLowerCase().replace(/^www\./, "");
  const data = loadLocal();
  const hit = (data.domains || []).find((x) => x.domain === d || d.endsWith("." + x.domain));
  return hit || null;
}

/**
 * Live update from public feeds.
 * Returns status object for UI: { status, message, details }
 */
export async function updateDatabase(onProgress) {
  const rl = rateLimit("fraud_db_update", 3, 120000);
  if (!rl.allowed) {
    return {
      status: "rate_limited",
      message_ar: "تم تجاوز حد التحديث. حاول لاحقاً.",
      message_en: "Update rate limit exceeded. Try again later.",
      details: [],
    };
  }

  const meta = loadMeta();
  const data = loadLocal();
  const details = [];
  let anyOk = false;
  let anyFail = false;

  const report = (msg) => {
    if (typeof onProgress === "function") onProgress(msg);
  };

  report("starting");

  for (const feed of LIVE_FEEDS) {
    if (!feed.enabled) continue;
    report(feed.id);
    try {
      // Credential-less, referrer-less, time- and size-bounded fetch.
      const body = await safeFetchText(feed.url, {
        method: "GET",
        headers: { Accept: feed.type === "get_text" ? "text/plain" : "application/json" },
        timeoutMs: 20000,
        maxBytes: 3_000_000,
      });

      let added = 0;
      const existing = new Set((data.domains || []).map((d) => d.domain));

      if (feed.parse === "domain_lines") {
        const lines = body.split(/\r?\n/).map((l) => l.trim()).filter(Boolean);
        for (const line of lines.slice(0, 800)) {
          let host = line.toLowerCase().replace(/^www\./, "");
          // strip accidental scheme
          try {
            if (host.includes("://")) host = new URL(host).hostname;
          } catch { /* keep */ }
          host = host.split(/[\/?#:]/)[0]; // drop path/query/port when no scheme was present
          host = host.replace(/[^a-z0-9.-]/g, "");
          if (!acceptFeedHost(host) || existing.has(host)) continue;
          data.domains.push({
            domain: host,
            source: feed.id,
            threat: "phishing",
            date: new Date().toISOString().slice(0, 10),
            url: null,
          });
          existing.add(host);
          added++;
        }
      } else if (feed.parse === "gacs") {
        const json = safeJsonParse(body, 5_000_000);
        const list = Array.isArray(json) ? json : json?.scams || json?.data || [];
        for (const item of list.slice(0, 200)) {
          if (!item || typeof item !== "object") continue; // ignore malformed entries
          const host = String(item.domain || item.host || item.url || "")
            .toLowerCase()
            .replace(/^www\./, "");
          let domain = host;
          try {
            if (host.includes("://")) domain = new URL(host).hostname.replace(/^www\./, "");
          } catch { /* keep */ }
          domain = String(domain).replace(/[^a-z0-9.-]/g, "");
          if (domain && acceptFeedHost(domain) && !existing.has(domain)) {
            data.domains.push({
              domain,
              source: "gacs",
              threat: sanitizeText(String(item.category || item.type || "scam"), 40),
              date: sanitizeText(String(item.date || item.created || ""), 30) || null,
              url: isSafeUrl(item.url) ? item.url : null,
            });
            existing.add(domain);
            added++;
          }
          // Also add as entity if name present
          const name = sanitizeText(String(item.name || item.title || ""), 120).trim();
          if (name && name.length >= 3) {
            const id = "gacs-" + (item.id || domain || name).toString().slice(0, 40);
            if (!data.entities.some((e) => e.id === id)) {
              data.entities.push({
                id,
                names: [name],
                type: sanitizeText(String(item.category || "scam"), 40),
                countries: ["global"],
                risk: "high",
                summary_ar: `سجل من مصدر GACS العام: ${name}`,
                summary_en: `Entry from public GACS source: ${name}`,
                sources: [{ title: "GACS public feed", url: "https://gacs.app", date: item.date || null, kind: "public_db" }],
                aliases: domain ? [domain] : [],
                tags: ["gacs", "live"],
                updated: new Date().toISOString().slice(0, 10),
                evidence_strength: "medium",
              });
            }
          }
        }
      }

      meta.sources[feed.id] = {
        ok: true,
        at: new Date().toISOString(),
        added,
        error: null,
      };
      details.push({ id: feed.id, ok: true, added });
      anyOk = true;
      securityLog("feed_ok", { id: feed.id, added });
    } catch (err) {
      meta.sources[feed.id] = {
        ok: false,
        at: new Date().toISOString(),
        added: 0,
        error: String(err.message || err).slice(0, 120),
      };
      details.push({ id: feed.id, ok: false, error: String(err.message || err) });
      anyFail = true;
      securityLog("feed_fail", { id: feed.id, err: String(err) });
    }
  }

  // Always keep seed entities
  const ids = new Set(data.entities.map((e) => e.id));
  for (const s of SEED_ENTITIES) {
    if (!ids.has(s.id)) data.entities.push(s);
  }

  saveLocal(data);
  meta.lastUpdate = new Date().toISOString();
  saveMeta(meta);

  let status = "success";
  if (anyOk && anyFail) status = "partial";
  if (!anyOk && anyFail) status = "failed";
  if (!anyOk && !anyFail) status = "no_feeds";

  return {
    status,
    message_ar:
      status === "success"
        ? "تم التحديث بنجاح من المصادر المتاحة."
        : status === "partial"
          ? "تحديث جزئي: بعض المصادر نجحت وبعضها فشل."
          : status === "failed"
            ? "تعذر الاتصال بالمصادر الخارجية."
            : "لا توجد مصادر مفعّلة.",
    message_en:
      status === "success"
        ? "Updated successfully from available sources."
        : status === "partial"
          ? "Partial update: some sources succeeded, some failed."
          : status === "failed"
            ? "Could not reach external sources."
            : "No feeds enabled.",
    details,
    stats: getStats(),
  };
}

/** Export for UI binding */
export function getSeedCount() {
  return SEED_ENTITIES.length;
}
