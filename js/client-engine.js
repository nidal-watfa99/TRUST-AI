/**
 * TRUST AI — Client engine (محرك العميل)
 * Accepts ANY input (link, name, news, message, image, text file) and builds a
 * full "event dossier": kind, event type, entities, warnings, 6-axis risk
 * dimensions, sentence arc and verification tools. Pure functions — no DOM —
 * so it runs offline and is unit-testable in Node.
 */
import { analyze, scoreToLevel, detectSensitivePaste, LEVELS } from "./risk-engine.js";
import { TYPE_SIGNALS, PATTERNS, WATCHLIST, BRANDS, HONORIFICS, PLAYBOOKS, TOOLS, W, SENSITIVE_LABEL, L } from "./client-data.js";

const clamp = (n, lo = 0, hi = 100) => Math.max(lo, Math.min(hi, Math.round(n)));
const uniq = (arr) => [...new Set(arr.map((x) => x.trim()).filter(Boolean))];
const countMatches = (text, re) => {
  const flags = re.flags.includes("g") ? re.flags : re.flags + "g";
  return (text.match(new RegExp(re.source, flags)) || []).length;
};

export const KINDS = ["url", "name", "news", "message", "image", "mixed"];

const URL_RE = /\b(?:https?:\/\/|www\.)[^\s<>"')\]،]+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|net|org|info|xyz|top|tk|ml|ga|cf|gq|ru|cn|io|co|me|ly|gl|cc|app|site|online|click|link|shop|live|biz|us|uk|sa|ae|eg|sy|iq|jo|lb|ps|tr|bit\.ly)(?:\/[^\s<>"')\]،]*)?/gi;
const EMAIL_RE = /[\w.+-]+@[\w-]+(?:\.[\w-]+)+/g;
const PHONE_RE = /(?:\+|00)\d{1,3}[\s-]?\d{2,4}[\s-]?\d{3,4}[\s-]?\d{2,4}|\b0\d{8,10}\b/g;
const AMOUNT_RE = /(?:[$€£]\s?\d[\d,.]*|\d[\d,.]*\s?(?:USD|EUR|GBP|دولار|يورو|ليرة|ريال|دينار|درهم|\$|€))/gi;
const CRYPTO_RE = /\b0x[a-fA-F0-9]{40}\b|\bbc1[a-z0-9]{25,60}\b|\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b|\bT[1-9A-HJ-NP-Za-km-z]{33}\b/g;
const HANDLE_RE = /(?<![\w@])@[A-Za-z0-9_]{3,}/g;
const TITLED_NAME_RE = /(?:السيد|السيدة|الدكتور|الدكتورة|المهندس|الأستاذ|الشيخ|الأمير|الأميرة|المدير|السفير|Mr\.?|Mrs\.?|Ms\.?|Dr\.?|Prof\.?|Barrister|Prince|General)\s+[\p{L}]+(?:\s[\p{L}]+){0,2}/giu;
const LATIN_NAME_RE = /\b[A-Z][a-z]{2,}(?:\s[A-Z][a-z]{2,}){1,2}\b/g;
const ORG_RE = /(?:شركة|مؤسسة|بنك|مصرف|وزارة|هيئة|منظمة|مجموعة)\s+[\p{L}]+(?:\s[\p{L}]+)?/gu;

/* ── Kind detection ────────────────────────────────────────────────────── */

export function detectKind(text, imageCount = 0, fileCount = 0) {
  const s = (text || "").trim();
  const hasMedia = imageCount > 0;
  if (!s && hasMedia) return "image";
  if (!s) return "message";
  const urls = s.match(URL_RE) || [];
  const words = s.split(/\s+/).filter(Boolean);
  let kind;
  if (urls.length && urls.join("").length >= s.replace(/\s/g, "").length * 0.8) kind = "url";
  else if (looksLikeName(s, words, urls)) kind = "name";
  else if (isNewsLike(s)) kind = "news";
  else kind = "message";
  if (hasMedia) return "mixed";
  return kind;
}

function looksLikeName(s, words, urls) {
  if (urls.length || words.length > 6 || s.length > 70 || /[.!?؟:@]/.test(s)) return false;
  if (words.length === 1) return true;
  if (WATCHLIST.some((w) => w.re.test(s)) || BRANDS.test(s)) return true;
  if (/[A-Za-z]/.test(s)) return words.every((w) => /^[A-Z][\p{L}.'-]*$/u.test(w) || /^(?:bin|al|el|de|van|von|ibn|abu)$/i.test(w));
  return words.length <= 4 && !/(?:^|\s)(?:في|من|على|هل|ما|أن|إن|هذا|هذه|كيف|لا|إلى|عن|مع)(?:\s|$)/.test(s);
}

function isNewsLike(s) {
  const newsWords = /عاجل|breaking|وكالة|مصادر|أعلنت|أعلن|صرّح|reuters|according to|sources? (?:say|said)|reportedly|ذكرت|تقارير|بيان|report(?:s|ed)?|announced|officials?/i;
  const asks = /otp|رمز|كلمة المرور|password|حوّل|تحويل|ادفع|pay|رسوم|fee|اضغط|click/i;
  return newsWords.test(s) && !asks.test(s) || (s.length > 140 && !asks.test(s) && /[.!?؟]/.test(s) && !/\b(?:you|your|عزيزي|حسابك)\b/i.test(s));
}

/* ── Entities ──────────────────────────────────────────────────────────── */

export function extractEntities(text) {
  const s = text || "";
  const urls = uniq((s.match(URL_RE) || []).map((u) => u.replace(/[.,;:!؟،]+$/, "")));
  const emails = uniq(s.match(EMAIL_RE) || []);
  const urlsNoEmailDomains = urls.filter((u) => !emails.some((e) => e.endsWith("@" + u) || e.includes(u)));
  const names = uniq([...(s.match(TITLED_NAME_RE) || []), ...(s.match(ORG_RE) || []), ...(s.match(LATIN_NAME_RE) || [])]).slice(0, 12);
  return {
    urls: urlsNoEmailDomains.slice(0, 10),
    emails: emails.slice(0, 10),
    phones: uniq(s.match(PHONE_RE) || []).slice(0, 10),
    amounts: uniq(s.match(AMOUNT_RE) || []).slice(0, 10),
    crypto: uniq(s.match(CRYPTO_RE) || []).slice(0, 6),
    handles: uniq(s.match(HANDLE_RE) || []).slice(0, 10),
    names,
  };
}

/* ── News / misinformation signals ─────────────────────────────────────── */

export function newsSignals(text) {
  const s = text || "";
  const hits = [];
  const add = (key, re, weight) => { const n = countMatches(s, re); if (n) hits.push({ key, count: n, weight: Math.min(weight * 1.5, weight + (n - 1) * 3) }); };
  add("sensational", PATTERNS.sensational, 14);
  add("anonymous", PATTERNS.anonymousSource, 16);
  add("shareBait", PATTERNS.shareBait, 18);
  add("absolute", PATTERNS.absolute, 8);
  add("conspiracy", PATTERNS.conspiracy, 16);
  const exclam = (s.match(/[!！]{2,}|[؟?]{3,}/g) || []).length;
  const letters = s.replace(/[^A-Za-z]/g, "");
  const capsRatio = letters.length > 12 ? (s.replace(/[^A-Z]/g, "").length / letters.length) : 0;
  if (exclam) hits.push({ key: "punct", count: exclam, weight: 8 });
  if (capsRatio > 0.6) hits.push({ key: "caps", count: 1, weight: 8 });
  const hasNamedSource = PATTERNS.namedSource.test(s) || PATTERNS.attribution.test(s);
  const hasDate = PATTERNS.dated.test(s);
  const hasUrl = (s.match(URL_RE) || []).length > 0;
  const words = s.split(/\s+/).filter(Boolean).length;
  const evidence = (hasNamedSource ? 40 : 0) + (hasDate ? 25 : 0) + (hasUrl ? 15 : 0) + (/\d/.test(s) ? 10 : 0) + (words > 40 ? 10 : 0);
  const risk = clamp(hits.reduce((a, h) => a + h.weight, 0) + (words > 12 && !hasNamedSource ? 10 : 0));
  return { hits, risk, evidence: clamp(evidence), hasNamedSource, hasDate, hasUrl, words };
}

/* ── Name signals ──────────────────────────────────────────────────────── */

export function nameSignals(text) {
  const s = text || "";
  const watch = WATCHLIST.filter((w) => w.re.test(s)).map((w) => w.label);
  const brand = (s.match(BRANDS) || [])[0] || null;
  const honorific = HONORIFICS.test(s);
  return { watch, brand, honorific };
}

/* ── Event classification ──────────────────────────────────────────────── */

export function classifyEvent(text, engine, news, nm = { watch: [] }) {
  const s = text || "";
  const scores = {};
  for (const [type, res] of Object.entries(TYPE_SIGNALS)) {
    scores[type] = res.reduce((n, re) => n + (re.test(s) ? 1 : 0), 0);
  }
  if (news.risk >= 24) scores.fake_news += 1;
  if (nm.watch?.length) scores.pyramid += 3;
  if (engine.categories?.link > 0 && scores.phishing > 0) scores.phishing += 1;
  const ranked = Object.entries(scores).filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]);
  const top = ranked[0];
  const secondary = ranked.slice(1, 3).filter(([, v]) => v >= 2).map(([k]) => k);
  const needed = engine.score >= 50 ? 1 : 2;
  const type = top && top[1] >= needed ? top[0] : "neutral";
  const confidence = type === "neutral" ? 0 : clamp(35 + top[1] * 15 + Math.min(20, engine.score / 5));
  return { type, secondary, confidence, scores };
}

/* ── Sentence arc ──────────────────────────────────────────────────────── */

export function sentenceArc(text) {
  const parts = (text || "").split(/(?<=[.!?؟۔])\s+|\n+/).map((x) => x.trim()).filter((x) => x.length >= 6).slice(0, 14);
  return parts.map((p, i) => {
    const r = analyze({ text: p });
    const score = r.score < 0 ? 0 : r.score;
    const top = Object.entries(r.categories || {}).sort((a, b) => b[1] - a[1])[0];
    return { i: i + 1, text: p, score, topCategory: top && top[1] > 0 ? top[0] : null };
  });
}

/* ── Dossier ───────────────────────────────────────────────────────────── */

export function buildDossier({ text = "", images = 0, files = 0, lang = "ar", forcedKind = "auto", visionOn = false, aiOn = false } = {}) {
  const raw = (text || "").trim();
  const kind = forcedKind && forcedKind !== "auto" ? forcedKind : detectKind(raw, images, files);
  const tr = W[lang] || W.ar;
  const ui = L[lang] || L.ar;

  const analysisText = kind === "url" && raw && !/^https?:\/\//i.test(raw) ? "https://" + raw : raw;
  let engine = analyze({ text: analysisText, hasImage: images > 0 });
  if (kind === "url" && engine.links?.length === 0 && analysisText !== raw) engine = analyze({ text: raw, hasImage: images > 0 });

  const entities = extractEntities(raw);
  const news = newsSignals(raw);
  const nm = nameSignals(raw);
  const event = classifyEvent(raw, engine, news, nm);
  const sentences = sentenceArc(raw);
  const sensHits = detectSensitivePaste(raw);

  /* Warnings */
  const warnings = [];
  const warn = (level, key, text) => warnings.push({ level, key, text });
  const cats = engine.categories || {};
  const pct = engine.categoryPercents || {};

  sensHits.forEach((h) => warn("critical", "sensitive_paste", tr.sensitive_paste.replace("{x}", SENSITIVE_LABEL[lang]?.[h] || h)));
  nm.watch.forEach((w) => warn("critical", "pyramid_name", tr.pyramid_name.replace("{x}", w)));
  if (PATTERNS.secrecy.test(raw)) warn("critical", "secrecy", tr.secrecy);
  if (cats.sensitive > 0) warn("critical", "sensitive", tr.sensitive);
  if (cats.money > 0) warn("high", "money", tr.money);
  if (cats.unrealistic > 0) warn("high", "unrealistic", tr.unrealistic);
  if (cats.link > 0) warn("high", "link", tr.link);
  const newsOnly = kind === "news" && !cats.money && !cats.sensitive && !cats.link;
  if (cats.impersonation > 0 && !newsOnly) warn("high", "impersonation", tr.impersonation);
  if (nm.brand && (kind === "name" || cats.impersonation > 0)) warn("medium", "brand_name", tr.brand_name.replace("{x}", nm.brand));
  if (nm.honorific) warn("medium", "honorific", tr.honorific);
  if (cats.urgency > 0) warn("medium", "urgency", tr.urgency);
  const nh = Object.fromEntries(news.hits.map((h) => [h.key, h]));
  if (nh.shareBait) warn("high", "shareBait", tr.shareBait);
  if (nh.anonymous) warn("medium", "anonymous", tr.anonymous);
  if (nh.sensational || nh.punct || nh.caps) warn("medium", "sensational", tr.sensational);
  if (nh.conspiracy) warn("medium", "conspiracy", tr.conspiracy);
  if (nh.absolute) warn("medium", "absolute", tr.absolute);
  if ((kind === "news" || event.type === "fake_news") && !news.hasNamedSource && !news.hasUrl) warn("medium", "noSource", tr.noSource);
  if (kind === "name") warn("info", "name_only", tr.name_only);
  if (kind === "url") warn("info", "url_only", tr.url_only);
  if (images > 0 && !visionOn) warn("info", "image_no_vision", tr.image_no_vision);
  warn("info", "offline_limit", tr.offline_limit);
  if (aiOn) warn("info", "ai_privacy", tr.ai_privacy);

  /* Score */
  const engineScore = engine.score < 0 ? 0 : engine.score;
  const nameRisk = nm.watch.length ? 78 : 0;
  const newsRisk = kind === "news" || event.type === "fake_news" || event.type === "health_hoax" || news.hits.length >= 2 ? Math.round(news.risk * 0.9) : 0;
  const TYPE_BASE = { phishing: 35, advance_fee: 45, pyramid: 50, crypto_invest: 40, impersonation: 35, job_scam: 35, romance: 30, parcel: 35, extortion: 55, charity: 30, health_hoax: 30, fake_news: 0, neutral: 0 };
  const matched = event.scores[event.type] || 0;
  const patternRisk = event.type === "neutral" ? 0 : clamp(TYPE_BASE[event.type] + Math.max(0, matched - 1) * 12 + (PATTERNS.secrecy.test(raw) ? 15 : 0), 0, 95);
  let score = Math.max(engineScore, newsRisk, nameRisk, patternRisk);
  const nothing = !raw && images === 0;
  const unknownInput = nothing || (score === 0 && (kind === "image" || kind === "name"));
  if (unknownInput && kind !== "name" && kind !== "image") score = -1;
  if (unknownInput) score = -1;
  const unverified = ["news", "name", "url", "image", "mixed"].includes(kind) || score < 25;

  const lvl = scoreToLevel(score);
  const level = score < 0 ? "unknown" : lvl.key;

  /* Dimensions: 6-axis risk 0-100 */
  const dims = {
    manipulation: clamp(Math.max(pct.socialEngineering || 0, (nh.sensational?.weight || 0) * 3.2 + (nh.punct ? 15 : 0) + (nh.caps ? 15 : 0) + (nh.conspiracy?.weight || 0) * 2 + (nh.shareBait?.weight || 0) * 2 + (PATTERNS.secrecy.test(raw) ? 40 : 0) + (PATTERNS.fear.test(raw) ? 12 : 0))),
    urgency: clamp(pct.urgency || 0),
    financial: clamp(Math.max(pct.money || 0, pct.sensitive || 0, pct.unrealistic || 0)),
    impersonation: clamp((pct.impersonation || 0) + (nm.brand ? 10 : 0) + (nm.watch.length ? 40 : 0)),
    link: clamp(pct.link || 0),
    unverifiability: raw ? clamp(100 - news.evidence) : 100,
  };

  /* Category shares for donut */
  const breakdown = [...(engine.transparent?.breakdown || [])];
  if (score > engineScore && score > 0) breakdown.push({ category: "pattern", points: score - engineScore, max: 100, percentOfMax: score, percentOfTotal: Math.round(((score - engineScore) / score) * 100) });

  /* Claims worth proving (offline): sentences with numbers/absolutes without attribution */
  const claimsOffline = sentences
    .filter((x) => (/\d/.test(x.text) || PATTERNS.absolute.test(x.text)) && !PATTERNS.attribution.test(x.text) && !PATTERNS.namedSource.test(x.text))
    .slice(0, 5)
    .map((x) => x.text.slice(0, 160));

  /* Queries */
  const queries = [];
  const q0 = raw.slice(0, 90).replace(/\s+/g, " ");
  if (kind === "name") queries.push(`"${q0}" ${lang === "ar" ? "احتيال" : "scam"}`, `"${q0}" ${lang === "ar" ? "تقييم شكاوى" : "reviews complaints"}`);
  else if (kind === "url") {
    const host = engine.links?.[0]?.host || q0;
    queries.push(`${host} ${lang === "ar" ? "احتيال" : "scam"}`, `${host} ${lang === "ar" ? "هل الموقع موثوق" : "is it legit"}`);
  } else if (q0) queries.push(`"${q0.slice(0, 60)}" ${lang === "ar" ? "حقيقة أم شائعة" : "fact check"}`);
  nm.watch.forEach((w) => queries.push(`${w} ${lang === "ar" ? "تحذير هيئة الرقابة" : "regulator warning"}`));
  entities.emails.slice(0, 1).forEach((e) => queries.push(`"${e}" ${lang === "ar" ? "احتيال" : "scam"}`));

  const q = encodeURIComponent(q0 || (engine.links?.[0]?.host || ""));
  const tools = TOOLS.filter((t) => t.kinds.includes(kind) || (images > 0 && t.kinds.includes("image")))
    .map((t) => ({ id: t.id, label: t[lang] || t.ar, url: t.url.replace("{q}", q) }));

  /* Actions */
  const pb = PLAYBOOKS[event.type] || PLAYBOOKS.neutral;
  const book = pb[lang] || pb.ar;
  const doList = [];
  const dontList = [];
  if (cats.link > 0 || kind === "url") dontList.push(lang === "ar" ? "لا تفتح الرابط ولا تدخل أي بيانات فيه" : "Don't open the link or enter any data");
  if (cats.money > 0 || event.type === "advance_fee" || event.type === "pyramid") dontList.push(lang === "ar" ? "لا تدفع رسوماً ولا تحوّل مالاً" : "Don't pay fees or transfer money");
  if (cats.sensitive > 0 || event.type === "phishing") dontList.push(lang === "ar" ? "لا تشارك كلمة مرور أو رمز تحقق أو بطاقة" : "Don't share a password, code or card");
  if (event.type === "pyramid") dontList.push(lang === "ar" ? "لا تستدن ولا تبع ممتلكاتك ولا تجنّد أقاربك" : "Don't borrow, sell assets or recruit relatives");
  if (nh.shareBait || event.type === "fake_news") dontList.push(lang === "ar" ? "لا تنشر الخبر قبل التحقق من مصدر مستقل" : "Don't share before verifying an independent source");
  if (kind === "name") dontList.push(lang === "ar" ? "لا تتهم شخصاً بدون دليل موثّق" : "Don't accuse a person without documented evidence");
  doList.push(...(ui.d_do_default || []));
  if (score >= 50) doList.unshift(lang === "ar" ? "احذف الرسالة وأبلغ المنصة أو الجهة المنتحَلة" : "Delete the message and report it to the platform or impersonated party");
  if (score >= 75) doList.unshift(lang === "ar" ? "إن دفعت أو شاركت بياناتك: اتصل ببنكك فوراً وغيّر كلمات المرور" : "If you already paid or shared data: call your bank now and change passwords");
  const finalDont = dontList.length ? dontList : [...ui.d_dont_default];

  return {
    kind, lang, raw, imageCount: images, fileCount: files,
    score, level, levelColor: score < 0 ? LEVELS.unknown.color : lvl.color,
    unverified, engine, entities, news, nameInfo: nm,
    event: { type: event.type, secondary: event.secondary, confidence: event.confidence, title: book.title, what: book.what, how: book.how, harm: book.harm },
    warnings: sortWarnings(warnings),
    dims, breakdown, sentences, claimsOffline, queries: uniq(queries), tools,
    actions: { do: uniq(doList), dont: uniq(finalDont) },
    ai: null, mode: "offline",
  };
}

const SEV_ORDER = { critical: 0, high: 1, medium: 2, info: 3 };
function sortWarnings(list) {
  const seen = new Set();
  return list.filter((w) => { const k = w.key + w.text; if (seen.has(k)) return false; seen.add(k); return true; })
    .sort((a, b) => SEV_ORDER[a.level] - SEV_ORDER[b.level]);
}

/* ── Merge AI result (model layer) into the dossier ────────────────────── */

export function mergeAI(d, ai) {
  if (!ai || ai.error) return { ...d, aiError: ai?.error || null };
  const out = { ...d, ai, mode: "hybrid" };
  const aiScore = typeof ai.score === "number" ? ai.score : -1;
  if (aiScore >= 0) {
    const s = Math.max(d.score < 0 ? 0 : d.score, aiScore);
    const lv = scoreToLevel(s);
    out.score = s; out.level = lv.key; out.levelColor = lv.color;
  }
  if (ai.dims) {
    out.dims = { ...d.dims };
    for (const k of Object.keys(out.dims)) if (typeof ai.dims[k] === "number") out.dims[k] = clamp(Math.max(out.dims[k], ai.dims[k]));
  }
  if (ai.eventType && PLAYBOOKS[ai.eventType]) {
    const pb = PLAYBOOKS[ai.eventType][d.lang] || PLAYBOOKS[ai.eventType].ar;
    out.event = { ...d.event, type: ai.eventType, title: pb.title, what: pb.what, how: pb.how, harm: pb.harm };
  } else if (ai.eventType === "benign" || ai.eventType === "unknown") {
    out.event = { ...d.event };
  }
  const extra = [];
  (ai.warnings || []).forEach((w) => {
    if (w && w.text) extra.push({ level: ["critical", "high", "medium", "info"].includes(w.level) ? w.level : "medium", key: "ai", text: String(w.text) });
  });
  out.warnings = sortWarnings([...d.warnings, ...extra]);
  const doExtra = (ai.actions || []).map(String);
  out.actions = { do: uniq([...doExtra, ...d.actions.do]).slice(0, 8), dont: d.actions.dont };
  if (ai.verify?.length) out.queries = uniq([...(ai.verify || []).map(String), ...d.queries]).slice(0, 8);
  if (aiScore >= 0 || d.level === "unknown") out.unverified = d.unverified && !(ai.confidence >= 70 && out.level !== "low");
  return out;
}

export function normalizeUniversal(p, provider, model) {
  if (!p || typeof p !== "object") return null;
  const num = (v, d = null) => (typeof v === "number" && isFinite(v) ? clamp(v) : d);
  const dimsIn = p.dims && typeof p.dims === "object" ? p.dims : {};
  const credIn = p.credibility && typeof p.credibility === "object" ? p.credibility : null;
  return {
    score: num(p.score, -1),
    level: p.level || null,
    confidence: num(p.confidence, 65),
    inputKind: p.input_kind || null,
    eventType: typeof p.event_type === "string" ? p.event_type : null,
    headline: String(p.headline || "").slice(0, 200),
    whatHappened: String(p.what_happened || p.summary || "").slice(0, 1500),
    howItWorks: Array.isArray(p.how_it_works) ? p.how_it_works.map(String).slice(0, 8) : [],
    claims: Array.isArray(p.claims) ? p.claims.filter((c) => c && c.claim).slice(0, 10).map((c) => ({ claim: String(c.claim).slice(0, 240), verdict: String(c.verdict || "unverifiable"), note: String(c.note || "").slice(0, 300) })) : [],
    entities: Array.isArray(p.entities) ? p.entities.filter((e) => e && e.name).slice(0, 12).map((e) => ({ name: String(e.name).slice(0, 100), type: String(e.type || "other"), note: String(e.note || "").slice(0, 240) })) : [],
    credibility: credIn ? Object.fromEntries(["source", "evidence", "consistency", "neutrality"].map((k) => [k, num(credIn[k], null)])) : null,
    dims: Object.fromEntries(["manipulation", "urgency", "financial", "impersonation", "link", "unverifiability"].map((k) => [k, num(dimsIn[k], null)]).filter(([, v]) => v !== null)),
    warnings: Array.isArray(p.warnings) ? p.warnings.map((w) => (typeof w === "string" ? { level: "medium", text: w } : w)).filter((w) => w && w.text).slice(0, 8) : [],
    indicators: Array.isArray(p.indicators) ? p.indicators.slice(0, 10) : [],
    actions: Array.isArray(p.actions) ? p.actions.slice(0, 8) : [],
    verify: Array.isArray(p.verify) ? p.verify.slice(0, 6) : [],
    extractedText: String(p.extracted_text || "").slice(0, 3000),
    limits: String(p.limits || "").slice(0, 500),
    mode: "ai", provider, model,
  };
}

/** Plain-text export of the dossier */
export function dossierToText(d, lang = "ar") {
  const ui = L[lang] || L.ar;
  const lines = [
    "TRUST AI — " + ui.title,
    "──────────────",
    `${ui.verdict}: ${d.score < 0 ? "—" : d.score + "/100"} · ${ui.levels[d.level] || d.level}`,
    `${ui.detectedKind}: ${ui.kindName2[d.kind] || d.kind}`,
    `${ui.eventType}: ${d.event.title}`,
    "",
    d.ai?.whatHappened || d.event.what,
    "",
  ];
  if (d.warnings.length) {
    lines.push(ui.warnTitle + ":");
    d.warnings.filter((w) => w.level !== "info").forEach((w) => lines.push(`• [${ui.sev[w.level]}] ${w.text}`));
    lines.push("");
  }
  lines.push(ui.doTitle + ":");
  d.actions.do.forEach((x) => lines.push("• " + x));
  lines.push("", ui.dontTitle + ":");
  d.actions.dont.forEach((x) => lines.push("• " + x));
  lines.push("", ui.unverified);
  return lines.join("\n");
}
