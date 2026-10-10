/**
 * TRUST AI v3.1 — News verdict model (حكم الخبر)
 * Pure functions (no DOM, no network): turn the raw model JSON + real evidence records into a
 * validated view-model. The rule that matters: a "true"/"false" verdict is only shown when real
 * evidence backs it; otherwise it is downgraded to "unproven". We never present a guess as a fact.
 */
import { isSafeUrl, sanitizeText } from "./security.js";

export const VERDICTS = ["true", "false", "unproven"];
const clamp = (n, lo = 0, hi = 100) => Math.max(lo, Math.min(hi, Math.round(Number(n) || 0)));
const str = (v, n) => sanitizeText(String(v ?? ""), n);

/** Map a fact-checker's textual rating (any language) to a stance. */
export function ratingToStance(rating) {
  const r = String(rating || "").toLowerCase();
  if (/(false|fake|incorrect|misleading|hoax|fabricat|pants on fire|unfounded|satire|manipulated|scam|لا أساس|كاذب|زائف|مضلل|مفبرك|غير صحيح|خاطئ|شائعة|مزيف|غير دقيق)/.test(r)) return "refutes";
  if (/(^|\b)(true|correct|accurate|confirmed|verified)(\b|$)|(صحيح|صادق|دقيق|مؤكد|حقيقي)/.test(r) && !/(not|partly|mostly false|half|غير|جزئي)/.test(r)) return "supports";
  return "context";
}

function host(u) { try { return new URL(u).hostname.replace(/^www\./, ""); } catch { return ""; } }

/**
 * @param raw        parsed model JSON
 * @param ctx        { sources:[{url,title}], factChecks:[...], grounded:boolean, provider, model }
 */
export function normalizeNewsVerdict(raw, ctx = {}) {
  if (!raw || typeof raw !== "object") return null;
  const factChecks = Array.isArray(ctx.factChecks) ? ctx.factChecks : [];
  const groundSources = Array.isArray(ctx.sources) ? ctx.sources : [];
  const allowedUrls = new Set([...factChecks.map((f) => f.url), ...groundSources.map((s) => s.url)].filter(isSafeUrl));

  /* Evidence: model's items (URLs only if they came from real records) + real records themselves */
  const evidence = [];
  const seen = new Set();
  const push = (e) => { const k = (e.url || "") + "|" + e.publisher + "|" + e.title; if (seen.has(k)) return; seen.add(k); evidence.push(e); };
  for (const e of Array.isArray(raw.evidence) ? raw.evidence.slice(0, 12) : []) {
    if (!e || typeof e !== "object") continue;
    const url = typeof e.url === "string" && allowedUrls.has(e.url) ? e.url : "";
    push({ publisher: str(e.publisher, 80), title: str(e.title, 180), stance: ["supports", "refutes", "context"].includes(e.stance) ? e.stance : "context", summary: str(e.summary, 400), date: str(e.date, 20), url, kind: url ? "source" : "model" });
  }
  const modelItems = evidence.length;
  for (const f of factChecks) {
    if (!isSafeUrl(f.url)) continue;
    push({ publisher: str(f.publisher || host(f.url), 80), title: str(f.title || f.claim, 180), stance: ratingToStance(f.rating), summary: str(`${f.rating ? "التقييم: " + f.rating + ". " : ""}${f.claim || ""}`, 400), date: str(f.date, 20), url: f.url, kind: "factcheck", rating: str(f.rating, 80) });
  }
  for (const s of groundSources) {
    if (!isSafeUrl(s.url)) continue;
    if (evidence.some((e) => e.url === s.url)) continue;
    push({ publisher: str(s.title || host(s.url), 80), title: str(s.title, 180), stance: "context", summary: "", date: "", url: s.url, kind: "search" });
  }

  const urlBacked = evidence.filter((e) => e.url).length;
  const supports = evidence.filter((e) => e.stance === "supports").length;
  const refutes = evidence.filter((e) => e.stance === "refutes").length;

  let verdict = VERDICTS.includes(raw.verdict) ? raw.verdict : "unproven";
  let confidence = clamp(raw.confidence);
  let basis = ctx.grounded || factChecks.length ? "evidence" : "model";
  const notes = [];

  /* Fact-checker records outrank the model: a conflict is never resolved by guessing. */
  const fcRef = factChecks.filter((f) => ratingToStance(f.rating) === "refutes").length;
  const fcSup = factChecks.filter((f) => ratingToStance(f.rating) === "supports").length;
  if (verdict === "true" && fcRef > 0 && fcSup === 0) { verdict = "unproven"; notes.push("conflict"); }
  if (verdict === "false" && fcSup > 0 && fcRef === 0) { verdict = "unproven"; notes.push("conflict"); }

  if (verdict !== "unproven") {
    if (basis === "evidence" && urlBacked === 0) { verdict = "unproven"; notes.push("no_sources"); }
    else if (basis === "model" && !(confidence >= 80 && modelItems >= 2)) { verdict = "unproven"; notes.push("model_only"); }
    else if (basis === "model") confidence = Math.min(confidence, 75);
  }
  if (verdict === "unproven") confidence = Math.min(confidence, 60);

  const claims = (Array.isArray(raw.claims) ? raw.claims.slice(0, 8) : []).filter((c) => c && c.claim).map((c) => ({
    claim: str(c.claim, 280),
    verdict: VERDICTS.includes(c.verdict) ? c.verdict : "unproven",
    explanation: str(c.explanation, 500),
    evidence: (Array.isArray(c.evidence) ? c.evidence : []).map(Number).filter((i) => Number.isInteger(i) && i >= 0 && i < modelItems).slice(0, 6),
  }));
  /* A claim cannot be "true"/"false" without any cited evidence. */
  for (const c of claims) if (c.verdict !== "unproven" && !c.evidence.length && !urlBacked) c.verdict = "unproven";

  const cr = raw.credibility && typeof raw.credibility === "object" ? raw.credibility : null;
  return {
    verdict, confidence, basis, notes,
    grounded: !!ctx.grounded, provider: ctx.provider || null, model: ctx.model || null,
    headline: str(raw.headline, 220),
    explanation: str(raw.explanation, 2500),
    claims, evidence,
    balance: { supports, refutes, context: evidence.length - supports - refutes, total: evidence.length, urlBacked },
    credibility: cr ? Object.fromEntries(["source", "evidence", "consistency", "neutrality"].map((k) => [k, clamp(cr[k])])) : null,
    timeline: (Array.isArray(raw.timeline) ? raw.timeline.slice(0, 8) : []).filter((x) => x && x.event).map((x) => ({ date: str(x.date, 30), event: str(x.event, 240) })),
    imageNotes: str(raw.image_notes, 500),
    limits: str(raw.limits, 500),
  };
}

/** Does this dossier deserve a true/false verdict? (the person chose "news", or it reads like news) */
export function wantsNewsVerdict(d) {
  if (!d || !d.raw || d.raw.trim().length < 12 && !d.imageCount) return false;
  return d.kind === "news" || d.event?.type === "fake_news" || d.event?.type === "health_hoax";
}
