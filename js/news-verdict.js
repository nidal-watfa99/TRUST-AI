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

const MANIPULATION = ["none", "fabricated", "old_content_recycled", "out_of_context", "edited_image", "ai_generated", "satire", "misattributed", "unknown"];
const nrm = (t) => String(t || "").toLowerCase().replace(/[\s"'`\\،,.؟?!:;()[\]{}\-–—_/]+/g, "");
const rootOf = (dom) => nrm(String(dom || "").toLowerCase().replace(/^www\./, "").replace(/\.(com|org|net|gov|edu|int|co|io|info|news|tv|me|ae|sa|eg|sy|jo|lb|uk|us|de|fr|ps|iq|qa|kw|ma|dz|tn)(\.[a-z]{2})?$/i, ""));

/**
 * @param raw        parsed model JSON
 * @param ctx        { sources:[{url,title}], chunks:[{url,title}|null], supports:[{text,idx[]}], queries:[], factChecks:[...],
 *                     grounded:boolean, searchUnavailable:boolean, provider, model }
 *
 * Tying the model's words to REAL retrieved pages:
 *  - an evidence item gets a link only when its domain matches a retrieved page, or when Google's grounding says
 *    that exact sentence came from that page; nothing the model "remembers" gets a link;
 *  - a true/false verdict must be backed by linked evidence of the right stance (and 2 independent hosts for "true").
 */
export function normalizeNewsVerdict(raw, ctx = {}) {
  if (!raw || typeof raw !== "object") return null;
  const factChecks = Array.isArray(ctx.factChecks) ? ctx.factChecks : [];
  const groundSources = Array.isArray(ctx.sources) ? ctx.sources : [];
  const chunks = Array.isArray(ctx.chunks) && ctx.chunks.length ? ctx.chunks : groundSources;
  const supports = Array.isArray(ctx.supports) ? ctx.supports : [];
  const allowedUrls = new Set([...factChecks.map((f) => f.url), ...groundSources.map((s) => s.url)].filter(isSafeUrl));
  const hostOfChunk = (c) => (c && (c.title || host(c.url))) || "";

  /* Which retrieved pages does a piece of text come from? (Google's own sentence→page grounding) */
  const linksFor = (...texts) => {
    const out = [];
    for (const t of texts) {
      const nf = nrm(t);
      if (nf.length < 12) continue;
      for (const sp of supports) {
        const ns = nrm(sp.text);
        if (ns.length < 12 || !(nf.includes(ns) || ns.includes(nf))) continue;
        for (const i of sp.idx) { const c = chunks[i]; if (c && isSafeUrl(c.url) && !out.some((o) => o.url === c.url)) out.push({ url: c.url, title: hostOfChunk(c) }); }
      }
    }
    return out;
  };
  const byDomain = (e) => {
    const cands = [rootOf(e.domain), nrm(e.publisher)].filter((x) => x && x.length >= 3);
    for (const c of chunks) {
      if (!c || !isSafeUrl(c.url)) continue;
      const r = rootOf(hostOfChunk(c));
      if (r.length >= 3 && cands.some((x) => x === r || (x.length >= 4 && (x.includes(r) || r.includes(x))))) return { url: c.url, title: hostOfChunk(c) };
    }
    return null;
  };

  /* Evidence: the model's items (linked to real pages when provable) + fact-checker records + other retrieved pages */
  const evidence = [];
  const seen = new Set();
  const push = (e) => { const k = (e.url || "") + "|" + e.publisher + "|" + e.title; if (seen.has(k)) return evidence.find((x) => (x.url || "") + "|" + x.publisher + "|" + x.title === k); seen.add(k); evidence.push(e); return e; };
  const modelEv = []; // index in the model's list → pushed entry (claims refer to these indexes)
  for (const e of Array.isArray(raw.evidence) ? raw.evidence.slice(0, 12) : []) {
    if (!e || typeof e !== "object") { modelEv.push(null); continue; }
    const item = { publisher: str(e.publisher, 80), domain: str(e.domain, 80), title: str(e.title, 180), stance: ["supports", "refutes", "context"].includes(e.stance) ? e.stance : "context", summary: str(e.summary, 500), date: str(e.date, 20), url: "", kind: "model", linked: false, host: "" };
    if (typeof e.url === "string" && allowedUrls.has(e.url)) { item.url = e.url; item.linked = true; item.host = host(e.url); }
    else {
      const hit = byDomain(item) || linksFor(item.summary, item.title)[0] || null;
      if (hit) { item.url = hit.url; item.linked = true; item.host = hit.title; }
    }
    modelEv.push(push(item));
  }
  const modelItems = modelEv.length;
  for (const f of factChecks) {
    if (!isSafeUrl(f.url)) continue;
    push({ publisher: str(f.publisher || host(f.url), 80), domain: host(f.url), title: str(f.title || f.claim, 180), stance: ratingToStance(f.rating), summary: str(`${f.rating ? "التقييم: " + f.rating + ". " : ""}${f.claim || ""}`, 400), date: str(f.date, 20), url: f.url, rating: str(f.rating, 80), kind: "factcheck", linked: true, host: host(f.url) });
  }
  const usedUrls = new Set(evidence.map((e) => e.url).filter(Boolean));
  const others = [];
  for (const sc of groundSources) {
    if (!isSafeUrl(sc.url) || usedUrls.has(sc.url)) continue;
    others.push({ url: sc.url, title: str(sc.title || host(sc.url), 120) });
  }

  const countable = evidence.filter((e) => e.kind === "factcheck" || e.linked || !ctx.grounded);
  const supportsN = countable.filter((e) => e.stance === "supports").length;
  const refutesN = countable.filter((e) => e.stance === "refutes").length;
  const urlBacked = evidence.filter((e) => e.url).length + others.length;

  let verdict = VERDICTS.includes(raw.verdict) ? raw.verdict : "unproven";
  let confidence = clamp(raw.confidence);
  const basis = ctx.grounded || factChecks.length ? "evidence" : "model";
  const notes = [];
  const explLinks = linksFor(raw.explanation, raw.headline);

  /* Fact-checker records outrank the model: a conflict is never resolved by guessing. */
  const fcRef = factChecks.filter((f) => ratingToStance(f.rating) === "refutes").length;
  const fcSup = factChecks.filter((f) => ratingToStance(f.rating) === "supports").length;
  if (verdict === "true" && fcRef > 0 && fcSup === 0) { verdict = "unproven"; notes.push("conflict"); }
  if (verdict === "false" && fcSup > 0 && fcRef === 0) { verdict = "unproven"; notes.push("conflict"); }

  if (verdict !== "unproven") {
    if (basis === "evidence") {
      const want = verdict === "true" ? "supports" : "refutes";
      const opp = verdict === "true" ? "refutes" : "supports";
      const linked = evidence.filter((e) => (e.linked || e.kind === "factcheck") && e.url);
      const mine = linked.filter((e) => e.stance === want);
      const against = linked.filter((e) => e.stance === opp);
      const hosts = new Set([...mine.map((e) => e.host || host(e.url)), ...explLinks.map((c) => c.title)].filter(Boolean));
      const fcOk = (verdict === "true" ? fcSup : fcRef) > 0;
      if (urlBacked === 0) { verdict = "unproven"; notes.push("no_sources"); }
      else if (against.length && !mine.length) { verdict = "unproven"; notes.push("conflict"); }
      else if (!hosts.size && !fcOk) { verdict = "unproven"; notes.push("unlinked"); }
      else if (verdict === "true" && hosts.size < 2 && !fcOk) { verdict = "unproven"; notes.push("single_source"); }
    } else if (!(confidence >= 80 && modelItems >= 2)) { verdict = "unproven"; notes.push("model_only"); }
    else confidence = Math.min(confidence, 75);
  }
  if (verdict === "unproven") confidence = Math.min(confidence, 60);

  const claims = (Array.isArray(raw.claims) ? raw.claims.slice(0, 8) : []).filter((c) => c && c.claim).map((c) => {
    const ev = (Array.isArray(c.evidence) ? c.evidence : []).map(Number).filter((i) => Number.isInteger(i) && i >= 0 && i < modelItems);
    const links = [];
    const add = (u, t) => { if (u && isSafeUrl(u) && !links.some((l) => l.url === u) && links.length < 4) links.push({ url: u, title: t || host(u) }); };
    for (const i of ev) { const e = modelEv[i]; if (e && e.url) add(e.url, e.host || e.publisher); }
    for (const l of linksFor(c.explanation, c.claim)) add(l.url, l.title);
    const evIdx = ev.map((i) => evidence.indexOf(modelEv[i])).filter((i) => i >= 0).slice(0, 6);
    let cv = VERDICTS.includes(c.verdict) ? c.verdict : "unproven";
    /* A claim cannot be "true"/"false" without a real linked source behind it. */
    if (cv !== "unproven" && !links.length && (basis === "evidence" || !ev.length)) cv = "unproven";
    return { claim: str(c.claim, 280), verdict: cv, explanation: str(c.explanation, 600), evidence: evIdx, links };
  });

  const cr = raw.credibility && typeof raw.credibility === "object" ? raw.credibility : null;
  return {
    verdict, confidence, basis, notes,
    grounded: !!ctx.grounded, searchUnavailable: !!ctx.searchUnavailable, provider: ctx.provider || null, model: ctx.model || null,
    headline: str(raw.headline, 220),
    explanation: str(raw.explanation, 3000),
    explanationLinks: explLinks.slice(0, 6),
    manipulation: MANIPULATION.includes(raw.manipulation_type) ? raw.manipulation_type : "unknown",
    firstSeen: str(raw.first_seen, 160),
    queries: (Array.isArray(ctx.queries) ? ctx.queries : []).map((q) => str(q, 160)).filter(Boolean).slice(0, 12),
    claims, evidence, others: others.slice(0, 12),
    balance: { supports: supportsN, refutes: refutesN, context: countable.length - supportsN - refutesN, total: countable.length, urlBacked },
    credibility: cr ? Object.fromEntries(["source", "evidence", "consistency", "neutrality"].map((k) => [k, clamp(cr[k])])) : null,
    timeline: (Array.isArray(raw.timeline) ? raw.timeline.slice(0, 10) : []).filter((x) => x && x.event).map((x) => ({ date: str(x.date, 30), event: str(x.event, 260) })),
    imageNotes: str(raw.image_notes, 800),
    limits: str(raw.limits, 600),
  };
}

/** Does this dossier deserve a true/false verdict? (the person chose "news", or it reads like news) */
export function wantsNewsVerdict(d) {
  if (!d || !d.raw || d.raw.trim().length < 12 && !d.imageCount) return false;
  return d.kind === "news" || d.event?.type === "fake_news" || d.event?.type === "health_hoax";
}
