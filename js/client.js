/**
 * TRUST AI — Client UI (العميل)
 * Full-screen event analysis center. Accepts links, images, names, news,
 * messages and text files; renders a complete dossier with warnings and
 * professional SVG charts. Offline engine first, optional model layer second.
 */
import { buildDossier, mergeAI, normalizeUniversal, dossierToText, KINDS } from "./client-engine.js";
import { analyzeUniversal, isAIAvailable, isVisionAvailable, getAIStatus, verifyNewsWithAI, searchFactChecks } from "./ai-provider.js";
import { normalizeNewsVerdict, wantsNewsVerdict } from "./news-verdict.js";
import { detectSensitivePaste } from "./risk-engine.js";
import { renderSourceReport } from "./source-report.js";
import { getLang, t } from "./i18n.js";
import { L, SENSITIVE_LABEL } from "./client-data.js";
import { escapeHtml, sanitizeText, isSafeUrl, isSafeImageDataUrl, sniffImageType, rateLimit, securityLog } from "./security.js";

const $ = (s) => document.querySelector(s);
const MAX_IMAGES = 4;

const state = {
  open: false,
  kind: "auto",
  images: [], // { name, dataUrl }
  dossier: null,
  ai: null,
  aiError: null,
  input: null,
  opener: null,
  exampleIdx: 0,
  running: false,
  news: null, // { status: off|pending|done|error, data, error }
};

const EXAMPLES = [
  { ar: "QNET", en: "QNET" },
  { ar: "bit.ly/claim-prize-now", en: "bit.ly/claim-prize-now" },
  { ar: "عاجل!!! مصادر مطلعة تؤكد أن البنوك ستجمّد جميع الحسابات غداً. شارك الخبر قبل أن يحذفوه!", en: "BREAKING!!! Insiders confirm banks will freeze ALL accounts tomorrow. Share this before they delete it!" },
  { ar: "فرصة العمر: ادفع رسوم اشتراك 1500 دولار واجلب 3 أشخاص من عائلتك لتحصل على دخل سلبي شهري. لا تخبر أحداً بهذه الفرصة.", en: "Chance of a lifetime: pay a $1500 membership fee and recruit 3 family members for monthly passive income. Do not tell anyone about this opportunity." },
  { ar: "عزيزي العميل، سيتم تجميد حسابك خلال 30 دقيقة. أدخل رمز التحقق OTP عبر http://secure-bank-verify.tk/login", en: "Dear customer, your account will be suspended in 30 minutes. Enter your OTP via http://secure-bank-verify.tk/login" },
  { ar: "أعلن البنك المركزي في بيان رسمي بتاريخ 3 مارس 2025 خفض سعر الفائدة بمقدار 0.25%، بحسب وكالة رويترز.", en: "The central bank announced in an official statement on 3 March 2025 a 0.25% rate cut, according to Reuters." },
];

const esc = escapeHtml; // single hardened encoder (also escapes ' ` =)
const ui = () => L[getLang()] || L.ar;
const levelClass = (v) => (v >= 75 ? "severe" : v >= 50 ? "high" : v >= 25 ? "medium" : "low");
const LEVEL_COLOR = { low: "#22c55e", medium: "#eab308", high: "#f97316", severe: "#ef4444", unknown: "#94a3b8" };

/* ── Open / close ──────────────────────────────────────────────────────── */

export function initClient() {
  $("#btn-client")?.addEventListener("click", () => openClient());
  $("#btn-open-client")?.addEventListener("click", () => openClient());
  $("#cl-close")?.addEventListener("click", closeClient);
  $("#cl-models")?.addEventListener("click", () => document.dispatchEvent(new CustomEvent("trustai:open-models")));
  $("#cl-analyze")?.addEventListener("click", run);
  $("#cl-clear")?.addEventListener("click", clearAll);
  $("#cl-example")?.addEventListener("click", nextExample);
  $("#cl-file")?.addEventListener("change", (e) => { addFiles([...(e.target.files || [])]); e.target.value = ""; });
  $("#cl-add")?.addEventListener("keydown", (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("#cl-file")?.click(); } });
  $("#cl-text")?.addEventListener("keydown", (e) => { if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) run(); });
  $("#cl-text")?.addEventListener("input", watchSensitive);

  const drop = $("#cl-drop");
  ["dragenter", "dragover"].forEach((ev) => drop?.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.add("drag-over"); }));
  ["dragleave", "drop"].forEach((ev) => drop?.addEventListener(ev, (e) => { e.preventDefault(); drop.classList.remove("drag-over"); }));
  drop?.addEventListener("drop", (e) => addFiles([...(e.dataTransfer?.files || [])]));

  document.addEventListener("paste", (e) => {
    if (!state.open) return;
    const files = [...(e.clipboardData?.files || [])].filter((f) => f.type.startsWith("image/"));
    if (files.length) { e.preventDefault(); addFiles(files); }
  });
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape" && state.open && $("#settings-modal")?.classList.contains("hidden")) closeClient();
  });
  document.addEventListener("trustai:ai-changed", () => { if (state.open) { updateChip(); } });
  renderStatic();
}

export function openClient(prefill, kind) {
  const scr = $("#client-screen");
  if (!scr) return;
  state.opener = document.activeElement;
  state.open = true;
  scr.classList.remove("hidden");
  document.body.classList.add("client-open");
  document.body.style.overflow = "hidden";
  const app = $("#app"); if (app) app.inert = true;
  renderStatic();
  if (kind && ["auto", "url", "name", "news", "message"].includes(kind)) { state.kind = kind; renderStatic(); }
  if (typeof prefill === "string" && prefill) { $("#cl-text").value = prefill; watchSensitive(); }
  setTimeout(() => $("#cl-text")?.focus(), 60);
}

export function closeClient() {
  $("#client-screen")?.classList.add("hidden");
  document.body.classList.remove("client-open");
  document.body.style.overflow = "";
  const app = $("#app"); if (app) app.inert = false;
  state.open = false;
  try { state.opener?.focus?.(); } catch (_) {}
}

export function refreshClientLang() {
  renderStatic();
  if (state.dossier && state.input) rebuild();
}

/* ── Static labels ─────────────────────────────────────────────────────── */

function renderStatic() {
  const u = ui();
  const set = (sel, v) => { const e = $(sel); if (e) e.textContent = v; };
  set("#cl-title", u.title);
  set("#cl-sub", u.subtitle);
  set("#cl-analyze", u.analyze);
  set("#cl-add", u.addFiles);
  set("#cl-example", u.example);
  set("#cl-clear", u.clear);
  set("#cl-drophint", u.dropHint + " " + u.accepts);
  $("#cl-text")?.setAttribute("placeholder", u.placeholder);
  $("#cl-models")?.setAttribute("aria-label", u.models);
  $("#cl-models") && ($("#cl-models").textContent = "⚙ " + u.models);
  $("#cl-close")?.setAttribute("aria-label", u.close);
  const kinds = [["auto", u.kindAuto], ["url", u.kindUrl], ["name", u.kindName], ["news", u.kindNews], ["message", u.kindMsg]];
  const box = $("#cl-kinds");
  if (box) {
    box.innerHTML = kinds.map(([k, label]) => `<button type="button" role="radio" aria-checked="${state.kind === k}" class="cl-kind ${state.kind === k ? "active" : ""}" data-kind="${k}">${esc(label)}</button>`).join("");
    box.querySelectorAll(".cl-kind").forEach((b) => b.addEventListener("click", () => { state.kind = b.dataset.kind; renderStatic(); }));
  }
  renderTray();
  updateChip();
}

function updateChip() {
  const chip = $("#cl-ai-chip");
  if (!chip) return;
  const s = getAIStatus();
  const u = ui();
  chip.className = "cl-ai-chip " + (s.available ? "on" : "off");
  chip.textContent = s.available ? `${u.aiTitle}: ${s.model || ""}${s.vision ? " · 👁" : ""}` : (getLang() === "ar" ? "محلي فقط" : "Local only");
}

function watchSensitive() {
  const box = $("#cl-sens");
  if (!box) return;
  const hits = detectSensitivePaste($("#cl-text").value);
  if (!hits.length) { box.classList.add("hidden"); box.textContent = ""; return; }
  const lang = getLang();
  box.textContent = hits.map((h) => SENSITIVE_LABEL[lang]?.[h] || h).join("، ") + " — " + (lang === "ar" ? "احذفه قبل التحليل." : "remove it before analyzing.");
  box.classList.remove("hidden");
}

/* ── Files & images ────────────────────────────────────────────────────── */

async function addFiles(files) {
  const u = ui();
  for (const f of files) {
    const isImg = /^image\/(jpeg|png|webp)$/.test(f.type) || (f.type === "" && /\.(jpe?g|png|webp)$/i.test(f.name));
    const isTxt = f.type.startsWith("text/") || /\.(txt|md|csv|eml|log|json)$/i.test(f.name);
    if (isImg) {
      if (f.size > 5 * 1024 * 1024) { toast(u.fileTooBig, true); continue; }
      if (state.images.length >= MAX_IMAGES) { toast(u.maxImages, true); break; }
      let real = null;
      try { real = sniffImageType(new Uint8Array(await f.slice(0, 16).arrayBuffer())); } catch (_) { /* rejected below */ }
      if (!real || real === "image/gif") { toast(u.fileType, true); securityLog("client_image_rejected", { claimed: f.type }); continue; }
      try { state.images.push({ name: sanitizeText(f.name || "image", 80), dataUrl: await shrinkImage(f) }); } catch (_) { toast(u.fileType, true); }
    } else if (isTxt) {
      if (f.size > 200 * 1024) { toast(u.fileTooBig, true); continue; }
      const txt = sanitizeText(await f.text(), 200000).trim();
      const ta = $("#cl-text");
      ta.value = (ta.value.trim() ? ta.value.trim() + "\n\n" : "") + txt.slice(0, 20000);
      watchSensitive();
    } else {
      toast(u.fileType, true);
    }
  }
  renderTray();
}

function shrinkImage(file) {
  return new Promise((resolve, reject) => {
    const fr = new FileReader();
    fr.onerror = reject;
    fr.onload = () => {
      const img = new Image();
      img.onerror = reject;
      img.onload = () => {
        if (img.width * img.height > 60_000_000) { reject(new Error("image too large")); return; } // decompression-bomb guard
        const max = 1600;
        const k = Math.min(1, max / Math.max(img.width, img.height));
        const c = document.createElement("canvas");
        c.width = Math.round(img.width * k); c.height = Math.round(img.height * k);
        const g = c.getContext("2d");
        g.fillStyle = "#fff"; g.fillRect(0, 0, c.width, c.height);
        g.drawImage(img, 0, 0, c.width, c.height);
        resolve(c.toDataURL("image/jpeg", 0.86));
      };
      img.src = fr.result;
    };
    fr.readAsDataURL(file);
  });
}

function renderTray() {
  const tray = $("#cl-tray");
  if (!tray) return;
  if (!state.images.length) { tray.classList.add("hidden"); tray.innerHTML = ""; return; }
  tray.classList.remove("hidden");
  tray.innerHTML = state.images.map((im, i) => `<figure class="cl-thumb"><img src="${isSafeImageDataUrl(im.dataUrl) ? im.dataUrl : ""}" alt="${esc(im.name)}" /><button type="button" class="cl-thumb-x" data-i="${i}" aria-label="${esc(ui().clear)}">×</button></figure>`).join("");
  tray.querySelectorAll(".cl-thumb-x").forEach((b) => b.addEventListener("click", () => { state.images.splice(Number(b.dataset.i), 1); renderTray(); }));
}

function clearAll() {
  $("#cl-text").value = "";
  state.images = [];
  state.dossier = null; state.ai = null; state.aiError = null; state.input = null; state.news = null;
  $("#cl-out").innerHTML = "";
  $("#cl-progress")?.classList.add("hidden");
  watchSensitive();
  renderTray();
  $("#cl-text").focus();
}

function nextExample() {
  const ex = EXAMPLES[state.exampleIdx % EXAMPLES.length];
  state.exampleIdx++;
  $("#cl-text").value = ex[getLang()] || ex.ar;
  state.kind = "auto";
  renderStatic();
  watchSensitive();
}

/* ── Run ───────────────────────────────────────────────────────────────── */

async function run() {
  if (state.running) return;
  const u = ui();
  const text = sanitizeText($("#cl-text").value || "", 20000).trim();
  if (!text && !state.images.length) { toast(u.empty, true); return; }
  const rl = rateLimit("client_run", 20, 60000);
  if (!rl.allowed) { toast(getLang() === "ar" ? "طلبات كثيرة بسرعة. انتظر قليلاً." : "Too many requests. Please wait a moment.", true); securityLog("client_rate_limited"); return; }
  state.running = true;
  $("#cl-analyze").disabled = true;
  state.input = { text, images: state.images.map((i) => i.dataUrl), forcedKind: state.kind };
  state.ai = null; state.aiError = null;

  try {
    setProgress(0);
    await sleep(160);
    const vision = isVisionAvailable();
    const d = buildDossier({ text, images: state.input.images.length, lang: getLang(), forcedKind: state.kind, visionOn: vision, aiOn: isAIAvailable() });
    state.dossier = d;
    state.news = wantsNewsVerdict(d) ? { status: isAIAvailable() ? "pending" : "off" } : null;
    render(d, { aiPending: isAIAvailable() });
    $("#cl-out").scrollIntoView({ behavior: "smooth", block: "start" });

    const newsJob = state.news?.status === "pending" ? runNewsVerdict(text) : null;

    if (isAIAvailable()) {
      setProgress(1);
      const res = await analyzeUniversal({
        text, images: state.input.images, kind: d.kind, lang: getLang(),
        engineSummary: { score: d.score, type: d.event.type, signals: d.warnings.filter((w) => w.level !== "info").map((w) => w.key) },
      });
      if (res?.raw) {
        state.ai = normalizeUniversal(res.raw, res.provider, res.model);
        state.ai.usedImages = !!res.usedImages;
      } else if (res?.error) state.aiError = res.error;
    }
    if (newsJob) await newsJob;
    setProgress(2);
    await sleep(120);
    rebuild();
    setProgress(3);
    document.dispatchEvent(new CustomEvent("trustai:client-done", { detail: { score: state.dossier.score, level: state.dossier.level, text } }));
    toast(u.done);
  } catch (err) {
    console.error(err);
    toast(getLang() === "ar" ? "حدث خطأ غير متوقع." : "Unexpected error.", true);
  } finally {
    state.running = false;
    $("#cl-analyze").disabled = false;
    setTimeout(() => $("#cl-progress")?.classList.add("hidden"), 600);
  }
}

async function runNewsVerdict(text) {
  const lang = getLang();
  try {
    const factChecks = await searchFactChecks(text, lang);
    const res = await verifyNewsWithAI({ text, images: state.input?.images || [], lang, factChecks, today: new Date().toISOString().slice(0, 10) });
    if (res?.raw) {
      const data = normalizeNewsVerdict(res.raw, { sources: res.sources, factChecks, grounded: res.grounded, provider: res.provider, model: res.model });
      state.news = data ? { status: "done", data } : { status: "error", error: lang === "ar" ? "تعذّر فهم نتيجة التحقق." : "Could not read the verification result." };
    } else state.news = { status: "error", error: res?.error || (lang === "ar" ? "تعذّر التحقق." : "Verification failed.") };
  } catch (e) {
    state.news = { status: "error", error: String(e?.message || e) };
  }
  if (state.dossier) render(state.dossier, {});
}

function rebuild() {
  const inp = state.input;
  const d0 = buildDossier({ text: inp.text, images: inp.images.length, lang: getLang(), forcedKind: inp.forcedKind, visionOn: isVisionAvailable(), aiOn: isAIAvailable() });
  state.dossier = state.ai ? mergeAI(d0, state.ai) : { ...d0, aiError: state.aiError };
  state.dossier.newsVerdict = state.news?.status === "done" ? state.news.data : null;
  render(state.dossier, {});
}

function setProgress(step) {
  const u = ui();
  const box = $("#cl-progress");
  if (!box) return;
  const names = [u.stepOffline, u.stepAI, u.stepReport];
  box.classList.remove("hidden");
  box.innerHTML = names.map((n, i) => `<span class="cl-step ${i < step ? "done" : i === step ? "active" : ""}"><i></i>${esc(n)}</span>`).join("");
}

/* ── Rendering the dossier ─────────────────────────────────────────────── */

function render(d, { aiPending = false } = {}) {
  const out = $("#cl-out");
  if (!out) return;
  const u = ui();
  const lang = getLang();
  const col = d.levelColor;
  const levelLabel = u.levels[d.level] || d.level;
  const kindLabel = u.kindName2[d.kind] || d.kind;
  const ai = d.ai;
  const crit = d.warnings.filter((w) => w.level === "critical");

  const html = [];

  /* 0. News verdict (true / false with evidence) */
  if (state.news) html.push(newsVerdictSection(state.news, d));

  /* 1. Verdict */
  html.push(`
  <section class="cl-card cl-verdict" style="--lv:${col}" aria-labelledby="cl-h-verdict">
    <div class="cl-verdict-gauge">${gaugeSvg(d.score, col)}</div>
    <div class="cl-verdict-info">
      <h3 id="cl-h-verdict" class="cl-h">${esc(u.verdict)}</h3>
      <div class="cl-pills">
        <span class="cl-pill lv">${esc(levelLabel)}</span>
        <span class="cl-pill">${esc(u.detectedKind)}: ${esc(kindLabel)}</span>
        <span class="cl-pill">${esc(ai ? u.mode_hybrid : u.mode_offline)}</span>
      </div>
      <p class="cl-headline">${esc(ai?.headline || d.event.title)}</p>
      ${crit.length ? `<p class="cl-crit" role="alert">⚠ ${esc(crit[0].text)}</p>` : ""}
    </div>
  </section>
  ${d.unverified ? `<p class="cl-unverified" role="note">ℹ ${esc(u.unverified)}</p>` : ""}`);

  /* 2. Event */
  html.push(`
  <section class="cl-card" aria-labelledby="cl-h-event">
    <h3 id="cl-h-event" class="cl-h">${esc(u.eventTitle)}</h3>
    <p class="cl-type"><span class="cl-type-tag">${esc(u.eventType)}</span> <strong>${esc(d.event.title)}</strong>${d.event.confidence ? ` <span class="muted">· ${esc(u.confidence)} ${d.event.confidence}%</span>` : ""}</p>
    <p class="cl-p">${esc(d.event.what)}</p>
    <h4 class="cl-h4">${esc(u.howTitle)}</h4>
    <ol class="cl-steps">${d.event.how.map((s) => `<li>${esc(s)}</li>`).join("")}</ol>
    <h4 class="cl-h4">${esc(u.harmTitle)}</h4>
    <p class="cl-p cl-harm">${esc(d.event.harm)}</p>
  </section>`);

  /* 3. AI */
  html.push(aiSection(d, aiPending));

  /* 4. Warnings */
  html.push(`
  <section class="cl-card" aria-labelledby="cl-h-warn">
    <h3 id="cl-h-warn" class="cl-h">${esc(u.warnTitle)}</h3>
    <ul class="cl-warns">${d.warnings.map((w) => `<li class="cl-warn ${w.level}"><span class="cl-sev">${esc(u.sev[w.level])}</span><span>${esc(w.text)}</span></li>`).join("")}</ul>
  </section>`);

  /* 5. Charts */
  html.push(`
  <section class="cl-card" aria-labelledby="cl-h-charts">
    <h3 id="cl-h-charts" class="cl-h">${esc(u.chartsTitle)}</h3>
    <div class="cl-charts">
      <figure class="cl-chart"><figcaption>${esc(u.radarTitle)}</figcaption>${radarSvg(d.dims, col, u)}</figure>
      <figure class="cl-chart"><figcaption>${esc(u.donutTitle)}</figcaption>${donutBlock(d, u)}</figure>
    </div>
    <figure class="cl-chart cl-chart-wide"><figcaption>${esc(u.dimsTitle)}</figcaption>${dimBars(d.dims, u)}</figure>
    <figure class="cl-chart cl-chart-wide"><figcaption>${esc(u.arcTitle)} <small>${esc(u.arcHint)}</small></figcaption>${arcSvg(d.sentences, u)}</figure>
    ${ai?.credibility ? `<figure class="cl-chart cl-chart-wide"><figcaption>${esc(u.credTitle)}</figcaption>${credBars(ai.credibility, u)}</figure>` : ""}
  </section>`);

  /* 6. Images */
  if (d.imageCount > 0) {
    const note = !isAIAvailable() ? u.imgNoAI : !isVisionAvailable() ? u.imgNoVision : "";
    html.push(`
    <section class="cl-card" aria-labelledby="cl-h-img">
      <h3 id="cl-h-img" class="cl-h">${esc(u.imagesTitle)}</h3>
      <div class="cl-tray static">${state.images.map((im) => `<figure class="cl-thumb"><img src="${isSafeImageDataUrl(im.dataUrl) ? im.dataUrl : ""}" alt="${esc(im.name)}" /></figure>`).join("")}</div>
      ${note ? `<p class="cl-note-warn">${esc(note)}</p>` : ""}
      ${ai?.extractedText ? `<h4 class="cl-h4">${esc(u.extracted)}</h4><pre class="cl-pre">${esc(ai.extractedText)}</pre>` : ""}
    </section>`);
  }

  /* 7. Entities + links */
  html.push(entitiesSection(d, u));

  /* 8. Claims */
  html.push(claimsSection(d, u));

  /* 9. Verify */
  html.push(`
  <section class="cl-card" aria-labelledby="cl-h-verify">
    <h3 id="cl-h-verify" class="cl-h">${esc(u.verifyTitle)}</h3>
    <p class="cl-note">${esc(u.cannotOpen)}</p>
    ${d.queries.length ? `<h4 class="cl-h4">${esc(u.queriesTitle)}</h4><ul class="cl-queries">${d.queries.map((q) => `<li><code dir="auto">${esc(q)}</code></li>`).join("")}</ul>` : ""}
    <ul class="cl-tools">${d.tools.map((tl) => `<li><a href="${esc(isSafeUrl(tl.url) ? tl.url : "#")}" target="_blank" rel="noopener noreferrer"><span>${esc(tl.label)}</span><em>${esc(u.open)} ↗</em></a></li>`).join("")}</ul>
  </section>`);

  /* 10. Actions */
  html.push(`
  <section class="cl-card" aria-labelledby="cl-h-act">
    <h3 id="cl-h-act" class="cl-h">${esc(u.actionsTitle)}</h3>
    <div class="cl-actions">
      <div class="cl-do"><h4 class="cl-h4">✓ ${esc(u.doTitle)}</h4><ul>${d.actions.do.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>
      <div class="cl-dont"><h4 class="cl-h4">✕ ${esc(u.dontTitle)}</h4><ul>${d.actions.dont.map((x) => `<li>${esc(x)}</li>`).join("")}</ul></div>
    </div>
  </section>`);

  /* 11. Source report (kept feature) */
  html.push(`
  <details class="cl-card cl-details" id="cl-source-box">
    <summary>${esc(u.sourceTitle)} — <span class="muted">${esc(u.sourceOpen)}</span></summary>
    <div id="cl-source-body"></div>
  </details>`);

  /* 12. Disclaimer + actions */
  html.push(`
  <p class="disclaimer">${esc(t("disclaimer"))}</p>
  <div class="btn-row cl-final">
    <button type="button" class="btn btn-primary" id="cl-copy">${esc(u.copy)}</button>
    <button type="button" class="btn btn-secondary" id="cl-share">${esc(u.share)}</button>
    <button type="button" class="btn btn-secondary" id="cl-print">${esc(u.print)}</button>
  </div>
  <div class="btn-row cl-final">
    <button type="button" class="btn btn-secondary" id="cl-tomain">${esc(u.toMain)}</button>
    <button type="button" class="btn btn-ghost" id="cl-again">${esc(u.again)}</button>
  </div>`);

  out.innerHTML = html.join("");
  animateGauge();

  const src = $("#cl-source-box");
  src?.addEventListener("toggle", () => {
    if (src.open && !$("#cl-source-body").dataset.done) {
      try { renderSourceReport($("#cl-source-body"), { text: d.raw, result: { ...d.engine, score: d.score, level: d.level, levelColor: d.levelColor }, lang }); } catch (_) {}
      $("#cl-source-body").dataset.done = "1";
    }
  });
  $("#cl-open-models")?.addEventListener("click", () => document.dispatchEvent(new CustomEvent("trustai:open-models")));
  $("#nv-retry")?.addEventListener("click", () => { state.news = { status: "pending" }; render(d, {}); runNewsVerdict(state.input?.text || ""); });
  $("#nv-open-models")?.addEventListener("click", () => document.dispatchEvent(new CustomEvent("trustai:open-models")));
  $("#cl-copy")?.addEventListener("click", async () => {
    try { await navigator.clipboard.writeText(dossierToText(d, lang)); toast(u.copied); } catch (_) { toast(t("shareFail"), true); }
  });
  $("#cl-share")?.addEventListener("click", async () => {
    const text = dossierToText(d, lang);
    if (navigator.share) { try { await navigator.share({ title: "TRUST AI", text }); return; } catch (e) { if (e?.name === "AbortError") return; } }
    try { await navigator.clipboard.writeText(text); toast(u.copied); } catch (_) { toast(t("shareFail"), true); }
  });
  $("#cl-print")?.addEventListener("click", () => window.print());
  $("#cl-tomain")?.addEventListener("click", () => document.dispatchEvent(new CustomEvent("trustai:client-to-main", { detail: { text: d.raw } })));
  $("#cl-again")?.addEventListener("click", () => { clearAll(); $("#cl-scroll")?.scrollTo({ top: 0, behavior: "smooth" }); });
}

function aiSection(d, pending) {
  const u = ui();
  const ai = d.ai;
  if (ai) {
    return `
    <section class="cl-card cl-ai" aria-labelledby="cl-h-ai">
      <h3 id="cl-h-ai" class="cl-h">${esc(u.aiTitle)}</h3>
      <p class="cl-p">${esc(ai.whatHappened || ai.headline || "")}</p>
      ${ai.howItWorks?.length ? `<ol class="cl-steps">${ai.howItWorks.map((s) => `<li>${esc(s)}</li>`).join("")}</ol>` : ""}
      <p class="cl-meta"><span>${esc(u.confidence)}: <strong>${ai.confidence ?? "—"}%</strong></span><span dir="ltr">${esc(ai.provider || "")} / ${esc(ai.model || "")}</span></p>
      ${ai.indicators?.length ? `<ul class="ai-indicators">${ai.indicators.map((i) => `<li><strong>${esc(i.category || "")}</strong>: ${esc(i.detail || "")} ${i.severity ? `(${esc(i.severity)})` : ""}</li>`).join("")}</ul>` : ""}
      ${ai.limits ? `<p class="cl-note"><strong>${esc(u.limits)}:</strong> ${esc(ai.limits)}</p>` : ""}
    </section>`;
  }
  if (d.aiError) {
    return `<section class="cl-card cl-ai bad"><h3 class="cl-h">${esc(u.aiFail)}</h3><p class="error-text">${esc(d.aiError)}</p><button type="button" class="btn btn-secondary" id="cl-open-models">${esc(u.openModels)}</button></section>`;
  }
  if (pending) {
    return `<section class="cl-card cl-ai"><h3 class="cl-h">${esc(u.aiTitle)}</h3><p class="cl-p"><span class="spinner inline" aria-hidden="true"></span> ${esc(u.aiRunning)}</p></section>`;
  }
  return `<section class="cl-card cl-ai off"><h3 class="cl-h">${esc(u.aiTitle)}</h3><p class="cl-p">${esc(u.aiOff)}</p><p class="cl-note">${esc(u.aiPrivacy)}</p><button type="button" class="btn btn-secondary" id="cl-open-models">${esc(u.openModels)}</button></section>`;
}

function entitiesSection(d, u) {
  const e = d.entities;
  const groups = [["urls", u.e_urls], ["emails", u.e_emails], ["phones", u.e_phones], ["amounts", u.e_amounts], ["crypto", u.e_crypto], ["handles", u.e_handles], ["names", u.e_names]]
    .filter(([k]) => e[k]?.length);
  const aiEnt = d.ai?.entities || [];
  const links = d.engine?.links || [];
  const flagLabel = (l) => {
    const out = [];
    if (l.isShortener) out.push(t("linkFlag_shortener"));
    if (l.isBrandSpoof) out.push(t("linkFlag_brand_spoof"));
    (l.flags || []).forEach((f) => {
      if (f === "suspicious_tld") out.push(t("linkFlag_suspicious_tld"));
      if (f === "http_not_https") out.push(t("linkFlag_http_not_https"));
      if (String(f).startsWith("typosquat")) out.push(t("linkFlag_typosquat"));
    });
    return [...new Set(out)];
  };
  return `
  <section class="cl-card" aria-labelledby="cl-h-ent">
    <h3 id="cl-h-ent" class="cl-h">${esc(u.entitiesTitle)}</h3>
    ${groups.length || aiEnt.length ? groups.map(([k, label]) => `<div class="cl-ent"><span class="cl-ent-k">${esc(label)}</span><div class="cl-chips">${e[k].map((x) => `<code dir="ltr">${esc(x)}</code>`).join("")}</div></div>`).join("") : `<p class="muted">${esc(u.noEntities)}</p>`}
    ${aiEnt.length ? `<ul class="cl-ai-ents">${aiEnt.map((x) => `<li><strong>${esc(x.name)}</strong> <span class="muted">(${esc(x.type)})</span>${x.note ? ` — ${esc(x.note)}` : ""}</li>`).join("")}</ul>` : ""}
    ${links.length ? `<h4 class="cl-h4">${esc(u.linksTitle)}</h4>${links.map((l) => {
      const fl = flagLabel(l);
      return `<div class="link-card ${l.score >= 8 ? "link-danger" : l.score >= 4 ? "link-warn" : ""}"><div class="link-card-top"><strong class="link-host">${esc(l.host || "—")}</strong><span class="link-score-badge">${esc(u.linkScore)}: ${l.score}</span></div><code class="link-url">${esc((l.url || "").slice(0, 90))}</code>${fl.length ? `<ul class="link-flags">${fl.map((x) => `<li>${esc(x)}</li>`).join("")}</ul>` : ""}</div>`;
    }).join("")}` : ""}
  </section>`;
}

function claimsSection(d, u) {
  const aiClaims = d.ai?.claims || [];
  if (!aiClaims.length && !d.claimsOffline.length) return "";
  return `
  <section class="cl-card" aria-labelledby="cl-h-claims">
    <h3 id="cl-h-claims" class="cl-h">${esc(u.claimsTitle)}</h3>
    ${aiClaims.length ? `<ul class="cl-claims">${aiClaims.map((c) => `<li class="cl-claim ${esc(c.verdict)}"><span class="cl-verdict-tag">${esc(u["v_" + c.verdict] || c.verdict)}</span><div><p>${esc(c.claim)}</p>${c.note ? `<small>${esc(c.note)}</small>` : ""}</div></li>`).join("")}</ul>`
      : `<p class="cl-note">${esc(u.claimsOffline)}</p><ul class="cl-claims">${d.claimsOffline.map((c) => `<li class="cl-claim unverifiable"><span class="cl-verdict-tag">${esc(u.v_unverifiable)}</span><div><p>${esc(c)}</p></div></li>`).join("")}</ul>`}
  </section>`;
}

/* ── Charts (inline SVG, theme-aware via CSS variables) ────────────────── */

function polar(cx, cy, r, ang) { return [cx + r * Math.cos(ang), cy + r * Math.sin(ang)]; }

function arcPath(cx, cy, r, a0, a1) {
  const [x0, y0] = polar(cx, cy, r, a0);
  const [x1, y1] = polar(cx, cy, r, a1);
  const large = Math.abs(a1 - a0) > Math.PI ? 1 : 0;
  const sweep = a1 > a0 ? 1 : 0;
  return `M${x0.toFixed(2)} ${y0.toFixed(2)} A${r} ${r} 0 ${large} ${sweep} ${x1.toFixed(2)} ${y1.toFixed(2)}`;
}

function gaugeSvg(score, color) {
  const cx = 110, cy = 108, r = 84;
  const zones = [[0, 24, "low"], [25, 49, "medium"], [50, 74, "high"], [75, 100, "severe"]];
  const ang = (v) => Math.PI + (v / 100) * Math.PI;
  const zonePaths = zones.map(([a, b, k]) => `<path d="${arcPath(cx, cy, r, ang(a), ang(b + 1 > 100 ? 100 : b + 1))}" fill="none" stroke="${LEVEL_COLOR[k]}" stroke-opacity=".28" stroke-width="12" stroke-linecap="butt"/>`).join("");
  const known = score >= 0;
  const fill = known && score > 0 ? `<path class="gauge-fill" data-len="1" d="${arcPath(cx, cy, r, Math.PI, ang(score))}" fill="none" stroke="${color}" stroke-width="12" stroke-linecap="round"/>` : "";
  const [nx, ny] = polar(cx, cy, r - 18, ang(known ? score : 0));
  const needle = known ? `<line x1="${cx}" y1="${cy}" x2="${nx.toFixed(2)}" y2="${ny.toFixed(2)}" stroke="var(--text)" stroke-width="3" stroke-linecap="round"/><circle cx="${cx}" cy="${cy}" r="6" fill="var(--text)"/>` : "";
  const ticks = [0, 25, 50, 75, 100].map((v) => { const [x, y] = polar(cx, cy, r + 14, ang(v)); return `<text x="${x.toFixed(1)}" y="${(y + 3).toFixed(1)}" text-anchor="middle" class="cl-tick">${v}</text>`; }).join("");
  return `<svg viewBox="0 0 220 138" class="cl-gauge" role="img" aria-label="${known ? score + "/100" : "?"}">${zonePaths}${fill}${needle}${ticks}<text x="${cx}" y="${cy + 26}" text-anchor="middle" class="cl-gauge-num" fill="${color}">${known ? score : "؟"}</text></svg>`;
}

function animateGauge() {
  document.querySelectorAll(".gauge-fill").forEach((p) => {
    try {
      const len = p.getTotalLength();
      p.style.strokeDasharray = len; p.style.strokeDashoffset = len;
      p.getBoundingClientRect();
      p.style.transition = "stroke-dashoffset .9s ease";
      p.style.strokeDashoffset = 0;
    } catch (_) {}
  });
}

function radarSvg(dims, color, u) {
  const keys = ["manipulation", "urgency", "financial", "impersonation", "link", "unverifiability"];
  const cx = 160, cy = 150, R = 92;
  const ang = (i) => -Math.PI / 2 + (i * 2 * Math.PI) / keys.length;
  const ring = (f) => keys.map((_, i) => polar(cx, cy, R * f, ang(i)).map((n) => n.toFixed(1)).join(",")).join(" ");
  const rings = [0.25, 0.5, 0.75, 1].map((f) => `<polygon points="${ring(f)}" fill="none" stroke="var(--text-dim)" stroke-opacity=".35" stroke-width="1"/>`).join("");
  const axes = keys.map((_, i) => { const [x, y] = polar(cx, cy, R, ang(i)); return `<line x1="${cx}" y1="${cy}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}" stroke="var(--text-dim)" stroke-opacity=".35"/>`; }).join("");
  const pts = keys.map((k, i) => polar(cx, cy, R * ((dims[k] || 0) / 100), ang(i)));
  const poly = pts.map((p) => p.map((n) => n.toFixed(1)).join(",")).join(" ");
  const dots = pts.map((p) => `<circle cx="${p[0].toFixed(1)}" cy="${p[1].toFixed(1)}" r="3.5" fill="${color}"/>`).join("");
  const labels = keys.map((k, i) => {
    const [x, y] = polar(cx, cy, R + 18, ang(i));
    const c = Math.cos(ang(i));
    const anchor = c > 0.3 ? "start" : c < -0.3 ? "end" : "middle";
    return `<text x="${x.toFixed(1)}" y="${(y + 3).toFixed(1)}" text-anchor="${anchor}" class="cl-axis">${esc(u["d_" + k])} ${dims[k] || 0}</text>`;
  }).join("");
  return `<svg viewBox="0 0 320 300" class="cl-svg" role="img" aria-label="${esc(u.radarTitle)}">${rings}${axes}<polygon points="${poly}" fill="${color}" fill-opacity=".25" stroke="${color}" stroke-width="2.2" stroke-linejoin="round"/>${dots}${labels}</svg>`;
}

const PALETTE = ["#22d3ee", "#f97316", "#a78bfa", "#ef4444", "#eab308", "#22c55e", "#ec4899", "#60a5fa"];

function donutBlock(d, u) {
  const rows = (d.breakdown || []).filter((b) => b.points > 0);
  if (!rows.length) return `<p class="muted cl-empty">${esc(u.noChartData)}</p>`;
  const total = rows.reduce((a, b) => a + b.points, 0);
  const r = 52, C = 2 * Math.PI * r;
  let acc = 0;
  const seg = rows.map((b, i) => {
    const len = (b.points / total) * C;
    const s = `<circle cx="70" cy="70" r="${r}" fill="none" stroke="${PALETTE[i % PALETTE.length]}" stroke-width="18" stroke-dasharray="${len.toFixed(2)} ${(C - len).toFixed(2)}" stroke-dashoffset="${(-acc).toFixed(2)}" transform="rotate(-90 70 70)"/>`;
    acc += len;
    return s;
  }).join("");
  const name = (k) => (k === "pattern" ? u.cat_pattern : t("cat_" + k));
  const legend = rows.map((b, i) => `<li><i style="background:${PALETTE[i % PALETTE.length]}"></i><span>${esc(name(b.category))}</span><b>${b.points}</b><em>${Math.round((b.points / total) * 100)}%</em></li>`).join("");
  return `<svg viewBox="0 0 140 140" class="cl-svg cl-donut" role="img" aria-label="${esc(u.donutTitle)}"><circle cx="70" cy="70" r="${r}" fill="none" stroke="var(--border)" stroke-width="18"/>${seg}<text x="70" y="76" text-anchor="middle" class="cl-donut-num">${d.score < 0 ? "؟" : d.score}</text></svg><ul class="cl-legend">${legend}</ul>`;
}

function dimBars(dims, u) {
  return `<div class="cl-dimbars">${Object.keys(dims).map((k) => {
    const v = dims[k] || 0;
    return `<div class="cl-dim"><span>${esc(u["d_" + k])}</span><div class="cl-track" role="progressbar" aria-valuenow="${v}" aria-valuemin="0" aria-valuemax="100"><div class="cl-fill ${levelClass(v)}" style="width:${v}%"></div></div><b>${v}</b></div>`;
  }).join("")}</div>`;
}

function credBars(c, u) {
  return `<div class="cl-dimbars">${["source", "evidence", "consistency", "neutrality"].filter((k) => typeof c[k] === "number").map((k) => {
    const v = c[k]; // higher = more credible → invert the colour scale
    return `<div class="cl-dim"><span>${esc(u["cred_" + k])}</span><div class="cl-track"><div class="cl-fill ${levelClass(100 - v)}" style="width:${v}%"></div></div><b>${v}</b></div>`;
  }).join("")}</div>`;
}

function arcSvg(sentences, u) {
  if (!sentences.length) return `<p class="muted cl-empty">${esc(u.noChartData)}</p>`;
  const n = sentences.length;
  const bw = 26, gap = 12, padL = 30, H = 150, base = 118, maxH = 92;
  const W = Math.max(300, padL + n * (bw + gap) + 10);
  const bars = sentences.map((s, i) => {
    const x = padL + i * (bw + gap);
    const h = Math.max(2, (s.score / 100) * maxH);
    const k = levelClass(s.score);
    return `<g><title>${esc(s.text.slice(0, 120))}</title><rect x="${x}" y="${(base - h).toFixed(1)}" width="${bw}" height="${h.toFixed(1)}" rx="4" fill="${LEVEL_COLOR[k]}"/><text x="${x + bw / 2}" y="${(base - h - 4).toFixed(1)}" text-anchor="middle" class="cl-val">${s.score}</text><text x="${x + bw / 2}" y="${base + 14}" text-anchor="middle" class="cl-axis">${esc(u.arcCol)}${s.i}</text></g>`;
  }).join("");
  const yTh = base - 0.5 * maxH;
  return `<div class="cl-scrollx"><svg viewBox="0 0 ${W} ${H}" width="${W}" height="${H}" class="cl-svg cl-arc" role="img" aria-label="${esc(u.arcTitle)}"><line x1="${padL - 6}" y1="${base}" x2="${W - 6}" y2="${base}" stroke="var(--border)"/><line x1="${padL - 6}" y1="${yTh}" x2="${W - 6}" y2="${yTh}" stroke="var(--high)" stroke-dasharray="4 4" opacity=".6"/><text x="2" y="${yTh + 3}" class="cl-tick">50</text>${bars}</svg></div>`;
}


/* ── News verdict (صادق / كاذب) ─────────────────────────────────────────── */

const NV = {
  ar: {
    title: "حكم التحقق من الخبر", true: "خبر صادق", false: "خبر كاذب", unproven: "غير مثبت — لا يوجد دليل كافٍ للحكم",
    trueSub: "أكّدته أدلة موثوقة", falseSub: "فنّدته أدلة موثوقة", unprovenSub: "لن نصفه بالصدق أو الكذب دون دليل",
    conf: "درجة اليقين", basis: { evidence: "أدلة من بحث حيّ وسجلات مدقّقي الحقائق", model: "معرفة النموذج فقط (بلا بحث حيّ) — أقل موثوقية" },
    explain: "الشرح التفصيلي", balance: "ميزان الأدلة", sup: "تؤيّد", ref: "تفنّد", ctx: "سياق", claims: "الادعاءات واحداً واحداً", evid: "الأدلة والمصادر",
    cred: "مؤشرات المصداقية", timeline: "التسلسل الزمني", images: "الصور المرفقة", open: "فتح المصدر", rating: "تقييم المدقّق", limits: "حدود التحقق",
    pending: "جارٍ البحث عن الأدلة والمصادر…", retry: "إعادة المحاولة", none: "لا توجد أدلة مرفقة",
    offTitle: "الحكم «صادق/كاذب» يحتاج بحثاً بالأدلة", offBody: "اربط نموذج Gemini (مجاني) ليبحث التطبيق في الويب الحيّ وسجلات مدقّقي الحقائق ويصدر حكماً مدعوماً بمصادر. بدون ذلك لا يستطيع التطبيق الجزم بصحة خبر، وهو لا يخمّن.",
    connect: "ربط نموذج", reverse: "ابحث عن أصل الصورة", noteConflict: "تعارضت الأدلة، لذلك لم نصدر حكماً قاطعاً.",
    noteNoSources: "لم نجد مصدراً قابلاً للفتح يسند الحكم، فلم نعتمده.", noteModelOnly: "اعتمد النموذج على معرفته فقط دون أدلة كافية، فلم نعتمد الحكم.",
    supports: "يؤيّد", refutes: "يفنّد", context: "سياق", claimV: { true: "صحيح", false: "كاذب", unproven: "غير مثبت" },
  },
  en: {
    title: "News verification verdict", true: "TRUE news", false: "FALSE news", unproven: "Unproven — not enough evidence to judge",
    trueSub: "Confirmed by reliable evidence", falseSub: "Refuted by reliable evidence", unprovenSub: "We will not call it true or false without evidence",
    conf: "Confidence", basis: { evidence: "Live web search & fact-checker records", model: "Model knowledge only (no live search) — less reliable" },
    explain: "Detailed explanation", balance: "Evidence balance", sup: "Support", ref: "Refute", ctx: "Context", claims: "Claim by claim", evid: "Evidence & sources",
    cred: "Credibility indicators", timeline: "Timeline", images: "Attached images", open: "Open source", rating: "Fact-checker rating", limits: "Limits of verification",
    pending: "Searching for evidence and sources…", retry: "Retry", none: "No evidence attached",
    offTitle: "A true/false verdict needs evidence search", offBody: "Connect a (free) Gemini model so the app can search the live web and fact-checker records and issue a source-backed verdict. Without it the app cannot vouch for a news item — and it does not guess.",
    connect: "Connect a model", reverse: "Find the image's origin", noteConflict: "Evidence conflicted, so no firm verdict was issued.",
    noteNoSources: "No openable source supported the verdict, so it was not adopted.", noteModelOnly: "The model relied on memory only without enough evidence, so the verdict was not adopted.",
    supports: "Supports", refutes: "Refutes", context: "Context", claimV: { true: "True", false: "False", unproven: "Unproven" },
  },
};
const NV_COLOR = { true: "#22c55e", false: "#ef4444", unproven: "#94a3b8" };

function nvIcon(v, color) {
  const mark = v === "true" ? '<path d="M-26 2 L-9 20 L28 -20" fill="none" stroke="#fff" stroke-width="12" stroke-linecap="round" stroke-linejoin="round"/>'
    : v === "false" ? '<path d="M-22 -22 L22 22 M22 -22 L-22 22" fill="none" stroke="#fff" stroke-width="12" stroke-linecap="round"/>'
    : '<path d="M-14 -16 C-14 -34 16 -34 16 -14 C16 -2 0 -4 0 10" fill="none" stroke="#fff" stroke-width="11" stroke-linecap="round"/><circle cx="0" cy="28" r="6.5" fill="#fff"/>';
  return `<svg viewBox="0 0 120 120" class="nv-icon" role="img" aria-hidden="true"><circle cx="60" cy="60" r="56" fill="${color}" fill-opacity=".18"/><circle cx="60" cy="60" r="46" fill="${color}"/><g transform="translate(60 60)">${mark}</g></svg>`;
}

function nvRing(pct, color) {
  const r = 34, C = 2 * Math.PI * r, len = (Math.max(0, Math.min(100, pct)) / 100) * C;
  return `<svg viewBox="0 0 90 90" class="nv-ring" role="img" aria-label="${pct}%"><circle cx="45" cy="45" r="${r}" fill="none" stroke="var(--border)" stroke-width="9"/><circle cx="45" cy="45" r="${r}" fill="none" stroke="${color}" stroke-width="9" stroke-linecap="round" stroke-dasharray="${len.toFixed(1)} ${(C - len).toFixed(1)}" transform="rotate(-90 45 45)"/><text x="45" y="51" text-anchor="middle" class="nv-ring-num" fill="${color}">${pct}%</text></svg>`;
}

function newsVerdictSection(n, d) {
  const lang = getLang();
  const s = NV[lang] || NV.ar;
  if (n.status === "off") {
    return `<section class="cl-card nv-card nv-off" aria-labelledby="nv-h"><h3 id="nv-h" class="cl-h">📰 ${esc(s.offTitle)}</h3><p class="cl-p">${esc(s.offBody)}</p><button type="button" class="btn btn-primary" id="nv-open-models">${esc(s.connect)}</button></section>`;
  }
  if (n.status === "pending") {
    return `<section class="cl-card nv-card" aria-labelledby="nv-h"><h3 id="nv-h" class="cl-h">📰 ${esc(s.title)}</h3><p class="cl-p"><span class="spinner inline" aria-hidden="true"></span> ${esc(s.pending)}</p></section>`;
  }
  if (n.status === "error") {
    return `<section class="cl-card nv-card nv-err"><h3 class="cl-h">📰 ${esc(s.title)}</h3><p class="error-text">${esc(n.error || "")}</p><button type="button" class="btn btn-secondary" id="nv-retry">${esc(s.retry)}</button></section>`;
  }
  const v = n.data;
  const col = NV_COLOR[v.verdict];
  const sub = v.verdict === "true" ? s.trueSub : v.verdict === "false" ? s.falseSub : s.unprovenSub;
  const b = v.balance;
  const tot = Math.max(1, b.supports + b.refutes + b.context);
  const seg = (k, cnt, c) => (cnt ? `<i class="nv-seg" style="width:${(cnt / tot) * 100}%;background:${c}" title="${esc(s[k])}: ${cnt}"></i>` : "");
  const stanceLabel = { supports: s.supports, refutes: s.refutes, context: s.context };
  const stanceColor = { supports: "#22c55e", refutes: "#ef4444", context: "#94a3b8" };
  const note = v.notes.includes("conflict") ? s.noteConflict : v.notes.includes("no_sources") ? s.noteNoSources : v.notes.includes("model_only") ? s.noteModelOnly : "";
  const safe = (u) => (isSafeUrl(u) ? u : "");

  const claims = v.claims.length ? `<h4 class="cl-h4">${esc(s.claims)}</h4><ul class="nv-claims">${v.claims.map((c) => `<li class="nv-claim" style="--c:${NV_COLOR[c.verdict]}"><span class="nv-chip" style="background:${NV_COLOR[c.verdict]}">${esc(s.claimV[c.verdict])}</span><div><p>${esc(c.claim)}</p>${c.explanation ? `<small>${esc(c.explanation)}</small>` : ""}${c.evidence.length ? `<small class="muted"> · ${c.evidence.map((i) => "#" + (i + 1)).join(" ")}</small>` : ""}</div></li>`).join("")}</ul>` : "";

  const evid = v.evidence.length ? `<h4 class="cl-h4">${esc(s.evid)}</h4><ul class="nv-evid">${v.evidence.map((e, i) => `<li class="nv-ev" style="--c:${stanceColor[e.stance]}">
      <span class="nv-badge" aria-hidden="true">${esc((e.publisher || "?").trim().charAt(0).toUpperCase())}</span>
      <div class="nv-ev-body"><div class="nv-ev-top"><strong>#${i + 1} ${esc(e.publisher || "—")}</strong><span class="nv-chip" style="background:${stanceColor[e.stance]}">${esc(stanceLabel[e.stance])}</span>${e.rating ? `<span class="nv-chip rating">${esc(s.rating)}: ${esc(e.rating)}</span>` : ""}</div>
      ${e.title ? `<p class="nv-ev-title">${esc(e.title)}</p>` : ""}${e.summary ? `<p class="nv-ev-sum">${esc(e.summary)}</p>` : ""}
      <div class="nv-ev-meta">${e.date ? `<span>${esc(e.date)}</span>` : ""}${safe(e.url) ? `<a href="${esc(safe(e.url))}" target="_blank" rel="noopener noreferrer">${esc(s.open)} ↗</a>` : ""}</div></div></li>`).join("")}</ul>` : `<p class="muted">${esc(s.none)}</p>`;

  const cred = v.credibility ? `<h4 class="cl-h4">${esc(s.cred)}</h4>${credBars(v.credibility, ui())}` : "";
  const tl = v.timeline.length ? `<h4 class="cl-h4">${esc(s.timeline)}</h4><ol class="nv-timeline">${v.timeline.map((x) => `<li><b>${esc(x.date)}</b><span>${esc(x.event)}</span></li>`).join("")}</ol>` : "";
  const imgs = state.images.length ? `<h4 class="cl-h4">${esc(s.images)}</h4><div class="cl-tray static">${state.images.map((im) => `<figure class="cl-thumb"><img src="${isSafeImageDataUrl(im.dataUrl) ? im.dataUrl : ""}" alt="${esc(im.name)}" /></figure>`).join("")}</div>${v.imageNotes ? `<p class="cl-p">${esc(v.imageNotes)}</p>` : ""}<p class="nv-rev"><a href="https://lens.google.com/" target="_blank" rel="noopener noreferrer">Google Lens ↗</a> <a href="https://tineye.com/" target="_blank" rel="noopener noreferrer">TinEye ↗</a> <span class="muted">${esc(s.reverse)}</span></p>` : "";

  return `<section class="cl-card nv-card nv-${v.verdict}" style="--nv:${col}" aria-labelledby="nv-h">
    <h3 id="nv-h" class="cl-h">📰 ${esc(s.title)}</h3>
    <div class="nv-banner" role="status">
      ${nvIcon(v.verdict, col)}
      <div class="nv-banner-text"><p class="nv-label" style="color:${col}">${esc(s[v.verdict])}</p><p class="nv-sub">${esc(sub)}</p>${v.headline ? `<p class="nv-headline">${esc(v.headline)}</p>` : ""}</div>
      <div class="nv-conf">${nvRing(v.confidence, col)}<small>${esc(s.conf)}</small></div>
    </div>
    <p class="nv-basis"><span class="nv-chip basis">${esc(s.basis[v.basis] || "")}</span>${v.provider ? ` <span class="muted" dir="ltr">${esc(v.provider)} / ${esc(v.model || "")}</span>` : ""}</p>
    ${note ? `<p class="cl-note-warn">${esc(note)}</p>` : ""}
    ${v.explanation ? `<h4 class="cl-h4">${esc(s.explain)}</h4><p class="cl-p nv-expl">${esc(v.explanation)}</p>` : ""}
    <h4 class="cl-h4">${esc(s.balance)}</h4>
    <div class="nv-balance" role="img" aria-label="${esc(s.sup)} ${b.supports} / ${esc(s.ref)} ${b.refutes} / ${esc(s.ctx)} ${b.context}">${seg("sup", b.supports, "#22c55e")}${seg("ref", b.refutes, "#ef4444")}${seg("ctx", b.context, "#94a3b8")}</div>
    <p class="nv-legend"><span><i style="background:#22c55e"></i>${esc(s.sup)} ${b.supports}</span><span><i style="background:#ef4444"></i>${esc(s.ref)} ${b.refutes}</span><span><i style="background:#94a3b8"></i>${esc(s.ctx)} ${b.context}</span></p>
    ${claims}${evid}${cred}${tl}${imgs}
    ${v.limits ? `<p class="cl-note"><strong>${esc(s.limits)}:</strong> ${esc(v.limits)}</p>` : ""}
  </section>`;
}

/* ── Utils ─────────────────────────────────────────────────────────────── */

function toast(msg, isErr = false) {
  const el = $("#toast");
  if (!el) return;
  el.textContent = msg;
  el.classList.toggle("error", !!isErr);
  el.classList.remove("hidden");
  clearTimeout(toast._t);
  toast._t = setTimeout(() => el.classList.add("hidden"), 3200);
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
