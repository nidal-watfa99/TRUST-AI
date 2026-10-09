/**
 * TRUST AI v1.0 — Application controller
 * Dual-layer: offline Risk Engine + optional AI client
 */

import { analyze } from "./risk-engine.js";
import {
  initAIProvider,
  clearAIProvider,
  isAIAvailable,
  isVisionAvailable,
  getAIStatus,
  getFreeModels,
  analyzeWithAI,
  analyzeImageWithAI,
  testConnection,
} from "./ai-provider.js";
import { initI18n, setLang, getLang, t, applyTranslations } from "./i18n.js";
import { EXAMPLES } from "./examples.js";
import { renderSourceReport } from "./source-report.js";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

let currentImageDataUrl = null;
let lastResult = null;
let lastText = "";

// ── Init ─────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  bindEvents();
  bindImageFallbacks();
  updateAIStatusUI();
  populateModelSelect();
  setLiveAlertsIdle();
});

function bindEvents() {
  $("#lang-ar")?.addEventListener("click", () => switchLang("ar"));
  $("#lang-en")?.addEventListener("click", () => switchLang("en"));

  $("#btn-analyze")?.addEventListener("click", onAnalyze);
  $("#btn-upload")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter" || e.key === " ") { e.preventDefault(); $("#file-input")?.click(); }
  });
  $("#file-input")?.addEventListener("change", onFileSelected);
  $("#btn-remove-image")?.addEventListener("click", removeImage);
  $("#btn-example")?.addEventListener("click", openExamples);
  $("#btn-settings")?.addEventListener("click", openSettings);
  $("#btn-about")?.addEventListener("click", openAbout);
  $("#btn-about-back")?.addEventListener("click", resetToHome);
  $("#btn-again")?.addEventListener("click", resetToHome);
  $("#btn-source")?.addEventListener("click", openSourceReport);
  $("#btn-source-back")?.addEventListener("click", () => { showView("result"); window.scrollTo({ top: 0 }); });
  $("#btn-source-new")?.addEventListener("click", resetToHome);
  $("#btn-back")?.addEventListener("click", resetToHome);
  $("#btn-mic")?.addEventListener("click", toggleVoiceInput);

  // LIVE alert lights — tap to explain signal meaning
  $$(".alert-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      const level = btn.dataset.level;
      const msgs = {
        low: { ar: "🟢 أخضر — خطر منخفض / آمن نسبياً", en: "🟢 Green — Low risk / relatively safe" },
        info: { ar: "🔵 أزرق — مراقبة / تحليل جارٍ أو بيانات غير كافية", en: "🔵 Blue — Monitoring / analyzing or insufficient data" },
        high: { ar: "🟠 برتقالي — تحذير مرتفع — انتبه ولا تتسرع", en: "🟠 Orange — High warning — pause and verify" },
        severe: { ar: "🔴 أحمر — خطر شديد — لا تضغط ولا تدفع ولا تشارك بيانات", en: "🔴 Red — Severe risk — do not click, pay, or share data" },
      };
      const m = msgs[level];
      if (m) showToast(getLang() === "ar" ? m.ar : m.en);
    });
  });

  $("#examples-close")?.addEventListener("click", closeExamples);
  $("#examples-backdrop")?.addEventListener("click", closeExamples);
  $("#settings-close")?.addEventListener("click", closeSettings);
  $("#settings-backdrop")?.addEventListener("click", closeSettings);

  $("#btn-save-ai")?.addEventListener("click", onSaveAI);
  $("#btn-clear-ai")?.addEventListener("click", onClearAI);
  $("#btn-test-ai")?.addEventListener("click", onTestAI);

  $("#input-text")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter" && (e.ctrlKey || e.metaKey)) onAnalyze();
  });
}

function switchLang(lang) {
  setLang(lang);
  $("#lang-ar")?.classList.toggle("active", lang === "ar");
  $("#lang-en")?.classList.toggle("active", lang === "en");
  $("#lang-ar")?.setAttribute("aria-pressed", lang === "ar");
  $("#lang-en")?.setAttribute("aria-pressed", lang === "en");
  updateAIStatusUI();
  if (lastResult) renderResult(lastResult);
  if ($("#view-source")?.classList.contains("active")) openSourceReport();
  updateSourceLabels();
}

// ── Analysis ─────────────────────────────────────────────────────────────

async function onAnalyze() {
  const text = ($("#input-text")?.value || "").trim();
  const hasImage = !!currentImageDataUrl;

  if (!text && !hasImage) {
    showToast(t("error_empty"), true);
    return;
  }

  showView("analyzing");
  setLiveAlertsMonitoring();
  await sleep(280);

  try {
    // Layer 1 — always offline
    const engineResult = analyze({ text, hasImage });

    let aiResult = null;
    let finalResult = { ...engineResult, mode: "offline" };

    // Layer 2 — optional AI
    if (isAIAvailable()) {
      if (hasImage && isVisionAvailable()) {
        aiResult = await analyzeImageWithAI(currentImageDataUrl, text);
      } else if (text) {
        aiResult = await analyzeWithAI(text, engineResult);
      }

      if (aiResult && !aiResult.error) {
        // Hybrid: take the higher risk signal, keep full transparency
        const hybridScore = Math.max(engineResult.score < 0 ? 0 : engineResult.score, aiResult.score);
        finalResult = {
          ...engineResult,
          score: hybridScore,
          level: hybridScore <= 24 ? "low" : hybridScore <= 49 ? "medium" : hybridScore <= 74 ? "high" : "severe",
          levelColor: hybridScore <= 24 ? "#22c55e" : hybridScore <= 49 ? "#eab308" : hybridScore <= 74 ? "#f97316" : "#ef4444",
          mode: hasImage && isVisionAvailable() ? "ai-vision" : "hybrid",
          ai: aiResult,
        };
      } else if (aiResult?.error) {
        finalResult.aiError = aiResult.error;
        finalResult.mode = "offline";
      }
    } else if (hasImage && !text) {
      finalResult.reasons = ["image_unavailable"];
      finalResult.score = -1;
      finalResult.level = "unknown";
      finalResult.levelColor = "#94a3b8";
    }

    lastResult = finalResult;
    lastText = text;
    renderResult(finalResult);
    showView("result");
    showToast(t("analysisDone"));
  } catch (err) {
    console.error(err);
    showToast(t("error_generic"), true);
    setLiveAlertsIdle();
    showView("home");
  }
}

function renderResult(r) {
  const scoreEl = $("#result-score");
  const levelEl = $("#result-level");
  const gaugeEl = $("#risk-gauge");
  const modeEl = $("#result-mode");
  const reasonsEl = $("#result-reasons");
  const actionsEl = $("#result-actions");
  const breakdownEl = $("#result-breakdown");
  const catsEl = $("#result-categories");
  const linksEl = $("#result-links");
  const aiBox = $("#result-ai");
  const disclaimer = $("#result-disclaimer");

  // LIVE signal lights react immediately to risk level
  updateLiveAlerts(r.level, r.score);

  // Score & level
  const displayScore = r.score < 0 ? "—" : r.score;
  if (scoreEl) {
    scoreEl.textContent = displayScore;
    scoreEl.style.color = r.levelColor || "#94a3b8";
  }
  if (levelEl) {
    levelEl.textContent = t(`level_${r.level}`);
    levelEl.style.background = (r.levelColor || "#94a3b8") + "22";
    levelEl.style.color = r.levelColor || "#94a3b8";
    levelEl.style.borderColor = r.levelColor || "#94a3b8";
  }

  // Gauge (SVG circle)
  if (gaugeEl) {
    const pct = r.score < 0 ? 0 : r.score;
    const circ = 2 * Math.PI * 54;
    const offset = circ - (pct / 100) * circ;
    gaugeEl.innerHTML = `
      <svg viewBox="0 0 120 120" class="gauge-svg" aria-hidden="true">
        <circle cx="60" cy="60" r="54" fill="none" stroke="#1e2a3a" stroke-width="10"/>
        <circle cx="60" cy="60" r="54" fill="none" stroke="${r.levelColor || "#94a3b8"}"
          stroke-width="10" stroke-linecap="round"
          stroke-dasharray="${circ}" stroke-dashoffset="${offset}"
          transform="rotate(-90 60 60)" class="gauge-arc"/>
        <text x="60" y="58" text-anchor="middle" class="gauge-score" fill="${r.levelColor || "#94a3b8"}">${displayScore}</text>
        <text x="60" y="76" text-anchor="middle" class="gauge-label" fill="#94a3b8">/ 100</text>
      </svg>`;
  }

  // Mode badge
  if (modeEl) {
    const modeKey = r.mode === "hybrid" || r.mode === "ai-vision" ? "modeHybrid" : r.mode === "ai" ? "modeAI" : "modeOffline";
    modeEl.textContent = t(modeKey);
    modeEl.className = "mode-badge " + (r.mode || "offline");
  }

  // Reasons
  if (reasonsEl) {
    reasonsEl.innerHTML = "";
    (r.reasons || []).forEach((key) => {
      const li = document.createElement("li");
      li.textContent = t(`reason_${key}`) || key;
      reasonsEl.appendChild(li);
    });
    if (!(r.reasons || []).length) {
      const li = document.createElement("li");
      li.textContent = t("action_low");
      reasonsEl.appendChild(li);
    }
  }

  // Actions
  if (actionsEl) {
    actionsEl.innerHTML = "";
    (r.actions || []).forEach((key) => {
      const li = document.createElement("li");
      li.textContent = t(`action_${key}`) || key;
      actionsEl.appendChild(li);
    });
    // AI actions if present
    if (r.ai?.actions?.length) {
      r.ai.actions.forEach((a) => {
        const li = document.createElement("li");
        li.textContent = a;
        li.className = "ai-action";
        actionsEl.appendChild(li);
      });
    }
  }

  // Transparent breakdown table
  if (breakdownEl) {
    const rows = (r.transparent?.breakdown || []).map((b) => `
      <tr>
        <td>${t(`cat_${b.category}`) || b.category}</td>
        <td class="num">${b.points}</td>
        <td class="num">${b.max}</td>
        <td class="num">${b.percentOfMax}%</td>
        <td>
          <div class="mini-bar"><div class="mini-fill" style="width:${b.percentOfMax}%;background:${r.levelColor}"></div></div>
        </td>
      </tr>`).join("");
    breakdownEl.innerHTML = rows
      ? `<table class="data-table" aria-label="${t("breakdownTitle")}">
          <thead><tr>
            <th>${t("categoriesTitle")}</th>
            <th>${t("points")}</th>
            <th>Max</th>
            <th>${t("percentOfMax")}</th>
            <th></th>
          </tr></thead>
          <tbody>${rows}</tbody>
        </table>`
      : `<p class="muted">${t("action_low")}</p>`;
  }

  // Category percent cards
  if (catsEl) {
    const cats = r.categories || {};
    catsEl.innerHTML = Object.entries(cats)
      .filter(([, v]) => v > 0)
      .map(([k, v]) => {
        const pct = r.categoryPercents?.[k] || 0;
        return `<div class="cat-card">
          <div class="cat-name">${t(`cat_${k}`)}</div>
          <div class="cat-val">${v} <span class="muted">/ ${r.transparent?.weights?.[k] || "?"} (${pct}%)</span></div>
          <div class="cat-bar"><div style="width:${pct}%;background:${r.levelColor}"></div></div>
        </div>`;
      })
      .join("") || "";
  }

  // Links table
  if (linksEl) {
    if (r.links?.length) {
      linksEl.innerHTML = `
        <table class="data-table">
          <thead><tr>
            <th>${t("host")}</th>
            <th>${t("linkScore")}</th>
            <th>URL</th>
          </tr></thead>
          <tbody>
            ${r.links.map((l) => `
              <tr>
                <td>${escapeHtml(l.host || "—")}</td>
                <td class="num">${l.score}</td>
                <td class="url-cell"><code>${escapeHtml((l.url || "").slice(0, 60))}</code></td>
              </tr>`).join("")}
          </tbody>
        </table>`;
    } else {
      linksEl.innerHTML = `<p class="muted">${t("noLinks")}</p>`;
    }
  }

  // AI box
  if (aiBox) {
    if (r.ai) {
      aiBox.classList.remove("hidden");
      aiBox.innerHTML = `
        <h3>${t("aiSummary")}</h3>
        <p>${escapeHtml(r.ai.summary || "")}</p>
        <div class="ai-meta">
          <span>${t("confidence")}: <strong>${r.ai.confidence ?? "—"}%</strong></span>
          <span>${r.ai.provider || ""} / ${r.ai.model || ""}</span>
        </div>
        ${r.ai.indicators?.length ? `<ul class="ai-indicators">${r.ai.indicators.map((i) =>
          `<li><strong>${escapeHtml(i.category || "")}</strong>: ${escapeHtml(i.detail || "")} (${i.severity ?? ""})</li>`
        ).join("")}</ul>` : ""}`;
    } else if (r.aiError) {
      aiBox.classList.remove("hidden");
      aiBox.innerHTML = `<p class="error-text">${t("connectionFail")}: ${escapeHtml(r.aiError)}</p>`;
    } else {
      aiBox.classList.add("hidden");
      aiBox.innerHTML = "";
    }
  }

  if (disclaimer) disclaimer.textContent = t("disclaimer");
}

// ── Image handling ───────────────────────────────────────────────────────

function onFileSelected(e) {
  const file = e.target.files?.[0];
  if (file) processFile(file);
  e.target.value = "";
}

function processFile(file) {
  const okTypes = ["image/jpeg", "image/png", "image/webp", "image/jpg"];
  const extOk = /\.(jpe?g|png|webp)$/i.test(file.name || "");
  if (!okTypes.includes(file.type) && !(file.type === "" && extOk)) {
    showToast(t("error_image_type"), true);
    return;
  }
  if (file.size > 5 * 1024 * 1024) {
    showToast(t("error_image_size"), true);
    return;
  }
  const reader = new FileReader();
  reader.onload = () => {
    currentImageDataUrl = reader.result;
    const img = $("#preview-img");
    if (img) img.src = currentImageDataUrl;
    $("#image-preview")?.classList.remove("hidden");
  };
  reader.onerror = () => showToast(t("error_generic"), true);
  reader.readAsDataURL(file);
}

function bindImageFallbacks() {
  const card = $(".input-card");
  if (!card) return;
  ["dragenter", "dragover"].forEach((ev) =>
    card.addEventListener(ev, (e) => { e.preventDefault(); card.classList.add("drag-over"); }));
  ["dragleave", "drop"].forEach((ev) =>
    card.addEventListener(ev, (e) => { e.preventDefault(); card.classList.remove("drag-over"); }));
  card.addEventListener("drop", (e) => {
    const f = [...(e.dataTransfer?.files || [])].find((x) => x.type.startsWith("image/") || /\.(jpe?g|png|webp)$/i.test(x.name));
    if (f) processFile(f);
  });
  document.addEventListener("paste", (e) => {
    const item = [...(e.clipboardData?.items || [])].find((i) => i.type.startsWith("image/"));
    const f = item?.getAsFile();
    if (f) { e.preventDefault(); processFile(f); }
  });
}

function removeImage() {
  currentImageDataUrl = null;
  $("#image-preview")?.classList.add("hidden");
  const img = $("#preview-img");
  if (img) {
    if (img.src.startsWith("blob:")) URL.revokeObjectURL(img.src);
    img.src = "";
  }
  const fi = $("#file-input");
  if (fi) fi.value = "";
}

// ── Settings / AI ────────────────────────────────────────────────────────

function populateModelSelect() {
  const sel = $("#ai-model");
  if (!sel) return;
  sel.innerHTML = "";
  getFreeModels().forEach((m) => {
    const opt = document.createElement("option");
    opt.value = m.id;
    opt.textContent = m.name + (m.free ? " ★" : "");
    sel.appendChild(opt);
  });
  // Free models list with official links
  const list = $("#free-models-list");
  if (list) {
    list.innerHTML = getFreeModels()
      .filter((m) => m.free)
      .map((m) => `
        <li>
          <strong>${escapeHtml(m.name)}</strong>
          <a href="${m.officialUrl}" target="_blank" rel="noopener noreferrer">${t("getKey")}</a>
        </li>`)
      .join("");
  }
}

function openSettings() {
  updateAIStatusUI();
  $("#settings-modal")?.classList.remove("hidden");
  document.body.style.overflow = "hidden";
}

function closeSettings() {
  $("#settings-modal")?.classList.add("hidden");
  document.body.style.overflow = "";
}

function onSaveAI() {
  const key = ($("#ai-key")?.value || "").trim();
  const modelId = $("#ai-model")?.value;
  if (!key || key.length < 8) {
    showToast(t("error_generic"), true);
    return;
  }
  const ok = initAIProvider({ apiKey: key, modelId });
  // Clear the visible field immediately for privacy
  if ($("#ai-key")) $("#ai-key").value = "";
  updateAIStatusUI();
  if (ok) {
    showToast(t("aiConnected"));
    closeSettings();
  } else {
    showToast(t("connectionFail"), true);
  }
}

function onClearAI() {
  clearAIProvider();
  if ($("#ai-key")) $("#ai-key").value = "";
  updateAIStatusUI();
  showToast(t("aiDisconnected"));
}

async function onTestAI() {
  const status = getAIStatus();
  if (!status.available) {
    // Try with current form values without saving permanently
    const key = ($("#ai-key")?.value || "").trim();
    const modelId = $("#ai-model")?.value;
    if (key.length > 8) initAIProvider({ apiKey: key, modelId });
  }
  const btn = $("#btn-test-ai");
  if (btn) btn.disabled = true;
  const res = await testConnection();
  if (btn) btn.disabled = false;
  showToast(res.ok ? t("connectionOk") : `${t("connectionFail")}: ${res.error || ""}`, !res.ok);
  updateAIStatusUI();
}

function updateAIStatusUI() {
  const badge = $("#ai-status-badge");
  const status = getAIStatus();
  if (badge) {
    badge.textContent = status.available ? t("aiConnected") : t("aiDisconnected");
    badge.className = "ai-status " + (status.available ? "on" : "off");
  }
}

// ── Examples ─────────────────────────────────────────────────────────────

function openExamples() {
  renderExamplesList();
  $("#examples-modal")?.classList.remove("hidden");
  document.body.style.overflow = "hidden";
}

function closeExamples() {
  $("#examples-modal")?.classList.add("hidden");
  document.body.style.overflow = "";
}

function renderExamplesList() {
  const list = $("#examples-list");
  if (!list) return;
  list.innerHTML = "";
  EXAMPLES.forEach((ex) => {
    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "example-item";
    btn.innerHTML = `<div class="ex-title">${t(ex.titleKey)}</div><div class="ex-desc">${t(ex.descKey)}</div>`;
    btn.addEventListener("click", () => {
      const lang = getLang();
      if ($("#input-text")) $("#input-text").value = ex.text[lang] || ex.text.ar;
      removeImage();
      closeExamples();
    });
    list.appendChild(btn);
  });
}

// ── About page ───────────────────────────────────────────────────────────

function updateSourceLabels() {
  const ar = getLang() === "ar";
  const set = (sel, v) => { const e = $(sel); if (e) e.textContent = v; };
  set("#btn-source", ar ? "📊 تقرير المصدر التفصيلي" : "📊 Detailed source report");
  set("#source-title", ar ? "تقرير المصدر التفصيلي" : "Detailed source report");
  set("#btn-source-back", ar ? "العودة للنتيجة" : "Back to result");
  set("#btn-source-new", ar ? "تحليل جديد" : "New analysis");
}

function openSourceReport() {
  const lang = getLang();
  updateSourceLabels();
  renderSourceReport($("#source-body"), { text: lastText, result: lastResult, lang });
  const lead = $("#source-lead");
  if (lead) lead.textContent = lang === "ar"
    ? "كل ما يمكن استنتاجه عن مصدر الخبر أو الرابط أو الحدث — بشفافية، مع بيان ما لا يمكن التحقق منه دون اتصال."
    : "Everything that can be inferred about the source — transparently, including what cannot be verified offline.";
  showView("source");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

function openAbout() {
  showView("about");
  window.scrollTo({ top: 0, behavior: "smooth" });
}

// ── Voice input (Web Speech API) ─────────────────────────────────────────

let recognition = null;
let isListening = false;

function getSpeechRecognition() {
  const SR = window.SpeechRecognition || window.webkitSpeechRecognition;
  if (!SR) return null;
  if (!recognition) {
    recognition = new SR();
    recognition.continuous = false;
    recognition.interimResults = true;
    recognition.maxAlternatives = 1;
    recognition.onresult = (event) => {
      let transcript = "";
      for (let i = event.resultIndex; i < event.results.length; i++) {
        transcript += event.results[i][0].transcript;
      }
      const ta = $("#input-text");
      if (ta && transcript) {
        const cur = ta.value.trim();
        ta.value = cur ? cur + " " + transcript : transcript;
      }
    };
    recognition.onerror = () => {
      stopVoiceInput();
      showToast(t("micError"), true);
    };
    recognition.onend = () => {
      stopVoiceInput();
    };
  }
  return recognition;
}

function toggleVoiceInput() {
  if (isListening) {
    stopVoiceInput();
    return;
  }
  const rec = getSpeechRecognition();
  if (!rec) {
    showToast(t("micNotSupported"), true);
    return;
  }
  rec.lang = getLang() === "ar" ? "ar-SA" : "en-US";
  try {
    rec.start();
    isListening = true;
    $("#btn-mic")?.classList.add("listening");
    showToast(t("micListening"));
  } catch (_) {
    showToast(t("micError"), true);
  }
}

function stopVoiceInput() {
  isListening = false;
  $("#btn-mic")?.classList.remove("listening");
  try {
    recognition?.stop();
  } catch (_) {}
}

// ── Views ────────────────────────────────────────────────────────────────

function showView(name) {
  $$(".view").forEach((v) => v.classList.remove("active"));
  const el = $(`#view-${name}`);
  if (el) el.classList.add("active");
}

function resetToHome() {
  lastResult = null;
  stopVoiceInput();
  setLiveAlertsIdle();
  showView("home");
}

// ── LIVE alert signal lights ─────────────────────────────────────────────
// Green = low/safe · Blue = monitoring/info · Orange = high · Red = severe

function clearLiveAlertClasses() {
  const group = $(".live-alerts");
  if (!group) return;
  group.classList.remove("idle", "has-high", "has-severe");
  $$(".alert-btn").forEach((btn) => btn.classList.remove("active"));
}

function setLiveAlertsIdle() {
  clearLiveAlertClasses();
  $(".live-alerts")?.classList.add("idle");
}

function setLiveAlertsMonitoring() {
  clearLiveAlertClasses();
  $("#alert-blue")?.classList.add("active");
}

/**
 * Map analysis level → glowing signal lights.
 * medium activates orange (warning), high → orange stronger, severe → red.
 * low → green. unknown → blue.
 */
function updateLiveAlerts(level, score) {
  clearLiveAlertClasses();
  const group = $(".live-alerts");
  if (!group) return;

  if (level === "severe" || (typeof score === "number" && score >= 75)) {
    $("#alert-red")?.classList.add("active");
    group.classList.add("has-severe");
  } else if (level === "high" || (typeof score === "number" && score >= 50)) {
    $("#alert-orange")?.classList.add("active");
    group.classList.add("has-high");
  } else if (level === "medium" || (typeof score === "number" && score >= 25)) {
    $("#alert-orange")?.classList.add("active");
  } else if (level === "low" || (typeof score === "number" && score >= 0 && score < 25)) {
    $("#alert-green")?.classList.add("active");
  } else {
    // unknown / insufficient data
    $("#alert-blue")?.classList.add("active");
  }
}

// ── Toast & utils ────────────────────────────────────────────────────────

let toastTimer = null;
function showToast(message, isError = false) {
  const toast = $("#toast");
  if (!toast) return;
  toast.textContent = message;
  toast.classList.toggle("error", isError);
  toast.classList.remove("hidden");
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => toast.classList.add("hidden"), 3500);
}

function sleep(ms) {
  return new Promise((r) => setTimeout(r, ms));
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}
