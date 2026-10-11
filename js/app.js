/**
 * TRUST AI v2 — Application controller
 * Dual-layer: offline Risk Engine + optional AI client
 * Security layer: js/security.js
 */

import { analyze, detectSensitivePaste } from "./risk-engine.js";
import {
  initAIProvider,
  clearAIProvider,
  saveAIConfig,
  restoreAIProvider,
  isAIAvailable,
  isVisionAvailable,
  getAIStatus,
  getFreeModels,
  PROVIDERS,
  analyzeWithAI,
  analyzeImageWithAI,
  testConnection,
} from "./ai-provider.js";
import { initI18n, setLang, getLang, getSavedLang, detectLang, t, applyTranslations } from "./i18n.js";
import { EXAMPLES } from "./examples.js";
import { renderSourceReport } from "./source-report.js";
import { initClient, openClient, closeClient, refreshClientLang } from "./client.js";
import { renderShieldStatus } from "./shield-ui.js";
import {
  escapeHtml as secEscapeHtml,
  sanitizeText,
  isSafeUrl,
  rateLimit,
  securityLog,
  storageGetJSON,
  storageSetJSON,
  sniffImageType,
  isSafeImageDataUrl,
  validateApiKey,
  APP_VERSION,
} from "./security.js";
import {
  searchEntities,
  listEntities,
  updateDatabase,
  getStats,
  getMeta,
} from "./fraud-db.js";
import { checkPhone } from "./phone-check.js";
import { renderPhoneDossier, renderScamNumberCards } from "./phone-ui.js";
import { searchScamNumbers, listScamNumberCards } from "./scam-numbers.js";
import { getQuestnetDossier } from "./questnet.js";
import { getVictimHelp } from "./victim-help.js";

const HISTORY_KEY = "trustai_history";
const HISTORY_MAX = 20;
const USAGE_KEY = "trustai_usage";

const $ = (sel) => document.querySelector(sel);
const $$ = (sel) => document.querySelectorAll(sel);

let currentImageDataUrl = null;
let lastResult = null;
let lastText = "";

// ── Init ─────────────────────────────────────────────────────────────────

document.addEventListener("DOMContentLoaded", () => {
  initI18n();
  initTheme();
  initElderly();
  restoreAIProvider();
  bindEvents();
  bindImageFallbacks();
  bindSensitiveWatch();
  updateAIStatusUI();
  populateModelSelect();
  setLiveAlertsIdle();
  initInstallPrompt();
  syncLangButtons();
  updateModeBanner();
  initClient();
  bindModelsPanel();
  handleLaunchShortcut();
});

/** PWA shortcuts (manifest "shortcuts"): ?open=news | phone */
function handleLaunchShortcut() {
  try {
    const which = new URLSearchParams(location.search).get("open");
    if (which === "phone") openPhoneCheck();
    else if (which === "news") openClient("", "news");
  } catch (_) {}
}

function bindEvents() {
  $("#lang-ar")?.addEventListener("click", () => switchLang("ar"));
  $("#lang-en")?.addEventListener("click", () => switchLang("en"));

  // Follow the device language live while the person has not picked one manually.
  window.addEventListener("languagechange", () => {
    if (getSavedLang()) return;
    const next = detectLang();
    if (next !== getLang()) switchLang(next, false);
  });

  // v2 tools
  $("#btn-fraud-db")?.addEventListener("click", openFraudDb);
  $("#btn-phone-check")?.addEventListener("click", openPhoneCheck);
  $("#btn-me-center")?.addEventListener("click", openMeCenter);
  $("#btn-questnet")?.addEventListener("click", openQuestnet);
  $("#btn-victim-help")?.addEventListener("click", openVictimHelp);
  $("#btn-report-scam")?.addEventListener("click", openReport);
  $("#btn-fraud-update")?.addEventListener("click", onFraudUpdate);
  $("#fraud-search")?.addEventListener("input", onFraudSearch);
  $("#me-search")?.addEventListener("input", onMeSearch);
  $("#btn-phone-run")?.addEventListener("click", onPhoneRun);
  $("#phone-input")?.addEventListener("keydown", (e) => {
    if (e.key === "Enter") { e.preventDefault(); onPhoneRun(); }
  });
  $("#report-form")?.addEventListener("submit", onReportSubmit);
  document.querySelectorAll(".btn-back-home").forEach((btn) => {
    btn.addEventListener("click", resetToHome);
  });

  $("#btn-theme")?.addEventListener("click", toggleTheme);
  $("#btn-share")?.addEventListener("click", shareApp);
  $("#btn-install")?.addEventListener("click", triggerInstall);
  $("#btn-elderly")?.addEventListener("click", toggleElderly);
  $("#btn-history")?.addEventListener("click", openHistory);
  $("#history-close")?.addEventListener("click", closeHistory);
  $("#history-backdrop")?.addEventListener("click", closeHistory);
  $("#btn-clear-history")?.addEventListener("click", clearHistory);
  $("#btn-copy-result")?.addEventListener("click", copyResult);
  $("#btn-share-result")?.addEventListener("click", shareResult);
  $("#btn-print-result")?.addEventListener("click", printResult);

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
  $("#btn-result-client")?.addEventListener("click", () => openClient(lastText));
  document.addEventListener("trustai:open-models", openSettings);
  document.addEventListener("trustai:client-to-main", (e) => {
    closeClient();
    const ta = $("#input-text");
    if (ta && e.detail?.text) ta.value = e.detail.text;
    resetToHome();
    window.scrollTo({ top: 0 });
  });

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

function switchLang(lang, persist = true) {
  setLang(lang, { persist });
  syncLangButtons();
  updateAIStatusUI();
  populateModelSelect();
  refreshClientLang();
  renderShieldStatus();
  renderModelsPanel();
  if (lastResult) renderResult(lastResult);
  if ($("#view-source")?.classList.contains("active")) openSourceReport();
  updateSourceLabels();
}

function syncLangButtons() {
  const lang = getLang();
  $("#lang-ar")?.classList.toggle("active", lang === "ar");
  $("#lang-en")?.classList.toggle("active", lang === "en");
  $("#lang-ar")?.setAttribute("aria-pressed", lang === "ar");
  $("#lang-en")?.setAttribute("aria-pressed", lang === "en");
}

// ── Analysis ─────────────────────────────────────────────────────────────

async function onAnalyze() {
  const text = sanitizeText($("#input-text")?.value || "", 20000).trim();
  const hasImage = !!currentImageDataUrl && isSafeImageDataUrl(currentImageDataUrl);

  if (!text && !hasImage) {
    showToast(t("error_empty"), true);
    return;
  }

  const rl = rateLimit("analyze", 30, 60000);
  if (!rl.allowed) {
    showToast(getLang() === "ar" ? "طلبات كثيرة بسرعة. انتظر قليلاً ثم أعد المحاولة." : "Too many requests. Please wait a moment and retry.", true);
    securityLog("analyze_rate_limited");
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
    saveToHistory(text, finalResult);
    bumpUsage();
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

  // Links table with flags
  if (linksEl) {
    if (r.links?.length) {
      linksEl.innerHTML = r.links.map((l) => {
        const flagLabels = [];
        if (l.isShortener) flagLabels.push(t("linkFlag_shortener"));
        if (l.isBrandSpoof) flagLabels.push(t("linkFlag_brand_spoof"));
        (l.flags || []).forEach((f) => {
          if (f === "suspicious_tld") flagLabels.push(t("linkFlag_suspicious_tld"));
          if (f === "http_not_https") flagLabels.push(t("linkFlag_http_not_https"));
          if (f.startsWith("typosquat")) flagLabels.push(t("linkFlag_typosquat"));
        });
        const uniq = [...new Set(flagLabels)];
        return `<div class="link-card ${l.score >= 8 ? "link-danger" : l.score >= 4 ? "link-warn" : ""}">
          <div class="link-card-top">
            <strong class="link-host">${escapeHtml(l.host || "—")}</strong>
            <span class="link-score-badge">${t("linkScore")}: ${l.score}</span>
          </div>
          <code class="link-url">${escapeHtml((l.url || "").slice(0, 90))}</code>
          ${uniq.length ? `<ul class="link-flags">${uniq.map((x) => `<li>${escapeHtml(x)}</li>`).join("")}</ul>` : ""}
        </div>`;
      }).join("");
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
          <span>${t("confidence")}: <strong>${escapeHtml(r.ai.confidence ?? "—")}%</strong></span>
          <span>${escapeHtml(r.ai.provider || "")} / ${escapeHtml(r.ai.model || "")}</span>
        </div>
        ${r.ai.indicators?.length ? `<ul class="ai-indicators">${r.ai.indicators.map((i) =>
          `<li><strong>${escapeHtml(i.category || "")}</strong>: ${escapeHtml(i.detail || "")} (${escapeHtml(i.severity ?? "")})</li>`
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

async function processFile(file) {
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
  // Verify the REAL content type from magic bytes (SVG / HTML disguised as an image is rejected).
  let realType = null;
  try { realType = sniffImageType(new Uint8Array(await file.slice(0, 16).arrayBuffer())); } catch (_) { /* fall through */ }
  if (!realType || realType === "image/gif") {
    showToast(t("error_image_type"), true);
    securityLog("image_rejected_magic_bytes", { claimed: file.type });
    return;
  }
  const reader = new FileReader();
  reader.onload = () => {
    if (!isSafeImageDataUrl(reader.result)) {
      showToast(t("error_image_type"), true);
      return;
    }
    currentImageDataUrl = reader.result;
    const img = $("#preview-img");
    if (img) img.src = currentImageDataUrl;
    $("#image-preview")?.classList.remove("hidden");
    showToast(t("pasteImageOk"));
  };
  reader.onerror = () => showToast(t("error_generic"), true);
  reader.readAsDataURL(new Blob([file], { type: realType }));
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
    if (document.body.classList.contains("client-open")) return; // the client handles its own paste
    const items = [...(e.clipboardData?.items || [])];
    const item = items.find((i) => i.type.startsWith("image/"));
    const f = item?.getAsFile();
    if (f) {
      e.preventDefault();
      processFile(f);
      return;
    }
    // Also accept files from clipboard on some mobile browsers
    const files = [...(e.clipboardData?.files || [])];
    const imgFile = files.find((x) => x.type.startsWith("image/"));
    if (imgFile) {
      e.preventDefault();
      processFile(imgFile);
    }
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

const PROVIDER_ICONS = {
  groq: `<svg class="model-icon" viewBox="0 0 24 24" width="28" height="28" aria-hidden="true"><rect width="24" height="24" rx="6" fill="#f55036"/><text x="12" y="16" text-anchor="middle" fill="#fff" font-size="9" font-weight="700" font-family="system-ui">G</text></svg>`,
  gemini: `<svg class="model-icon" viewBox="0 0 24 24" width="28" height="28" aria-hidden="true"><rect width="24" height="24" rx="6" fill="#4285F4"/><path d="M12 4l2.5 5.5L20 11l-5.5 2.5L12 19l-2.5-5.5L4 11l5.5-2.5L12 4z" fill="#fff"/></svg>`,
  openrouter: `<svg class="model-icon" viewBox="0 0 24 24" width="28" height="28" aria-hidden="true"><rect width="24" height="24" rx="6" fill="#6366f1"/><path d="M7 12h10M12 7v10" stroke="#fff" stroke-width="2.2" stroke-linecap="round"/></svg>`,
  openai: `<svg class="model-icon" viewBox="0 0 24 24" width="28" height="28" aria-hidden="true"><rect width="24" height="24" rx="6" fill="#10a37f"/><circle cx="12" cy="12" r="5.5" fill="none" stroke="#fff" stroke-width="1.8"/><circle cx="12" cy="12" r="2" fill="#fff"/></svg>`,
};

// ── Models panel (لوحة النماذج) ──────────────────────────────────────────
let panelProvider = "groq";

function populateModelSelect() {
  // Hidden <select id="ai-model"> stays the single source of truth for the chosen model.
  const sel = $("#ai-model");
  if (sel) {
    const keep = sel.value;
    sel.innerHTML = "";
    getFreeModels().forEach((m) => {
      const opt = document.createElement("option");
      opt.value = m.id;
      opt.textContent = m.name;
      sel.appendChild(opt);
    });
    if (keep && getFreeModels().some((m) => m.id === keep)) sel.value = keep;
  }
  renderModelsPanel();
}

function renderModelsPanel() {
  const sel = $("#ai-model");
  const status = getAIStatus();
  const models = getFreeModels();
  if (sel && !sel.value) sel.value = status.modelId || models[0].id;
  const chosen = models.find((m) => m.id === sel?.value) || models[0];
  if (!models.some((m) => m.provider === panelProvider)) panelProvider = models[0].provider;
  if (chosen && sel && !sel.dataset.touched) panelProvider = chosen.provider;

  // status strip
  const st = $("#mp-status");
  if (st) {
    st.className = "mp-status " + (status.available ? "on" : "off");
    st.textContent = status.available
      ? `● ${t("mpStatusOn")}: ${status.model || ""}${status.vision ? " · 👁" : ""}`
      : `○ ${t("mpStatusOff")}`;
  }

  // provider tabs
  const tabs = $("#mp-tabs");
  if (tabs) {
    const provs = [...new Set(models.map((m) => m.provider))];
    tabs.innerHTML = provs.map((pid) => `
      <button type="button" role="tab" class="mp-tab ${pid === panelProvider ? "active" : ""}" data-provider="${pid}" aria-selected="${pid === panelProvider}">
        ${PROVIDER_ICONS[pid] || ""}<span>${escapeHtml(PROVIDERS[pid]?.name || pid)}</span>
        ${status.available && status.provider === pid ? `<i class="mp-live" title="${escapeHtml(t("mpActive"))}"></i>` : ""}
      </button>`).join("");
    tabs.querySelectorAll(".mp-tab").forEach((b) => b.addEventListener("click", () => {
      panelProvider = b.dataset.provider;
      const first = getFreeModels().find((m) => m.provider === panelProvider);
      if (sel && first) { sel.value = first.id; sel.dataset.touched = "1"; }
      renderModelsPanel();
    }));
  }

  // model cards for this provider
  const list = $("#mp-models");
  if (list) {
    list.innerHTML = models.filter((m) => m.provider === panelProvider).map((m) => {
      const on = sel?.value === m.id;
      const badges = [
        m.free ? `<span class="model-badge free">${t("badgeFree")}</span>` : `<span class="model-badge paid">${t("badgePaid")}</span>`,
        m.vision ? `<span class="model-badge vision">${t("badgeVision")}</span>` : `<span class="model-badge text">${t("mpNoVision")}</span>`,
      ].join("");
      return `<button type="button" role="radio" aria-checked="${on}" class="mp-model ${on ? "active" : ""}" data-id="${m.id}">
        <span class="mp-radio" aria-hidden="true"></span>
        <span class="mp-model-main"><strong>${escapeHtml(m.name.replace(/^[^—]+—\s*/, ""))}</strong><code dir="ltr">${escapeHtml(m.model)}</code></span>
        <span class="model-badges">${badges}</span>
      </button>`;
    }).join("");
    list.querySelectorAll(".mp-model").forEach((b) => b.addEventListener("click", () => {
      if (sel) { sel.value = b.dataset.id; sel.dataset.touched = "1"; }
      renderModelsPanel();
    }));
  }

  // official key link
  const prov = PROVIDERS[panelProvider];
  const kl = $("#mp-keylink");
  if (kl && prov) {
    kl.innerHTML = `
      <div class="mp-kl-head"><span class="mp-kl-label">${t("mpOfficial")}</span>${chosen?.free === false ? `<span class="model-badge paid">${t("badgePaid")}</span>` : `<span class="model-badge free">${t("badgeFree")}</span>`}</div>
      <code class="mp-kl-url" dir="ltr">${escapeHtml(prov.host)}</code>
      <div class="mp-kl-btns">
        <a class="btn btn-primary mp-kl-open" href="${prov.keyUrl}" target="_blank" rel="noopener noreferrer">${t("mpOpenOfficial")} ↗</a>
        <button type="button" class="btn btn-secondary" id="mp-copy-link">${t("mpCopyLink")}</button>
        <a class="mp-kl-docs" href="${prov.docs}" target="_blank" rel="noopener noreferrer">${t("mpDocs")} ↗</a>
      </div>
      <p class="mp-kl-steps">${t("mpSteps")}</p>`;
    $("#mp-copy-link")?.addEventListener("click", async () => {
      try { await navigator.clipboard.writeText(prov.keyUrl); showToast(t("mpLinkCopied")); } catch (_) { showToast(t("shareFail"), true); }
    });
  }
  updateKeyHint();
}

function updateKeyHint() {
  const el = $("#mp-keyhint");
  const prov = PROVIDERS[panelProvider];
  if (!el || !prov) return;
  const v = ($("#ai-key")?.value || "").trim();
  el.className = "mp-keyhint";
  if (!v) { el.textContent = `${t("mpKeyEmpty")} ${prov.keyHint}…`; return; }
  const ok = prov.keyHint === "sk-" ? v.startsWith("sk-") && !v.startsWith("sk-or-") : v.startsWith(prov.keyHint);
  el.textContent = ok ? t("mpKeyMatch") : `${t("mpKeyMismatch")} ${prov.keyHint}`;
  el.classList.add(ok ? "ok" : "warn");
}

function bindModelsPanel() {
  $("#ai-key")?.addEventListener("input", updateKeyHint);
  $("#mp-eye")?.addEventListener("click", () => {
    const inp = $("#ai-key");
    if (!inp) return;
    const show = inp.type === "password";
    inp.type = show ? "text" : "password";
    $("#mp-eye").setAttribute("aria-label", show ? t("mpHide") : t("mpShow"));
    $("#mp-eye").classList.toggle("on", show);
  });
  $("#mp-paste")?.addEventListener("click", async () => {
    try {
      const txt = (await navigator.clipboard.readText()).trim();
      if (txt) { $("#ai-key").value = txt; updateKeyHint(); }
    } catch (_) { showToast(t("mpPasteFail"), true); $("#ai-key")?.focus(); }
  });
}

function openSettings() {
  updateAIStatusUI();
  populateModelSelect();
  // Usage line
  let note = $("#usage-note");
  if (!note) {
    note = document.createElement("p");
    note.id = "usage-note";
    note.className = "modal-note usage-note";
    $("#settings-modal .settings-panel")?.appendChild(note);
  }
  note.textContent = `${t("usageToday")} ${getUsageToday()}`;
  $("#settings-modal")?.classList.remove("hidden");
  document.body.style.overflow = "hidden";
}

function closeSettings() {
  $("#settings-modal")?.classList.add("hidden");
  document.body.style.overflow = document.body.classList.contains("client-open") ? "hidden" : "";
}

function showAIResult(ok, msg) {
  const box = $("#ai-test-result");
  if (!box) return;
  box.classList.remove("hidden");
  box.classList.toggle("ok", !!ok);
  box.classList.toggle("bad", !ok);
  box.textContent = msg;
}

function syncModelSelectToStatus() {
  const sel = $("#ai-model");
  const st = getAIStatus();
  if (!sel || !st.modelId || sel.value === st.modelId) return false;
  sel.value = st.modelId;
  sel.dataset.touched = "";
  renderModelsPanel();
  return true;
}

async function onSaveAI() {
  const key = ($("#ai-key")?.value || "").trim();
  const modelId = $("#ai-model")?.value;
  const customModel = ($("#ai-custom-model")?.value || "").trim();
  if (!validateApiKey(key).ok) {
    showAIResult(false, getLang() === "ar" ? "الصق مفتاح API صالحاً أولاً (بدون مسافات أو رموز غريبة)." : "Paste a valid API key first (no spaces or unusual characters).");
    return;
  }
  initAIProvider({ apiKey: key, modelId, customModel });
  const switched = syncModelSelectToStatus();
  showAIResult(true, (switched ? (getLang() === "ar" ? "تم اختيار مزوّد المفتاح تلقائيًا. " : "Provider chosen from your key. ") : "") + (getLang() === "ar" ? "جارٍ اختبار الاتصال…" : "Testing connection…"));
  const res = await testConnection();
  updateAIStatusUI();
  if (res.ok) {
    saveAIConfig();
    if ($("#ai-key")) $("#ai-key").value = "";
    showAIResult(true, t("connectionOk"));
    showToast(t("aiConnected"));
    setTimeout(closeSettings, 700);
  } else {
    clearAIProvider();
    updateAIStatusUI();
    showAIResult(false, `${t("connectionFail")}: ${res.error || ""}`);
  }
}

function onClearAI() {
  if (!confirm(t("clearAIConfirm"))) return;
  clearAIProvider();
  if ($("#ai-key")) $("#ai-key").value = "";
  updateAIStatusUI();
  updateModeBanner();
  showToast(t("aiDisconnected"));
}

async function onTestAI() {
  const key = ($("#ai-key")?.value || "").trim();
  const modelId = $("#ai-model")?.value;
  const customModel = ($("#ai-custom-model")?.value || "").trim();
  if (validateApiKey(key).ok) { initAIProvider({ apiKey: key, modelId, customModel }); syncModelSelectToStatus(); }
  const btn = $("#btn-test-ai");
  if (btn) btn.disabled = true;
  showAIResult(true, getLang() === "ar" ? "جارٍ اختبار الاتصال…" : "Testing connection…");
  const res = await testConnection();
  if (btn) btn.disabled = false;
  if (res.ok) saveAIConfig();
  showAIResult(res.ok, res.ok ? t("connectionOk") : `${t("connectionFail")}: ${res.error || ""}`);
  updateAIStatusUI();
}

function updateAIStatusUI() {
  const badge = $("#ai-status-badge");
  const status = getAIStatus();
  if (badge) {
    badge.textContent = status.available ? t("aiConnected") : t("aiDisconnected");
    badge.className = "ai-status " + (status.available ? "on" : "off");
  }
  updateModeBanner();
  renderModelsPanel();
  document.dispatchEvent(new CustomEvent("trustai:ai-changed"));
}

function updateModeBanner() {
  const el = $("#mode-banner");
  if (!el) return;
  if (isAIAvailable()) {
    el.textContent = t("modeBannerAI");
    el.className = "mode-banner ai-banner";
  } else {
    el.textContent = t("modeBannerOffline");
    el.className = "mode-banner offline-banner";
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
  renderShieldStatus();
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
        ta.dispatchEvent(new Event("input", { bubbles: true }));
      }
    };
    recognition.onerror = (event) => {
      stopVoiceInput();
      const code = event?.error || "";
      if (code === "not-allowed" || code === "service-not-allowed") {
        showToast(t("micError"), true);
      } else if (code === "no-speech") {
        showToast(getLang() === "ar" ? "لم يُلتقط كلام — حاول مجدداً" : "No speech detected — try again", true);
      } else if (code !== "aborted") {
        showToast(t("micError"), true);
      }
    };
    recognition.onend = () => {
      stopVoiceInput();
    };
  }
  return recognition;
}

async function toggleVoiceInput() {
  if (isListening) {
    stopVoiceInput();
    return;
  }
  const rec = getSpeechRecognition();
  if (!rec) {
    showToast(t("micNotSupported"), true);
    return;
  }
  // Ensure mic permission when available
  if (navigator.mediaDevices?.getUserMedia) {
    try {
      const stream = await navigator.mediaDevices.getUserMedia({ audio: true });
      stream.getTracks().forEach((tr) => tr.stop());
    } catch (_) {
      showToast(t("micError"), true);
      return;
    }
  }
  rec.lang = getLang() === "ar" ? "ar-SA" : "en-US";
  try {
    rec.start();
    isListening = true;
    $("#btn-mic")?.classList.add("listening");
    showToast(t("micListening"));
  } catch (_) {
    showToast(t("micError"), true);
    isListening = false;
  }
}

function stopVoiceInput() {
  isListening = false;
  $("#btn-mic")?.classList.remove("listening");
  try {
    recognition?.stop();
  } catch (_) {}
}

// ── Theme (dark / light) ─────────────────────────────────────────────────

function initTheme() {
  let theme = "dark";
  try {
    theme = localStorage.getItem("trustai_theme") || "dark";
  } catch (_) {}
  applyTheme(theme);
}

function applyTheme(theme) {
  const isLight = theme === "light";
  document.documentElement.setAttribute("data-theme", isLight ? "light" : "dark");
  const moon = document.querySelector(".theme-icon-moon");
  const sun = document.querySelector(".theme-icon-sun");
  if (moon) moon.style.display = isLight ? "none" : "block";
  if (sun) sun.style.display = isLight ? "block" : "none";
  const meta = document.querySelector('meta[name="theme-color"]');
  if (meta) meta.setAttribute("content", isLight ? "#f1f5f9" : "#0a0f1a");
  try {
    localStorage.setItem("trustai_theme", theme);
  } catch (_) {}
}

function toggleTheme() {
  const current = document.documentElement.getAttribute("data-theme") || "dark";
  applyTheme(current === "light" ? "dark" : "light");
}

// ── PWA Install to desktop ───────────────────────────────────────────────
// The install button is ALWAYS visible (unless the app already runs installed). When the browser
// offers a native prompt we use it; otherwise we open a how-to for this exact browser/OS, plus a
// downloadable desktop shortcut for Windows.

let deferredInstallPrompt = null;

function isStandalone() {
  return window.matchMedia("(display-mode: standalone)").matches
    || window.matchMedia("(display-mode: window-controls-overlay)").matches
    || window.navigator.standalone === true;
}

function initInstallPrompt() {
  const btn = $("#btn-install");
  const cta = $("#btn-install-cta");
  window.addEventListener("beforeinstallprompt", (e) => {
    e.preventDefault();
    deferredInstallPrompt = e;
  });
  window.addEventListener("appinstalled", () => {
    deferredInstallPrompt = null;
    btn?.classList.add("hidden");
    cta?.classList.add("hidden");
    closeInstallHelp();
    showToast(t("installOk"));
  });
  if (isStandalone()) {
    btn?.classList.add("hidden");
    cta?.classList.add("hidden");
  } else {
    btn?.classList.remove("hidden");
    cta?.classList.remove("hidden");
  }
  cta?.addEventListener("click", triggerInstall);
  $("#install-close")?.addEventListener("click", closeInstallHelp);
  $("#install-backdrop")?.addEventListener("click", closeInstallHelp);
  $("#btn-install-native")?.addEventListener("click", nativeInstall);
  $("#btn-install-shortcut")?.addEventListener("click", downloadShortcut);
}

function detectPlatform() {
  const ua = navigator.userAgent || "";
  const ios = /iPad|iPhone|iPod/.test(ua) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  const android = /Android/i.test(ua);
  const mac = /Macintosh/.test(ua) && !ios;
  const win = /Windows/i.test(ua);
  const edge = /Edg\//.test(ua);
  const firefox = /Firefox|FxiOS/.test(ua);
  const safari = /Safari/.test(ua) && !/Chrome|Chromium|CriOS|Edg\/|OPR\//.test(ua);
  return { ios, android, mac, win, edge, firefox, safari };
}

function installSteps() {
  const p = detectPlatform();
  const ar = getLang() === "ar";
  if (p.ios) return ar
    ? ["افتح الصفحة في Safari", "اضغط زر المشاركة ⬆︎ في الأسفل", "اختر «إضافة إلى الشاشة الرئيسية»", "اضغط «إضافة» — ستظهر الأيقونة على شاشتك"]
    : ["Open this page in Safari", "Tap the Share button ⬆︎", "Choose “Add to Home Screen”", "Tap “Add” — the icon appears on your Home Screen"];
  if (p.android) return ar
    ? ["اضغط قائمة المتصفح ⋮", "اختر «تثبيت التطبيق» أو «إضافة إلى الشاشة الرئيسية»", "أكّد — ستظهر الأيقونة بين تطبيقاتك"]
    : ["Tap the browser menu ⋮", "Choose “Install app” or “Add to Home screen”", "Confirm — the icon appears among your apps"];
  if (p.mac && p.safari) return ar
    ? ["من قائمة «ملف» في Safari اختر «إضافة إلى Dock»", "أكّد الاسم والأيقونة", "سيظهر التطبيق في Dock وفي مجلد التطبيقات"]
    : ["In Safari choose File → Add to Dock", "Confirm the name and icon", "The app appears in your Dock and Applications"];
  if (p.firefox) return ar
    ? ["Firefox على سطح المكتب لا يدعم تثبيت التطبيقات", "افتح هذا الرابط في Chrome أو Edge ثم اضغط «تثبيت»", "أو نزّل اختصار سطح المكتب بالزر أدناه (ويندوز)"]
    : ["Desktop Firefox cannot install web apps", "Open this link in Chrome or Edge and press Install", "Or download the desktop shortcut below (Windows)"];
  return ar
    ? [p.edge ? "اضغط ⋯ ← «التطبيقات» ← «تثبيت هذا الموقع كتطبيق»" : "اضغط ⋮ ← «حفظ ومشاركة» ← «تثبيت TRUST AI»", "أو اضغط أيقونة التثبيت ⊕ في شريط العنوان", "أكّد — ستظهر الأيقونة على سطح المكتب وقائمة ابدأ"]
    : [p.edge ? "Click ⋯ → Apps → Install this site as an app" : "Click ⋮ → Save and share → Install TRUST AI", "Or click the install icon ⊕ in the address bar", "Confirm — the icon appears on your desktop and Start menu"];
}

function openInstallHelp() {
  const modal = $("#install-modal");
  if (!modal) return;
  const list = $("#install-steps");
  if (list) list.innerHTML = installSteps().map((s) => `<li>${escapeHtml(s)}</li>`).join("");
  $("#btn-install-native")?.classList.toggle("hidden", !deferredInstallPrompt);
  $("#btn-install-shortcut")?.classList.toggle("hidden", !detectPlatform().win);
  modal.classList.remove("hidden");
  applyTranslations();
}

function closeInstallHelp() {
  $("#install-modal")?.classList.add("hidden");
}

async function nativeInstall() {
  if (!deferredInstallPrompt) return;
  deferredInstallPrompt.prompt();
  try {
    const choice = await deferredInstallPrompt.userChoice;
    if (choice?.outcome === "accepted") showToast(t("installOk"));
  } catch (_) {}
  deferredInstallPrompt = null;
  closeInstallHelp();
}

async function triggerInstall() {
  if (isStandalone()) { showToast(t("installOk")); return; }
  if (deferredInstallPrompt) { await nativeInstall(); return; }
  openInstallHelp();
}

function downloadShortcut() {
  const url = window.location.href.split("?")[0].split("#")[0];
  const blob = new Blob([`[InternetShortcut]\r\nURL=${url}\r\n`], { type: "application/octet-stream" });
  const a = document.createElement("a");
  a.href = URL.createObjectURL(blob);
  a.download = "TRUST AI.url";
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 4000);
}

// ── Share app (Web Share API — Android multi-share menu) ─────────────────

async function shareApp() {
  const url = window.location.href.split("?")[0].split("#")[0];
  const title = "TRUST AI";
  const text = getLang() === "ar"
    ? "تحقق قبل أن تثق — منصة موثوقة لتحليل الرسائل والروابط ضد الاحتيال"
    : "Verify before you trust — digital safety analysis for messages & links";
  if (navigator.share) {
    try {
      await navigator.share({ title, text, url });
      showToast(t("shareOk"));
      return;
    } catch (err) {
      if (err?.name === "AbortError") return;
    }
  }
  // Fallback: copy link
  try {
    await navigator.clipboard.writeText(url);
    showToast(getLang() === "ar" ? "تم نسخ الرابط ✓" : "Link copied ✓");
  } catch (_) {
    showToast(t("shareFail"), true);
  }
}

// ── History (local only) ─────────────────────────────────────────────────

const LEVEL_SET = new Set(["low", "medium", "high", "severe", "unknown"]);

/** Local storage can be edited by anyone with device access / an extension: coerce every field. */
function loadHistory() {
  const arr = storageGetJSON(HISTORY_KEY, { fallback: [], maxBytes: 200_000 });
  if (!Array.isArray(arr)) return [];
  return arr.slice(0, HISTORY_MAX).filter((e) => e && typeof e === "object").map((e) => ({
    id: Number.isFinite(Number(e.id)) ? Number(e.id) : 0,
    at: typeof e.at === "string" && !Number.isNaN(Date.parse(e.at)) ? e.at : null,
    preview: sanitizeText(String(e.preview ?? ""), 120),
    score: Number.isFinite(Number(e.score)) ? Number(e.score) : -1,
    level: LEVEL_SET.has(e.level) ? e.level : "unknown",
    mode: ["offline", "hybrid", "ai", "ai-vision"].includes(e.mode) ? e.mode : "offline",
  }));
}

function saveToHistory(text, result) {
  try {
    const entry = {
      id: Date.now(),
      at: new Date().toISOString(),
      preview: (text || "").slice(0, 120),
      score: result.score,
      level: result.level,
      mode: result.mode || "offline",
    };
    const list = loadHistory().filter((e) => e.preview !== entry.preview);
    list.unshift(entry);
    storageSetJSON(HISTORY_KEY, list.slice(0, HISTORY_MAX), { maxBytes: 200_000 });
  } catch (_) {}
}

function openHistory() {
  const list = $("#history-list");
  if (!list) return;
  const items = loadHistory();
  if (!items.length) {
    list.innerHTML = `<li class="history-empty">${t("historyEmpty")}</li>`;
  } else {
    list.innerHTML = items.map((e) => {
      const date = e.at ? new Date(e.at).toLocaleString(getLang() === "ar" ? "ar" : "en") : "";
      const numScore = Number(e.score);
      const score = !Number.isFinite(numScore) || numScore < 0 ? "—" : numScore;
      return `<li class="history-item" data-id="${escapeHtml(e.id)}">
        <div class="history-item-main">
          <span class="history-score" style="color:${levelColor(e.level)}">${score}</span>
          <span class="history-level">${t("level_" + (e.level || "unknown"))}</span>
          <span class="history-date">${escapeHtml(date)}</span>
        </div>
        <p class="history-preview">${escapeHtml(e.preview || "")}</p>
      </li>`;
    }).join("");
  }
  $("#history-modal")?.classList.remove("hidden");
  document.body.style.overflow = "hidden";
}

function closeHistory() {
  $("#history-modal")?.classList.add("hidden");
  document.body.style.overflow = "";
}

function clearHistory() {
  if (!confirm(t("historyConfirmClear"))) return;
  try {
    localStorage.removeItem(HISTORY_KEY);
  } catch (_) {}
  openHistory();
  showToast(t("btnClearHistory"));
}

function levelColor(level) {
  return { low: "#22c55e", medium: "#eab308", high: "#f97316", severe: "#ef4444", unknown: "#94a3b8" }[level] || "#94a3b8";
}

// ── Copy / Share / Print result ──────────────────────────────────────────

function buildResultText() {
  if (!lastResult) return "";
  const r = lastResult;
  const lines = [
    "TRUST AI — " + (getLang() === "ar" ? "نتيجة التحليل" : "Analysis result"),
    "──────────────",
    `${t("riskScore")}: ${r.score < 0 ? "—" : r.score}/100`,
    `${t("resultTitle")}: ${t("level_" + r.level)}`,
    "",
  ];
  if (r.ai?.summary) {
    lines.push(t("aiSummary") + ":", r.ai.summary, "");
  }
  if (r.reasons?.length) {
    lines.push(t("whyTitle") + ":");
    r.reasons.forEach((k) => lines.push("• " + (t("reason_" + k) || k)));
    lines.push("");
  }
  if (r.actions?.length) {
    lines.push(t("actionTitle") + ":");
    r.actions.forEach((k) => lines.push("• " + (t("action_" + k) || k)));
    lines.push("");
  }
  if (r.links?.length) {
    lines.push(t("linksTitle") + ":");
    r.links.forEach((l) => lines.push(`• ${l.host || ""} (score ${l.score})`));
    lines.push("");
  }
  lines.push(t("disclaimer"));
  lines.push(window.location.href.split("?")[0]);
  return lines.join("\n");
}

async function copyResult() {
  const text = buildResultText();
  if (!text) return;
  try {
    await navigator.clipboard.writeText(text);
    showToast(t("copyOk"));
  } catch (_) {
    showToast(t("shareFail"), true);
  }
}

async function shareResult() {
  const text = buildResultText();
  if (!text) return;
  if (navigator.share) {
    try {
      await navigator.share({
        title: "TRUST AI",
        text,
      });
      showToast(t("shareResultOk"));
      return;
    } catch (err) {
      if (err?.name === "AbortError") return;
    }
  }
  await copyResult();
}

function printResult() {
  window.print();
}

// ── Elderly / large text mode ────────────────────────────────────────────

function initElderly() {
  let on = false;
  try {
    on = localStorage.getItem("trustai_elderly") === "1";
  } catch (_) {}
  document.documentElement.classList.toggle("elderly", on);
}

function toggleElderly() {
  const on = !document.documentElement.classList.contains("elderly");
  document.documentElement.classList.toggle("elderly", on);
  try {
    localStorage.setItem("trustai_elderly", on ? "1" : "0");
  } catch (_) {}
  showToast(on ? t("elderlyOn") : t("elderlyOff"));
}

// ── Sensitive paste warning ──────────────────────────────────────────────

function bindSensitiveWatch() {
  const ta = $("#input-text");
  if (!ta) return;
  const run = () => {
    const hits = detectSensitivePaste(ta.value);
    const box = $("#sensitive-warn");
    if (!box) return;
    if (!hits.length) {
      box.classList.add("hidden");
      box.textContent = "";
      return;
    }
    const map = {
      otp: t("sensitiveWarnOtp"),
      card: t("sensitiveWarnCard"),
      iban: t("sensitiveWarnIban"),
      seed: t("sensitiveWarnSeed"),
      password: t("sensitiveWarnPassword"),
    };
    box.textContent = hits.map((h) => map[h] || "").filter(Boolean).join(" ");
    box.classList.remove("hidden");
  };
  ta.addEventListener("input", run);
  ta.addEventListener("paste", () => setTimeout(run, 30));
}

// ── Usage counter (local, approximate) ───────────────────────────────────

function bumpUsage() {
  try {
    const day = new Date().toISOString().slice(0, 10);
    let data = storageGetJSON(USAGE_KEY, { fallback: { day, count: 0 }, maxBytes: 1000 });
    if (!data || typeof data !== "object" || data.day !== day || !Number.isFinite(data.count)) data = { day, count: 0 };
    data.count = Math.min(1_000_000, data.count + 1);
    storageSetJSON(USAGE_KEY, { day: data.day, count: data.count }, { maxBytes: 1000 });
  } catch (_) {}
}

function getUsageToday() {
  try {
    const day = new Date().toISOString().slice(0, 10);
    const data = storageGetJSON(USAGE_KEY, { fallback: null, maxBytes: 1000 });
    if (!data || typeof data !== "object" || data.day !== day) return 0;
    return Number.isFinite(data.count) ? data.count : 0;
  } catch {
    return 0;
  }
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
  return secEscapeHtml(str);
}



// ── v2 Tools ─────────────────────────────────────────────────────────────

function openFraudDb() {
  showView("fraud-db");
  window.scrollTo({ top: 0, behavior: "smooth" });
  renderFraudStats();
  renderFraudList(listEntities());
  renderScamNumbers("");
  applyTranslations();
}

function renderScamNumbers(q) {
  const box = $("#fraud-numbers");
  if (!box) return;
  const lang = getLang();
  const query = String(q || "").trim();
  const cards = query.length >= 2 ? searchScamNumbers(query) : listScamNumberCards();
  box.innerHTML = cards.length
    ? `<h3 class="pn-section-title">${escapeHtml(lang === "ar" ? "أرقام مشبوهة تتصل من الخارج (نطاقات وأنماط موثّقة)" : "Suspicious foreign callers (documented ranges & patterns)")}</h3>` + renderScamNumberCards(cards, lang)
    : "";
}

function renderFraudStats() {
  const el = $("#fraud-stats");
  if (!el) return;
  const s = getStats();
  const lang = getLang();
  const last = s.lastUpdate
    ? new Date(s.lastUpdate).toLocaleString(lang === "ar" ? "ar" : "en")
    : "—";
  el.innerHTML = `
    <span>${escapeHtml(lang === "ar" ? "كيانات" : "Entities")}: ${s.entities}</span>
    <span>${escapeHtml(lang === "ar" ? "نطاقات" : "Domains")}: ${s.domains}</span>
    <span data-i18n="lastUpdate">${escapeHtml(t("lastUpdate"))}: ${escapeHtml(last)}</span>
  `;
}

function renderFraudList(items, containerId = "fraud-results") {
  const el = document.getElementById(containerId);
  if (!el) return;
  const lang = getLang();
  if (!items.length) {
    el.innerHTML = `<p class="muted">${escapeHtml(t("noResults"))}</p>`;
    return;
  }
  el.innerHTML = items
    .map((e) => {
      const name = (e.names && e.names[0]) || e.id;
      const summary = lang === "ar" ? e.summary_ar : e.summary_en;
      const risk = e.risk || "medium";
      return `<article class="fraud-card">
        <h3>${escapeHtml(name)} <span class="risk-tag ${escapeHtml(risk)}">${escapeHtml(t("risk_" + risk) || risk)}</span></h3>
        <p>${escapeHtml(summary || "")}</p>
        <p class="meta">${escapeHtml(t("sourceLabel"))}: ${(e.sources || [])
          .map((s) => escapeHtml(s.title || s.kind || ""))
          .join(" · ")} · ${escapeHtml(e.updated || "")}</p>
      </article>`;
    })
    .join("");
}

function onFraudSearch() {
  const q = $("#fraud-search")?.value || "";
  const items = q.trim().length >= 2 ? searchEntities(q) : listEntities();
  renderFraudList(items);
  renderScamNumbers(q);
}

async function onFraudUpdate() {
  const statusEl = $("#fraud-update-status");
  const btn = $("#btn-fraud-update");
  if (btn) btn.disabled = true;
  if (statusEl) {
    statusEl.classList.remove("hidden", "ok", "warn", "err");
    statusEl.textContent = t("fraudDbUpdating");
  }
  try {
    const res = await updateDatabase();
    if (statusEl) {
      statusEl.classList.add(
        res.status === "success" ? "ok" : res.status === "partial" ? "warn" : "err"
      );
      statusEl.textContent =
        getLang() === "ar" ? res.message_ar : res.message_en;
    }
    renderFraudStats();
    onFraudSearch();
  } catch (err) {
    if (statusEl) {
      statusEl.classList.add("err");
      statusEl.textContent = t("fraudDbFailed") + ": " + escapeHtml(String(err.message || err));
    }
  } finally {
    if (btn) btn.disabled = false;
  }
}

function openPhoneCheck() {
  showView("phone"); window.scrollTo({ top: 0, behavior: "smooth" });
  const r = $("#phone-result");
  if (r) {
    r.classList.add("hidden");
    r.innerHTML = "";
  }
  applyTranslations();
}

function onPhoneRun() {
  const raw = $("#phone-input")?.value || "";
  const res = checkPhone(raw);
  const el = $("#phone-result");
  if (!el) return;
  el.classList.remove("hidden");
  const lang = getLang();
  if (res.ok && res.profile) {
    el.innerHTML = renderPhoneDossier(res.profile, lang);
    try {
      const p = res.profile;
      saveToHistory("📞 " + p.display + (p.country ? " · " + (lang === "ar" ? p.country.name_ar : p.country.name_en) : ""), {
        score: p.score, level: p.level === "high" ? "severe" : p.level, mode: "offline",
      });
    } catch (_) {}
    return;
  }
  const title = lang === "ar" ? res.title_ar : res.title_en;
  const details = lang === "ar" ? res.details_ar : res.details_en;
  const disc = lang === "ar" ? res.disclaimer_ar : res.disclaimer_en;
  el.innerHTML = `
    <h3 class="risk-tag ${escapeHtml(res.level)}">${escapeHtml(title)}</h3>
    ${res.normalized ? `<p dir="ltr"><code>${escapeHtml(res.normalized)}</code></p>` : ""}
    <ul>${details.map((d) => `<li>${escapeHtml(d)}</li>`).join("")}</ul>
    <p class="meta">${escapeHtml(disc || "")}</p>
  `;
}

function openMeCenter() {
  showView("me"); window.scrollTo({ top: 0, behavior: "smooth" });
  const items = listEntities({ country: "sy" });
  // also include other ME countries
  const more = ["lb", "iq", "jo", "eg", "sa", "ae", "tr", "ps"];
  const merged = [...items];
  const seen = new Set(items.map((e) => e.id));
  for (const c of more) {
    for (const e of listEntities({ country: c })) {
      if (!seen.has(e.id)) {
        merged.push(e);
        seen.add(e.id);
      }
    }
  }
  renderFraudList(merged, "me-results");
  applyTranslations();
}

function onMeSearch() {
  const q = $("#me-search")?.value || "";
  if (q.trim().length >= 2) {
    const all = searchEntities(q);
    const me = all.filter(
      (e) =>
        (e.countries || []).some((c) =>
          ["sy", "lb", "iq", "jo", "eg", "sa", "ae", "tr", "ps", "global"].includes(c)
        )
    );
    renderFraudList(me, "me-results");
  } else {
    openMeCenter();
  }
}

function openQuestnet() {
  showView("questnet"); window.scrollTo({ top: 0, behavior: "smooth" });
  const d = getQuestnetDossier();
  const el = $("#quest-body");
  if (!el) return;
  const lang = getLang();
  const ent = d.entities[0];
  const steps = lang === "ar" ? ent.what_users_should_do_ar : ent.what_users_should_do_en;
  el.innerHTML = `
    <p><em>${escapeHtml(lang === "ar" ? d.methodology_ar : d.methodology_en)}</em></p>
    <p class="meta">${escapeHtml(t("lastUpdate"))}: ${escapeHtml(d.last_reviewed)}</p>
    <h3>${escapeHtml((ent.legal_name_candidates || []).join(" / "))}</h3>
    <p>${escapeHtml(lang === "ar" ? ent.note_ar : ent.note_en)}</p>
    <h3>${escapeHtml(lang === "ar" ? "النشاط" : "Activity")}</h3>
    <p>${escapeHtml(lang === "ar" ? ent.activity_ar : ent.activity_en)}</p>
    <h3>${escapeHtml(lang === "ar" ? "الشرق الأوسط" : "Middle East")}</h3>
    <p>${escapeHtml(lang === "ar" ? ent.middle_east_ar : ent.middle_east_en)}</p>
    <h3>${escapeHtml(lang === "ar" ? "خط زمني" : "Timeline")}</h3>
    <ul>${(ent.timeline || [])
      .map(
        (t) =>
          `<li><strong>${escapeHtml(t.period)}</strong> — ${escapeHtml(lang === "ar" ? t.ar : t.en)}</li>`
      )
      .join("")}</ul>
    <h3>${escapeHtml(lang === "ar" ? "ماذا تفعل؟" : "What should users do?")}</h3>
    <ul>${steps.map((s) => `<li>${escapeHtml(s)}</li>`).join("")}</ul>
    <h3>${escapeHtml(lang === "ar" ? "تمييز الكيانات" : "Distinguishing entities")}</h3>
    <p>${escapeHtml(lang === "ar" ? d.distinctions_ar : d.distinctions_en)}</p>
    <h3>${escapeHtml(lang === "ar" ? "مصادر للمستخدم" : "Sources for the user")}</h3>
    <ul>${(d.sources_for_user || [])
      .map((s) => {
        if (s.url) {
          return `<li><a href="${escapeHtml(s.url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(s.title)}</a></li>`;
        }
        return `<li>${escapeHtml(s.title)}</li>`;
      })
      .join("")}</ul>
  `;
  applyTranslations();
}

function openVictimHelp() {
  showView("victim"); window.scrollTo({ top: 0, behavior: "smooth" });
  const d = getVictimHelp();
  const el = $("#victim-body");
  if (!el) return;
  const lang = getLang();
  const copyLabel = lang === "ar" ? "نسخ" : "Copy";
  const contactsHtml = (d.contacts || [])
    .map((block) => {
      const region = lang === "ar" ? block.region_ar : block.region_en;
      const items = (block.items || [])
        .map((it) => {
          const name = lang === "ar" ? it.name_ar : it.name_en;
          const note = lang === "ar" ? it.note_ar : it.note_en;
          const phone = it.phone_label || it.phone;
          let phoneHtml = "";
          if (it.phone) {
            phoneHtml = `<div class="contact-phone-row" dir="ltr">
              <a class="contact-phone-link" href="tel:${escapeHtml(it.phone)}">${escapeHtml(phone)}</a>
              <button type="button" class="btn-copy-phone" data-copy="${escapeHtml(phone)}" title="${escapeHtml(copyLabel)}" aria-label="${escapeHtml(copyLabel)}">${escapeHtml(copyLabel)}</button>
            </div>`;
          }
          let webHtml = "";
          if (it.web) {
            const label = String(it.web).replace(/^https?:\/\//, "");
            webHtml = `<p class="contact-web"><a href="${escapeHtml(it.web)}" target="_blank" rel="noopener noreferrer">${escapeHtml(label)}</a></p>`;
          }
          return `<div class="contact-item">
            <strong>${escapeHtml(name)}</strong>
            ${phoneHtml}
            ${webHtml}
            <p class="meta">${escapeHtml(note || "")}</p>
          </div>`;
        })
        .join("");
      return `<div class="contact-region">
        <h4>${escapeHtml(region)}</h4>
        ${items}
      </div>`;
    })
    .join("");

  el.innerHTML = `
    <p>${escapeHtml(lang === "ar" ? d.intro_ar : d.intro_en)}</p>
    <ol>${d.steps
      .map((s) => `<li>${escapeHtml(lang === "ar" ? s.ar : s.en)}</li>`)
      .join("")}</ol>
    <h3>${escapeHtml(lang === "ar" ? d.contacts_title_ar : d.contacts_title_en)}</h3>
    <p class="meta">${escapeHtml(lang === "ar" ? d.contacts_note_ar : d.contacts_note_en)}</p>
    <div class="contacts-grid">${contactsHtml}</div>
    <h3>${escapeHtml(lang === "ar" ? "ملاحظات للمنطقة" : "Regional notes")}</h3>
    <p><strong>${escapeHtml(lang === "ar" ? "سوريا" : "Syria")}:</strong> ${escapeHtml(
      lang === "ar" ? d.by_country_notes.sy.ar : d.by_country_notes.sy.en
    )}</p>
    <p><strong>${escapeHtml(lang === "ar" ? "لبنان" : "Lebanon")}:</strong> ${escapeHtml(
      lang === "ar" ? d.by_country_notes.lb.ar : d.by_country_notes.lb.en
    )}</p>
    <p><strong>${escapeHtml(lang === "ar" ? "العراق" : "Iraq")}:</strong> ${escapeHtml(
      lang === "ar" ? d.by_country_notes.iq.ar : d.by_country_notes.iq.en
    )}</p>
    <p>${escapeHtml(lang === "ar" ? d.by_country_notes.default.ar : d.by_country_notes.default.en)}</p>
    <h3>${escapeHtml(lang === "ar" ? "مهم" : "Important")}</h3>
    <ul>${(lang === "ar" ? d.important_ar : d.important_en)
      .map((x) => `<li>${escapeHtml(x)}</li>`)
      .join("")}</ul>
  `;

  // Copy buttons for phone numbers
  el.querySelectorAll(".btn-copy-phone").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const val = btn.getAttribute("data-copy") || "";
      try {
        if (navigator.clipboard && navigator.clipboard.writeText) {
          await navigator.clipboard.writeText(val);
        } else {
          const ta = document.createElement("textarea");
          ta.value = val;
          ta.setAttribute("readonly", "");
          ta.style.position = "fixed";
          ta.style.left = "-9999px";
          document.body.appendChild(ta);
          ta.select();
          document.execCommand("copy");
          document.body.removeChild(ta);
        }
        const ok = lang === "ar" ? "تم النسخ" : "Copied";
        const prev = btn.textContent;
        btn.textContent = ok;
        btn.classList.add("copied");
        setTimeout(() => {
          btn.textContent = prev;
          btn.classList.remove("copied");
        }, 1500);
      } catch {
        /* ignore */
      }
    });
  });

  applyTranslations();
}

function openReport() {
  showView("report"); window.scrollTo({ top: 0, behavior: "smooth" });
  const st = $("#report-status");
  if (st) {
    st.classList.add("hidden");
    st.textContent = "";
  }
  applyTranslations();
}

function onReportSubmit(e) {
  e.preventDefault();
  const name = sanitizeText($("#report-name")?.value || "", 200);
  const url = sanitizeText($("#report-url")?.value || "", 500);
  const phone = sanitizeText($("#report-phone")?.value || "", 30);
  const country = sanitizeText($("#report-country")?.value || "", 80);
  const desc = sanitizeText($("#report-desc")?.value || "", 2000);
  if (!name || !desc) return;
  if (url && !isSafeUrl(url) && url.length > 0) {
    typeof showToast === 'function' ? showToast : (()=>{})(getLang() === "ar" ? "الرابط غير صالح" : "Invalid URL", true);
    return;
  }
  const report = {
    id: "local-" + Date.now(),
    name,
    url: url || null,
    phone: phone || null,
    country: country || null,
    desc,
    at: new Date().toISOString(),
  };
  try {
    const key = "trustai_local_reports";
    const prevRaw = storageGetJSON(key, { fallback: [], maxBytes: 400_000 });
    const prev = Array.isArray(prevRaw) ? prevRaw : [];
    prev.unshift(report);
    storageSetJSON(key, prev.slice(0, 100), { maxBytes: 400_000 });
  } catch {
    /* ignore quota */
  }
  const st = $("#report-status");
  if (st) {
    st.classList.remove("hidden", "err");
    st.classList.add("ok");
    st.textContent = t("reportSaved");
  }
  $("#report-form")?.reset();
  securityLog("local_report_saved", { hasUrl: !!url });
}

