/**
 * TRUST AI v3.1 — Caller dossier renderer (ملف المتصل)
 * Builds the HTML for a profileNumber() result. Every dynamic value goes through escapeHtml().
 */
import { escapeHtml as esc } from "./security.js";
import { REAL_RISK, IF_DONE, DO_NOW } from "./scam-numbers.js";

const COLOR = { high: "var(--severe)", medium: "var(--medium)", low: "var(--low)", unknown: "var(--text-dim)" };

const T = {
  ar: {
    riskTitle: "تقدير الخطورة", callerTitle: "ماذا نعرف عن المتصل", country: "الدولة", region: "المنطقة", range: "نطاق خاص", format: "الصيغة",
    intl: "دولي", local: "محلي", reports: "بلاغاتك على هذا الجهاز", typesTitle: "أنماط الاحتيال المرتبطة بهذا الرقم", how: "كيف تعمل", wants: "ماذا يريد منك", phrases: "عبارات شائعة",
    indTitle: "المؤشرات", realTitle: "هل يُخترق هاتفي إن رددت؟", doTitle: "افعل الآن", ifTitle: "إن كنتَ قد فعلتَ شيئاً بالفعل", lookTitle: "تحقق إضافي",
    cannot: "ما لا نستطيع معرفته", disc: "هذا مؤشر مبني على أنماط موثّقة علنياً وليس حكماً قاطعاً: معظم أرقام هذه الدول سليمة، والمحتالون قد يزوّرون أرقاماً محلية. لا نكشف هوية أحد ولا نخزّن أرقاماً لأشخاص.",
    levels: { high: "خطر مرتفع", medium: "مشبوه", low: "حذر", unknown: "غير كافٍ للحكم" },
    save: "ابلغ عن الرقم (محلياً)", open: "فتح",
  },
  en: {
    riskTitle: "Risk estimate", callerTitle: "What we know about the caller", country: "Country", region: "Area", range: "Special range", format: "Format",
    intl: "International", local: "Local", reports: "Your reports on this device", typesTitle: "Scam types linked to this number", how: "How it works", wants: "What they want", phrases: "Common phrases",
    indTitle: "Indicators", realTitle: "Does answering hack my phone?", doTitle: "Do this now", ifTitle: "If you already did something", lookTitle: "Extra checks",
    cannot: "What we cannot know", disc: "This is an indicator built on publicly documented patterns, not a verdict: most numbers from these countries are legitimate, and scammers can spoof local numbers. We never reveal anyone's identity and store no individuals' numbers.",
    levels: { high: "High risk", medium: "Suspicious", low: "Caution", unknown: "Not enough to judge" },
    save: "Report this number (locally)", open: "Open",
  },
};

const pick = (lang, ar, en) => (lang === "ar" ? ar : en);

function meter(score, level) {
  const c = COLOR[level] || COLOR.unknown;
  return `<div class="pn-meter" role="img" aria-label="${esc(String(score))}/100">
    <div class="pn-meter-track"><div class="pn-meter-fill" style="width:${Math.max(3, score)}%;background:${c}"></div>
    <i class="pn-tick" style="inset-inline-start:45%"></i><i class="pn-tick" style="inset-inline-start:70%"></i></div>
    <div class="pn-meter-scale"><span>0</span><span>45</span><span>70</span><span>100</span></div></div>`;
}

export function renderPhoneDossier(p, lang = "ar") {
  const u = T[lang] || T.ar;
  const c = COLOR[p.level] || COLOR.unknown;
  const cname = p.country ? pick(lang, p.country.name_ar, p.country.name_en) : "—";
  const rows = [
    [u.format, p.intl ? u.intl : u.local],
    [u.country, p.country ? `+${p.country.code} · ${cname}` : "—"],
  ];
  if (p.region) rows.push([u.region, `+1 ${p.region.area} · ${pick(lang, p.region.name_ar, p.region.name_en)}`]);
  if (p.special) rows.push([u.range, pick(lang, p.special.ar, p.special.en)]);
  if (p.reports) rows.push([u.reports, String(p.reports)]);

  const ind = p.indicators.map((i) => `<li class="pn-ind ${esc(i.level)}"><span>${esc(pick(lang, i.ar, i.en))}</span></li>`).join("");
  const types = p.types.filter((x) => x.id !== "generic_intl" || p.types.length === 1).map((x) => `
    <details class="pn-type ${esc(x.level)}"><summary><strong>${esc(pick(lang, x.title_ar, x.title_en))}</strong></summary>
      <p><b>${esc(u.how)}:</b> ${esc(pick(lang, x.how_ar, x.how_en))}</p>
      <p><b>${esc(u.wants)}:</b> ${esc(pick(lang, x.wants_ar, x.wants_en))}</p>
      ${(pick(lang, x.script_ar, x.script_en) || []).length ? `<p><b>${esc(u.phrases)}:</b></p><ul>${(pick(lang, x.script_ar, x.script_en)).map((s) => `<li>${esc(s)}</li>`).join("")}</ul>` : ""}
    </details>`).join("");
  const ifDone = IF_DONE.map((x) => `<details class="pn-if"><summary>${esc(pick(lang, x.ar, x.en))}</summary><ol>${pick(lang, x.do_ar, x.do_en).map((s) => `<li>${esc(s)}</li>`).join("")}</ol></details>`).join("");
  const look = p.lookups.map((l) => `<a class="pn-look" href="${esc(l.url)}" target="_blank" rel="noopener noreferrer">${esc(pick(lang, l.label_ar, l.label_en))} ↗</a>`).join("");

  return `
  <section class="pn-card" style="--lv:${c}">
    <div class="pn-head"><span class="pn-level" style="background:${c}">${esc(u.levels[p.level] || p.level)}</span><code dir="ltr" class="pn-num">${esc(p.display)}</code></div>
    <h4 class="pn-h">${esc(u.riskTitle)} · <b>${p.score}</b>/100</h4>${meter(p.score, p.level)}
    <h4 class="pn-h">${esc(u.callerTitle)}</h4>
    <dl class="pn-dl">${rows.map(([k, v]) => `<div><dt>${esc(k)}</dt><dd dir="auto">${esc(v)}</dd></div>`).join("")}</dl>
    ${ind ? `<h4 class="pn-h">${esc(u.indTitle)}</h4><ul class="pn-inds">${ind}</ul>` : ""}
    ${types ? `<h4 class="pn-h">${esc(u.typesTitle)}</h4>${types}` : ""}
    <h4 class="pn-h">${esc(u.realTitle)}</h4><p class="pn-real">${esc(pick(lang, REAL_RISK.ar, REAL_RISK.en))}</p>
    <h4 class="pn-h">${esc(u.doTitle)}</h4><ul class="pn-do">${pick(lang, DO_NOW.ar, DO_NOW.en).map((s) => `<li>${esc(s)}</li>`).join("")}</ul>
    <h4 class="pn-h">${esc(u.ifTitle)}</h4>${ifDone}
    <h4 class="pn-h">${esc(u.lookTitle)}</h4><div class="pn-looks">${look}</div>
    <h4 class="pn-h">${esc(u.cannot)}</h4><ul class="pn-cannot">${pick(lang, p.cannot_ar, p.cannot_en).map((s) => `<li>${esc(s)}</li>`).join("")}</ul>
    <p class="meta pn-disc">${esc(u.disc)}</p>
  </section>`;
}

/** Cards used in the fraud-database search (suspicious foreign numbers). */
export function renderScamNumberCards(cards, lang = "ar") {
  const col = (l) => COLOR[l] || COLOR.unknown;
  return cards.map((c) => `<article class="fraud-card pn-range">
    <h3>📞 ${esc(pick(lang, c.title_ar, c.title_en))} <span class="risk-tag ${esc(c.level)}">${esc((T[lang] || T.ar).levels[c.level] || c.level)}</span></h3>
    <p style="border-inline-start:3px solid ${col(c.level)};padding-inline-start:.6rem">${esc(pick(lang, c.desc_ar, c.desc_en))}</p>
  </article>`).join("");
}
