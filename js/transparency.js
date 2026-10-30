/**
 * TRUST AI — Transparency panel («الأدلة وحدود الفحص»)
 * For every result: what evidence was found, WHERE it came from (local rule / AI / web lookup),
 * HOW certain it is, and — just as important — what was NOT checked.
 */
import { analyzeDomain, fetchDomainAge, isNetCheckEnabled, setNetCheckEnabled } from "./domain-intel.js";
import { escapeHtml } from "./security.js";

const T = {
  ar: {
    title: "الأدلة وحدود الفحص",
    lead: "ما الذي وجدناه، ومن أين، وبأي درجة يقين — وما الذي لم نفحصه.",
    found: "ما وجدناه",
    notChecked: "ما لم يُفحص (حدود هذه النتيجة)",
    src: { local: "قاعدة محلية", ai: "ذكاء اصطناعي", web: "بحث خارجي", info: "ملاحظة" },
    cert: { high: "يقين مرتفع", medium: "يقين متوسط", low: "يقين منخفض" },
    cat: { urgency: "لغة استعجال وضغط", impersonation: "انتحال جهة", money: "طلب مال أو تحويل", sensitive: "طلب بيانات حساسة", link: "إشارات في الروابط", unrealistic: "وعود غير واقعية", socialEngineering: "هندسة اجتماعية" },
    lookalike: { homoglyph: "يحاكي اسم «{b}» بحروف مموّهة", typo: "يشبه اسم «{b}» بخطأ إملائي طفيف", combo: "يضيف كلمة خادعة إلى اسم «{b}»", subdomain: "يضع اسم «{b}» في بدايته بينما النطاق الحقيقي لجهة أخرى", other_tld: "يستعمل اسم «{b}» بلاحقة مجانية كثيرة الاستغلال" },
    host: "النطاق",
    official: "النطاق «{d}» يخص «{b}» رسميًا حسب قائمة مدمجة. هذا يؤكد النطاق فقط، ولا يثبت أن الرسالة نفسها صادقة.",
    floor: "رُفعت الدرجة إلى حدّ أدنى ({n}) لأن الرابط يحاكي جهة معروفة؛ هذه الإشارة وحدها كافية للحذر حتى لو بدا النص هادئًا.",
    ipfloor: "رُفعت الدرجة إلى حدّ أدنى ({n}) لأن الرابط يشير إلى عنوان IP مباشر بدل اسم نطاق.",
    aiUsed: "حلّل نموذج ذكاء اصطناعي ({m}) المحتوى. قد يخطئ أو يبالغ في ثقته؛ لا يخفض الدرجة المحلية.",
    age_new: "النطاق «{d}» سُجّل منذ {n} يومًا فقط (حديث جدًا) — مؤشر شائع في مواقع الاحتيال.",
    age_mid: "النطاق «{d}» عمره نحو {n} يومًا (حديث نسبيًا).",
    age_old: "النطاق «{d}» مسجّل منذ {y} (أكثر من سنة). قِدم النطاق لا يعني أنه آمن.",
    nc_noai: "لم يُستخدم الذكاء الاصطناعي: التحليل كله بقواعد محلية.",
    nc_rep: "لم تُقارن الروابط بقواعد بيانات السمعة الحيّة (Safe Browsing وPhishTank وغيرها) — تتطلب خادمًا وسيطًا أو مفتاحًا.",
    nc_page: "لم تُفتح الصفحة خلف الرابط ولم يُفحص محتواها أو شهادتها.",
    nc_age_off: "عمر النطاق لم يُفحص (خيار اختياري أدناه).",
    nc_age_fail: "تعذّر جلب عمر النطاق «{d}» (بعض اللواحق لا تدعم الاستعلام من المتصفح). لا يعني ذلك أنه آمن.",
    nc_img: "الصورة لم تُحلَّل لأن النموذج الحالي لا يدعم الرؤية أو غير مفعّل.",
    nc_final: "النتيجة تقدير احتمالي وليست حكمًا نهائيًا. تحقق دائمًا عبر القناة الرسمية للجهة.",
    none: "لا توجد إشارات خطر بارزة في ما أمكن فحصه — وهذا لا يعني أنه آمن.",
    toggle: "فحص عمر النطاق عبر RDAP (اختياري)",
    toggleHint: "عند التفعيل يُرسَل اسم النطاق فقط (دون نص الرسالة) إلى خدمة rdap.org للحصول على تاريخ التسجيل. معطّل افتراضيًا. تجريبي: قد لا يعمل مع بعض اللواحق.",
    checking: "جارٍ فحص عمر النطاق…",
  },
  en: {
    title: "Evidence & limits",
    lead: "What we found, where it came from, how certain it is — and what we did NOT check.",
    found: "What we found",
    notChecked: "What was not checked (limits of this result)",
    src: { local: "Local rule", ai: "AI", web: "Web lookup", info: "Note" },
    cert: { high: "High certainty", medium: "Medium certainty", low: "Low certainty" },
    cat: { urgency: "Urgency / pressure language", impersonation: "Impersonation", money: "Asks for money or a transfer", sensitive: "Asks for sensitive data", link: "Link signals", unrealistic: "Unrealistic promises", socialEngineering: "Social engineering" },
    lookalike: { homoglyph: "imitates “{b}” with disguised characters", typo: "looks like “{b}” with a small typo", combo: "adds a deceptive word to “{b}”", subdomain: "starts with “{b}” while the real domain belongs to someone else", other_tld: "uses the name “{b}” on a throw-away TLD" },
    host: "Domain",
    official: "“{d}” belongs to “{b}” per a built-in list. This confirms the domain only — not that the message itself is genuine.",
    floor: "Score raised to a minimum ({n}) because a link imitates a known brand; that alone warrants caution even if the text looks calm.",
    ipfloor: "Score raised to a minimum ({n}) because a link points to a raw IP address instead of a domain name.",
    aiUsed: "An AI model ({m}) analysed the content. It can be wrong or over-confident; it cannot lower the local score.",
    age_new: "“{d}” was registered only {n} days ago (very new) — a common sign of scam sites.",
    age_mid: "“{d}” is about {n} days old (fairly new).",
    age_old: "“{d}” has been registered since {y} (over a year). An old domain is not proof of safety.",
    nc_noai: "No AI was used: the whole analysis is local rules.",
    nc_rep: "Links were NOT compared with live reputation databases (Safe Browsing, PhishTank…) — that needs a proxy server or key.",
    nc_page: "The page behind the link was not opened; its content and certificate were not inspected.",
    nc_age_off: "Domain age was not checked (optional setting below).",
    nc_age_fail: "Could not fetch the age of “{d}” (some TLDs do not allow browser lookups). That does not mean it is safe.",
    nc_img: "The image was not analysed because the current model has no vision or is not enabled.",
    nc_final: "The result is a probabilistic estimate, not a final verdict. Always verify through the organisation's official channel.",
    none: "No notable risk signals in what could be checked — that does not mean it is safe.",
    toggle: "Check domain age via RDAP (optional)",
    toggleHint: "When on, only the domain name (never the message text) is sent to rdap.org to get its registration date. Off by default. Experimental: may not work for some TLDs.",
    checking: "Checking domain age…",
  },
};

const fill = (s, o) => s.replace(/\{(\w+)\}/g, (_, k) => (o[k] ?? ""));

/** Pure function: builds the evidence / not-checked lists (testable without a DOM). */
export function buildTransparency({ result, hosts = [], aiAvailable = false, aiVision = false, aiModel = "", lang = "ar", ageResults = {}, netcheck = false } = {}) {
  const s = T[lang] || T.ar;
  const evidence = [];
  const notChecked = [];
  if (!result) return { evidence, notChecked };

  for (const b of result.transparent?.breakdown || []) {
    evidence.push({ text: `${s.cat[b.category] || b.category} — ${b.points}/${b.max}`, source: "local", certainty: b.percentOfMax >= 60 ? "high" : "medium" });
  }

  const brandName = (b) => b.charAt(0).toUpperCase() + b.slice(1);
  for (const h of hosts) {
    const di = analyzeDomain(h);
    for (const f of di.findings) {
      evidence.push({ text: `${s.host} «${di.host}» ${fill(s.lookalike[f.kind] || "", { b: brandName(f.brand) })}`, source: "local", certainty: f.confidence });
    }
    if (di.official) evidence.push({ text: fill(s.official, { d: di.registered, b: brandName(di.official) }), source: "info", certainty: "high" });
    const age = ageResults[di.registered];
    if (age && age.ok) {
      const key = age.ageDays < 30 ? "age_new" : age.ageDays < 365 ? "age_mid" : "age_old";
      evidence.push({ text: fill(s[key], { d: di.registered, n: age.ageDays, y: (age.createdAt || "").slice(0, 4) }), source: "web", certainty: "medium" });
    } else if (age && !age.ok) {
      notChecked.push(fill(s.nc_age_fail, { d: di.registered }));
    }
  }

  const fl = result.transparent?.floor;
  if (fl && fl.applied !== false) evidence.push({ text: fill(fl.kind === "ip_host" ? s.ipfloor : s.floor, { n: fl.min }), source: "local", certainty: "high" });

  if (result.ai) evidence.push({ text: fill(s.aiUsed, { m: aiModel || result.ai.model || "AI" }), source: "ai", certainty: "medium" });
  else notChecked.push(s.nc_noai);

  if (hosts.length) {
    notChecked.push(s.nc_rep, s.nc_page);
    if (!netcheck) notChecked.push(s.nc_age_off);
  }
  if (result.hasImage && !(aiAvailable && aiVision)) notChecked.push(s.nc_img);
  notChecked.push(s.nc_final);
  return { evidence, notChecked };
}

function render(el, data, lang, extraHtml = "") {
  const s = T[lang] || T.ar;
  const ev = data.evidence.length
    ? data.evidence.map((e) => `<li class="tp-item"><span class="tp-src tp-${e.source}">${escapeHtml(s.src[e.source])}</span> ${escapeHtml(e.text)} <em class="tp-cert tp-${e.certainty}">${escapeHtml(s.cert[e.certainty] || "")}</em></li>`).join("")
    : `<li class="tp-item">${escapeHtml(s.none)}</li>`;
  el.innerHTML = `
    <h3>${escapeHtml(s.title)}</h3><p class="muted">${escapeHtml(s.lead)}</p>
    <h4 class="sr-h4">${escapeHtml(s.found)}</h4><ul class="tp-list">${ev}</ul>
    <h4 class="sr-h4">${escapeHtml(s.notChecked)}</h4><ul class="tp-list tp-no">${data.notChecked.map((x) => `<li class="tp-item">⚪ ${escapeHtml(x)}</li>`).join("")}</ul>
    ${extraHtml}`;
}

/** Mount the panel; wires the opt-in domain-age lookup. */
export function mountTransparency(el, ctx) {
  if (!el) return;
  const lang = ctx.lang || "ar";
  const s = T[lang] || T.ar;
  const domains = [...new Set(ctx.hosts.map((h) => analyzeDomain(h).registered).filter(Boolean))].slice(0, 3);
  const ageResults = {};

  const draw = (checking = false) => {
    const nc = isNetCheckEnabled();
    const data = buildTransparency({ ...ctx, ageResults, netcheck: nc });
    const toggle = domains.length ? `
      <label class="tp-toggle"><input type="checkbox" id="tp-netcheck" ${nc ? "checked" : ""}/> ${escapeHtml(s.toggle)}</label>
      <p class="muted tp-hint">${escapeHtml(s.toggleHint)}${checking ? " — " + escapeHtml(s.checking) : ""}</p>` : "";
    render(el, data, lang, toggle);
    el.querySelector("#tp-netcheck")?.addEventListener("change", (e) => { setNetCheckEnabled(e.target.checked); run(); });
  };

  const run = async () => {
    if (!isNetCheckEnabled() || !domains.length) { draw(); return; }
    draw(true);
    await Promise.all(domains.map(async (d) => { ageResults[d] = await fetchDomainAge(d); }));
    draw(false);
  };
  run();
}
