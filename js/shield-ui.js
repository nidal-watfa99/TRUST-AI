/**
 * TRUST AI — Shield status card (حالة الحماية المباشرة)
 * Shows the REAL, observable protection state of the running page.
 * Built with textContent only (no innerHTML) — same rule we ask of the rest of the app.
 */
import { getSecurityReport, APP_VERSION } from "./security.js";
import { getLang } from "./i18n.js";

const S = {
  ar: {
    title: "حالة الحماية المباشرة",
    lead: "فحص ذاتي حيّ لما هو مفعّل فعلاً في هذه الجلسة — بلا ادعاءات مبالغ فيها.",
    rows: {
      https: ["اتصال مشفّر (HTTPS)", "غير مشفّر — افتح التطبيق عبر https"],
      csp: ["سياسة أمان المحتوى (CSP) نشطة", "غير ظاهرة في الصفحة"],
      noInline: ["لا سكربتات مضمّنة (حاجز XSS)", "تم رصد سكربت مضمّن"],
      frame: ["محمي من الإطارات الخادعة (Clickjacking)", "الصفحة داخل إطار — لا تُدخل بياناتك"],
      guard: ["حارس الإطارات يعمل", "حارس الإطارات لم يعمل"],
      sw: ["التخزين دون اتصال (Service Worker)", "غير مفعّل بعد (سيعمل بعد أول تحميل كامل)"],
      storage: ["التخزين المحلي متاح ومُتحقَّق منه", "التخزين المحلي محجوب (وضع خاص؟)"],
      keys: ["مفاتيح API في الذاكرة فقط — وفي الترويسات لا الروابط", ""],
    },
    note: "ملاحظة: ترويسات HTTP الحقيقية (HSTS، frame-ancestors…) تتطلب Cloudflare أو Netlify — راجع SECURITY.md.",
    version: "إصدار الدرع",
  },
  en: {
    title: "Live protection status",
    lead: "A live self-check of what is actually active in this session — no inflated claims.",
    rows: {
      https: ["Encrypted connection (HTTPS)", "Not encrypted — open the app over https"],
      csp: ["Content Security Policy active", "Not detected on the page"],
      noInline: ["No inline scripts (XSS barrier)", "An inline script was detected"],
      frame: ["Protected from clickjacking frames", "Page is inside a frame — do not enter data"],
      guard: ["Frame guard running", "Frame guard did not run"],
      sw: ["Offline cache (Service Worker)", "Not active yet (starts after the first full load)"],
      storage: ["Local storage available & validated", "Local storage blocked (private mode?)"],
      keys: ["API keys kept in memory only — sent in headers, never URLs", ""],
    },
    note: "Note: real HTTP headers (HSTS, frame-ancestors…) need Cloudflare or Netlify — see SECURITY.md.",
    version: "Shield version",
  },
};

function row(ok, label, cls) {
  const li = document.createElement("li");
  li.className = "shield-row " + (ok ? "ok" : cls || "warn");
  const dot = document.createElement("span");
  dot.className = "shield-dot";
  dot.setAttribute("aria-hidden", "true");
  dot.textContent = ok ? "✓" : "!";
  const txt = document.createElement("span");
  txt.textContent = label;
  li.append(dot, txt);
  return li;
}

export function renderShieldStatus() {
  const host = document.getElementById("shield-status");
  if (!host) return;
  const L = S[getLang()] || S.ar;
  const r = getSecurityReport();
  while (host.firstChild) host.removeChild(host.firstChild);

  const h = document.createElement("h3");
  h.textContent = "🛡 " + L.title;
  const p = document.createElement("p");
  p.className = "shield-lead";
  p.textContent = L.lead;

  const ul = document.createElement("ul");
  ul.className = "shield-list";
  const R = L.rows;
  const items = [
    [r.https && r.secureContext, R.https],
    [r.csp, R.csp],
    [r.noInlineScripts, R.noInline],
    [!r.framed, R.frame],
    [r.guard, R.guard],
    [r.serviceWorker, R.sw, "info"],
    [r.storage, R.storage, "info"],
    [true, R.keys],
  ];
  for (const [ok, pair, cls] of items) ul.append(row(!!ok, ok ? pair[0] : pair[1] || pair[0], cls));

  const n = document.createElement("p");
  n.className = "shield-note";
  n.textContent = L.note + "  ·  " + L.version + " " + APP_VERSION;
  host.append(h, p, ul, n);
}
