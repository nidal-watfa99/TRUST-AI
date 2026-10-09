/**
 * TRUST AI — Source Report (صفحة تقرير المصدر)
 * Deep, transparent breakdown of a message / link / event:
 * source anatomy, claimed-vs-actual identity, sentence-level risk arc,
 * flow graph and radar chart. Runs fully offline on top of the Risk Engine.
 */
import { analyze, WEIGHTS } from "./risk-engine.js";

const L = {
  ar: {
    title: "تقرير المصدر التفصيلي",
    lead: "كل ما يمكن استنتاجه عن مصدر الخبر أو الرابط أو الحدث — بشفافية، مع بيان ما لا يمكن التحقق منه دون اتصال.",
    verdict: "الخلاصة",
    sourceTitle: "١. هوية المصدر",
    noSource: "لم يُعثر على رابط أو نطاق في المحتوى — المصدر مجهول. غياب المصدر المعلن بحد ذاته نقطة ضعف في المصداقية.",
    anatomy: "تشريح الرابط",
    protocol: "البروتوكول", subdomain: "النطاق الفرعي", domain: "النطاق المسجّل", tld: "اللاحقة", path: "المسار", params: "المعاملات",
    none: "—", secure: "مشفّر (HTTPS)", insecure: "غير مشفّر (HTTP)",
    claimedTitle: "٢. الجهة المُدّعاة مقابل الجهة الفعلية",
    claimed: "الجهة التي تدّعيها الرسالة", actual: "الجهة التي يشير إليها الرابط",
    mismatch: "عدم تطابق: الرسالة تدّعي جهة، والرابط يقود إلى نطاق لا يخصّها.",
    match: "لا يوجد تعارض ظاهر بين الجهة المُدّعاة والنطاق.",
    noClaim: "لا تُسمّي الرسالة جهة معروفة.",
    flagsTitle: "إشارات تقنية على الرابط",
    flag_suspicious_tld: "لاحقة نطاق شائعة في الاحتيال", flag_suspicious_host: "نمط مشبوه في اسم الخادم/المسار",
    flag_brand_spoof: "انتحال علامة تجارية داخل النطاق", flag_many_subdomains: "نطاقات فرعية كثيرة (إخفاء النطاق الحقيقي)",
    flag_long_url: "رابط طويل بشكل غير معتاد", flag_at_symbol: "رمز @ يخفي الوجهة الحقيقية", flag_invalid_url: "رابط غير صالح",
    flag_shortener: "رابط مختصر يخفي الوجهة", flag_ip: "عنوان IP بدل اسم نطاق", flag_punycode: "أحرف مموّهة (Punycode)",
    flag_http: "اتصال غير مشفّر", flag_clean: "لا مؤشرات تقنية ظاهرة (لا يعني أنه آمن)",
    arcTitle: "٣. تسلسل الخبر: خطورة كل جملة",
    arcHint: "كل عمود جملة من النص بترتيبها. الاحتيال غالباً يتصاعد: ادّعاء ← استعجال ← طلب.",
    sentence: "جملة",
    graphTitle: "٤. رسم بياني لمسار الخبر",
    graphHint: "من يدّعي ← ما الرسالة ← إلى أين تقود ← ماذا تطلب منك. لون الخط = درجة الخطر.",
    n_sender: "الجهة المُدّعاة", n_msg: "الرسالة", n_link: "الوجهة", n_ask: "المطلوب منك", n_pressure: "أسلوب الضغط",
    unknownSender: "غير معلن", noLink: "بلا رابط", noAsk: "لا طلب صريح",
    radarTitle: "٥. بصمة المخاطر",
    radarHint: "كلما اتسعت المساحة زاد الخطر؛ الحلقة الخارجية = الحد الأقصى لكل فئة.",
    checkTitle: "٦. ما لا يمكن التحقق منه دون اتصال",
    checkLead: "هذه عناصر تحدد المصداقية فعلاً، ولا يستطيع المحرك المحلي معرفتها. تحقّق منها بنفسك:",
    c1: "عمر النطاق ومالكه (WHOIS)", c1d: "النطاقات المُنشأة حديثاً شائعة في الاحتيال.",
    c2: "سمعة الرابط", c2d: "افحصه في خدمة فحص روابط موثوقة قبل فتحه.",
    c3: "تأكيد الخبر من مصدر ثانٍ مستقل", c3d: "ابحث عن عنوان الخبر في موقع الجهة الرسمي أو وكالة أنباء معروفة.",
    c4: "قناة التواصل الرسمية للجهة", c4d: "تواصل عبر رقم أو تطبيق الجهة نفسها، لا عبر بيانات الرسالة.",
    pending: "غير مُتحقَّق",
    queryTitle: "عبارات بحث مقترحة للتحقق",
    reasonsTitle: "أسباب الحكم",
    low: "منخفض", medium: "متوسط", high: "مرتفع", severe: "شديد", unknown: "غير كافٍ",
    risk: "الخطر",
    back: "العودة للنتيجة", empty: "حلّل رسالة أو رابطاً أولاً لعرض تقرير المصدر.",
    cat: { urgency: "الاستعجال", impersonation: "انتحال الهوية", money: "طلب أموال", sensitive: "بيانات حساسة", link: "الرابط", unrealistic: "عروض خيالية", socialEngineering: "هندسة اجتماعية" },
    ask_money: "دفع / تحويل مال", ask_sensitive: "كلمة مرور / رمز / بطاقة", ask_click: "الضغط على الرابط",
    v_low: "لا تظهر مؤشرات احتيال قوية في المصدر أو المحتوى، لكن تأكد من الخطوات في القسم ٦ قبل الوثوق.",
    v_mid: "توجد إشارات تستدعي الحذر. لا تتفاعل قبل التحقق من الجهة عبر قناتها الرسمية.",
    v_high: "المصدر والمحتوى يحملان مؤشرات احتيال واضحة. لا تضغط ولا تدفع ولا تشارك أي بيانات.",
    v_unknown: "المعلومات غير كافية لإصدار حكم. أضف نصاً أو رابطاً أو فعّل نموذج رؤية لتحليل الصورة.",
  },
  en: {
    title: "Detailed source report",
    lead: "Everything that can be inferred about the source of the news, link or event — transparently, including what cannot be verified offline.",
    verdict: "Bottom line",
    sourceTitle: "1. Source identity",
    noSource: "No link or domain found — the source is unknown. A missing, unnamed source is itself a credibility weakness.",
    anatomy: "Link anatomy",
    protocol: "Protocol", subdomain: "Subdomain", domain: "Registered domain", tld: "TLD", path: "Path", params: "Parameters",
    none: "—", secure: "Encrypted (HTTPS)", insecure: "Unencrypted (HTTP)",
    claimedTitle: "2. Claimed vs. actual entity",
    claimed: "Entity the message claims to be", actual: "Entity the link points to",
    mismatch: "Mismatch: the message claims one entity, but the link leads to a domain that doesn't belong to it.",
    match: "No obvious conflict between the claimed entity and the domain.",
    noClaim: "The message doesn't name a known entity.",
    flagsTitle: "Technical flags on the link",
    flag_suspicious_tld: "TLD common in scams", flag_suspicious_host: "Suspicious pattern in host/path",
    flag_brand_spoof: "Brand impersonation inside the domain", flag_many_subdomains: "Many subdomains (hides real domain)",
    flag_long_url: "Unusually long URL", flag_at_symbol: "@ symbol hides the real destination", flag_invalid_url: "Invalid URL",
    flag_shortener: "URL shortener hides destination", flag_ip: "Raw IP instead of a domain name", flag_punycode: "Disguised characters (Punycode)",
    flag_http: "Unencrypted connection", flag_clean: "No visible technical flags (this does not mean it is safe)",
    arcTitle: "3. Story arc: risk of each sentence",
    arcHint: "Each column is a sentence, in order. Scams usually escalate: claim → urgency → ask.",
    sentence: "Sentence",
    graphTitle: "4. Flow graph of the message",
    graphHint: "Who claims → what the message is → where it leads → what it asks of you. Line colour = risk.",
    n_sender: "Claimed sender", n_msg: "Message", n_link: "Destination", n_ask: "Ask", n_pressure: "Pressure tactic",
    unknownSender: "Not stated", noLink: "No link", noAsk: "No explicit ask",
    radarTitle: "5. Risk fingerprint",
    radarHint: "Larger area = higher risk; the outer ring is each category's maximum.",
    checkTitle: "6. What cannot be verified offline",
    checkLead: "These determine real credibility and the local engine can't know them. Check them yourself:",
    c1: "Domain age and owner (WHOIS)", c1d: "Newly registered domains are common in scams.",
    c2: "Link reputation", c2d: "Scan it with a trusted URL-scanning service before opening.",
    c3: "Confirmation from an independent second source", c3d: "Search the headline on the official site or a known news agency.",
    c4: "The entity's official contact channel", c4d: "Use the entity's own number or app, not details from the message.",
    pending: "Unverified",
    queryTitle: "Suggested search phrases",
    reasonsTitle: "Why this verdict",
    low: "Low", medium: "Medium", high: "High", severe: "Severe", unknown: "Insufficient",
    risk: "Risk",
    back: "Back to result", empty: "Analyze a message or link first to see the source report.",
    cat: { urgency: "Urgency", impersonation: "Impersonation", money: "Money", sensitive: "Sensitive data", link: "Link", unrealistic: "Unrealistic", socialEngineering: "Social eng." },
    ask_money: "Pay / transfer money", ask_sensitive: "Password / code / card", ask_click: "Click the link",
    v_low: "No strong scam signals in the source or content, but complete the checks in section 6 before trusting.",
    v_mid: "Some signals call for caution. Don't engage until you verify the entity through its official channel.",
    v_high: "Source and content carry clear scam indicators. Don't click, pay or share any data.",
    v_unknown: "Not enough information for a verdict. Add text or a link, or connect a vision model to analyze an image.",
  },
};

const SHORTENERS = /(^|\.)(bit\.ly|tinyurl\.com|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|rebrand\.ly|cutt\.ly|shorturl\.at)$/i;
const MULTI_TLD = /\.(co|com|org|net|gov|edu|ac)\.[a-z]{2}$/i;
const BRANDS = {
  apple: "Apple", google: "Google", microsoft: "Microsoft", amazon: "Amazon", paypal: "PayPal",
  facebook: "Facebook", instagram: "Instagram", whatsapp: "WhatsApp", netflix: "Netflix", spotify: "Spotify",
  dhl: "DHL", fedex: "FedEx", ups: "UPS", aramex: "Aramex", smsa: "SMSA",
};
const AR_ENTITIES = [
  [/البنك|بنك/, "البنك", "Bank"], [/وزارة|الحكومة|الجهات الحكومية/, "جهة حكومية", "Government"],
  [/الشرطة|الأمن/, "الشرطة / الأمن", "Police"], [/الضرائب|الزكاة|الجمارك/, "جهة ضريبية/جمركية", "Tax / Customs"],
  [/شركة (ال)?(توصيل|شحن|النقل)/, "شركة شحن", "Courier"], [/الدعم الفني|خدمة العملاء/, "الدعم الفني", "Support"],
];

const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
const COLORS = { low: "#22c55e", medium: "#eab308", high: "#f97316", severe: "#ef4444", unknown: "#94a3b8" };
const lvl = (s) => (s < 0 ? "unknown" : s <= 24 ? "low" : s <= 49 ? "medium" : s <= 74 ? "high" : "severe");

function parseLink(raw) {
  const out = { raw, ok: false, flags: [] };
  try {
    const u = new URL(/^https?:\/\//i.test(raw) ? raw : "https://" + raw);
    const host = u.hostname.toLowerCase();
    const parts = host.split(".");
    const isIp = /^\d{1,3}(\.\d{1,3}){3}$/.test(host);
    const tldLen = MULTI_TLD.test(host) ? 2 : 1;
    const domain = isIp ? host : parts.slice(-(tldLen + 1)).join(".");
    const sub = isIp ? "" : parts.slice(0, -(tldLen + 1)).join(".");
    Object.assign(out, {
      ok: true, host, isIp, domain, sub,
      tld: isIp ? "" : "." + parts.slice(-tldLen).join("."),
      https: u.protocol === "https:",
      path: u.pathname === "/" ? "" : u.pathname,
      params: [...u.searchParams.keys()],
      label: domain.split(".")[0],
    });
    if (SHORTENERS.test(host)) out.flags.push("shortener");
    if (isIp) out.flags.push("ip");
    if (/xn--/.test(host)) out.flags.push("punycode");
    if (!out.https && /^http:\/\//i.test(raw)) out.flags.push("http");
  } catch { out.flags.push("invalid_url"); }
  return out;
}

function detectClaims(text) {
  const found = [];
  const lower = text.toLowerCase();
  for (const [k, name] of Object.entries(BRANDS)) if (lower.includes(k)) found.push({ key: k, ar: name, en: name, brand: true });
  for (const [re, ar, en] of AR_ENTITIES) if (re.test(text) || re.test(en)) found.push({ key: en.toLowerCase(), ar, en });
  const enGeneric = [[/\bbank\b/i, "بنك", "Bank"], [/\b(government|ministry)\b/i, "جهة حكومية", "Government"], [/\bpolice\b/i, "الشرطة", "Police"], [/\b(courier|delivery)\b/i, "شركة شحن", "Courier"], [/\bsupport team\b/i, "الدعم الفني", "Support"]];
  for (const [re, ar, en] of enGeneric) if (re.test(text) && !found.some((f) => f.en === en)) found.push({ key: en.toLowerCase(), ar, en });
  return found;
}

function splitSentences(text) {
  return text.split(/(?<=[.!?؟！\n])\s+|\n+/).map((s) => s.trim()).filter((s) => s.length > 2).slice(0, 14);
}

function askOf(result) {
  const c = result.categories || {};
  const asks = [];
  if (c.money > 0) asks.push("money");
  if (c.sensitive > 0) asks.push("sensitive");
  if (c.link > 0 || (result.links || []).length) asks.push("click");
  return asks;
}

// ── Charts (inline SVG, uses currentColor / CSS vars for theme) ──────────

function arcChart(sentences, s) {
  const scores = sentences.map((x) => Math.max(0, analyze({ text: x }).score));
  if (!sentences.length) return "";
  const W = 560, H = 190, padL = 30, padB = 34, padT = 12;
  const n = scores.length, bw = Math.min(46, (W - padL - 10) / n - 8);
  const step = (W - padL - 10) / n;
  const bars = scores.map((v, i) => {
    const h = (v / 100) * (H - padB - padT);
    const x = padL + i * step + (step - bw) / 2, y = H - padB - h;
    const c = COLORS[lvl(v)];
    return `<g><title>${esc(sentences[i])} — ${v}/100</title>
      <rect x="${x}" y="${y}" width="${bw}" height="${Math.max(h, 2)}" rx="4" fill="${c}" opacity=".9"/>
      <text x="${x + bw / 2}" y="${y - 4}" text-anchor="middle" class="sr-num">${v}</text>
      <text x="${x + bw / 2}" y="${H - padB + 16}" text-anchor="middle" class="sr-axis">${i + 1}</text></g>`;
  }).join("");
  const grid = [0, 25, 50, 75, 100].map((g) => {
    const y = H - padB - (g / 100) * (H - padB - padT);
    return `<line x1="${padL}" x2="${W - 6}" y1="${y}" y2="${y}" class="sr-grid"/><text x="${padL - 6}" y="${y + 3}" text-anchor="end" class="sr-axis">${g}</text>`;
  }).join("");
  const list = sentences.map((x, i) => `<li><b>${i + 1}</b> <span style="color:${COLORS[lvl(scores[i])]}">●</span> ${esc(x.slice(0, 140))}</li>`).join("");
  return `<svg viewBox="0 0 ${W} ${H}" class="sr-svg" role="img" aria-label="${esc(s.arcTitle)}" dir="ltr">${grid}${bars}</svg><ol class="sr-sentences">${list}</ol>`;
}

function radarChart(result, s) {
  const keys = Object.keys(WEIGHTS), n = keys.length, cx = 150, cy = 140, R = 95;
  const pt = (i, r) => { const a = -Math.PI / 2 + (i * 2 * Math.PI) / n; return [cx + r * Math.cos(a), cy + r * Math.sin(a)]; };
  const ring = (f) => keys.map((_, i) => pt(i, R * f).join(",")).join(" ");
  const vals = keys.map((k) => (result.categoryPercents?.[k] || 0) / 100);
  const poly = vals.map((v, i) => pt(i, R * v).join(",")).join(" ");
  const col = COLORS[result.level] || COLORS.unknown;
  const labels = keys.map((k, i) => {
    const [x, y] = pt(i, R + 20);
    const anchor = x < cx - 8 ? "end" : x > cx + 8 ? "start" : "middle";
    return `<text x="${x}" y="${y + 3}" text-anchor="${anchor}" class="sr-axis">${esc(s.cat[k])}</text>`;
  }).join("");
  const spokes = keys.map((_, i) => `<line x1="${cx}" y1="${cy}" x2="${pt(i, R)[0]}" y2="${pt(i, R)[1]}" class="sr-grid"/>`).join("");
  const dots = vals.map((v, i) => { const [x, y] = pt(i, R * v); return `<circle cx="${x}" cy="${y}" r="3.5" fill="${col}"><title>${esc(s.cat[keys[i]])}: ${Math.round(v * 100)}%</title></circle>`; }).join("");
  return `<svg viewBox="0 0 300 285" class="sr-svg sr-radar" role="img" aria-label="${esc(s.radarTitle)}" dir="ltr">
    <polygon points="${ring(1)}" class="sr-ring"/><polygon points="${ring(.66)}" class="sr-ring"/><polygon points="${ring(.33)}" class="sr-ring"/>
    ${spokes}<polygon points="${poly}" fill="${col}" fill-opacity=".28" stroke="${col}" stroke-width="2"/>${dots}${labels}</svg>`;
}

function flowGraph(ctx, s, lang) {
  const { claims, links, result } = ctx;
  const c = result.categories || {}, P = result.categoryPercents || {};
  const asks = askOf(result);
  const col = (pct) => COLORS[lvl(pct)];
  const W = 640, H = 300;
  const node = (x, y, w, h, title, body, color, warn) => `
    <g><rect x="${x}" y="${y}" width="${w}" height="${h}" rx="12" class="sr-node" stroke="${color}" stroke-width="${warn ? 2.5 : 1.5}"/>
    <text x="${x + w / 2}" y="${y + 20}" text-anchor="middle" class="sr-nt">${esc(title)}</text>
    ${body.map((b, i) => `<text x="${x + w / 2}" y="${y + 40 + i * 16}" text-anchor="middle" class="sr-nb" fill="${color}">${esc(b.slice(0, 18))}</text>`).join("")}</g>`;
  const edge = (x1, y1, x2, y2, color, label, dash) => {
    const mx = (x1 + x2) / 2;
    return `<path d="M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}" fill="none" stroke="${color}" stroke-width="3" ${dash ? 'stroke-dasharray="6 5"' : ""} marker-end="url(#arr)" opacity=".85"/>
      ${label ? `<text x="${mx}" y="${(y1 + y2) / 2 - 6}" text-anchor="middle" class="sr-axis">${esc(label)}</text>` : ""}`;
  };
  const senderNames = claims.length ? claims.slice(0, 2).map((x) => x[lang]) : [s.unknownSender];
  const linkNames = links.length ? links.slice(0, 2).map((l) => l.ok ? l.domain : l.raw) : [s.noLink];
  const askNames = asks.length ? asks.map((a) => s["ask_" + a]) : [s.noAsk];
  const pressure = P.urgency || P.socialEngineering ? Math.max(P.urgency || 0, P.socialEngineering || 0) : 0;
  const claimCol = col(P.impersonation || 0), linkPct = P.link || 0, askPct = Math.max(P.money || 0, P.sensitive || 0, links.length ? linkPct : 0);
  const mismatch = ctx.mismatch;
  return `<svg viewBox="0 0 ${W} ${H}" class="sr-svg" role="img" aria-label="${esc(s.graphTitle)}" dir="ltr">
    <defs><marker id="arr" viewBox="0 0 10 10" refX="8" refY="5" markerWidth="7" markerHeight="7" orient="auto"><path d="M0,0 L10,5 L0,10 z" fill="currentColor" opacity=".7"/></marker></defs>
    ${node(10, 110, 120, 80, s.n_sender, senderNames, claims.length ? claimCol : COLORS.unknown, !!(P.impersonation > 50))}
    ${node(190, 110, 120, 80, s.n_msg, [`${s.risk}: ${Math.max(0, result.score)}/100`, s[result.level] || ""], COLORS[result.level] || COLORS.unknown, result.score >= 50)}
    ${node(370, 30, 130, 80, s.n_link, linkNames, links.length ? col(linkPct) : COLORS.unknown, mismatch || linkPct > 50)}
    ${node(370, 190, 130, 80, s.n_pressure, [pressure ? `${pressure}%` : "—"], pressure ? col(pressure) : COLORS.unknown, pressure > 60)}
    ${node(530, 110, 100, 80, s.n_ask, askNames.slice(0, 3), asks.length ? col(askPct) : COLORS.unknown, askPct > 50)}
    ${edge(130, 150, 190, 150, claimCol, "", !claims.length)}
    ${edge(310, 140, 370, 70, links.length ? col(linkPct) : COLORS.unknown, "", !links.length)}
    ${edge(310, 160, 370, 230, pressure ? col(pressure) : COLORS.unknown, "", !pressure)}
    ${edge(500, 70, 530, 140, links.length ? col(linkPct) : COLORS.unknown, "", !links.length)}
    ${edge(500, 230, 530, 160, pressure ? col(pressure) : COLORS.unknown, "", !pressure)}
    ${mismatch ? `<text x="${(130 + 370) / 2}" y="18" text-anchor="middle" fill="${COLORS.severe}" class="sr-nb">⚠ ${lang === "ar" ? "ادّعاء ≠ نطاق" : "claim ≠ domain"}</text>` : ""}
  </svg>`;
}

// ── Main render ──────────────────────────────────────────────────────────

export function renderSourceReport(el, { text, result, lang = "ar" }) {
  const s = L[lang] || L.ar;
  if (!result) { el.innerHTML = `<p class="muted">${s.empty}</p>`; return; }

  const urlRe = /https?:\/\/[^\s<>"']+|(?:www\.)?[a-z0-9][-a-z0-9]*(?:\.[a-z0-9][-a-z0-9]*)*\.[a-z]{2,}(?:\/[^\s]*)?/gi;
  const rawLinks = [...new Set((text.match(urlRe) || []).map((x) => x.replace(/[.,;)\]}،]+$/, "")))].slice(0, 5);
  const links = rawLinks.map(parseLink);
  const claims = detectClaims(text);

  // Merge engine flags into each link
  for (const l of links) {
    const eng = (result.links || []).find((x) => x.host === l.host);
    for (const i of eng?.indicators || []) if (!l.flags.includes(i.code)) l.flags.push(i.code);
  }

  // Claimed vs actual: brand claimed in text but not the registered domain's label
  let mismatch = false;
  const claimedBrands = claims.filter((c) => c.brand);
  for (const l of links) {
    if (!l.ok) continue;
    for (const b of claimedBrands) {
      if (!l.label.includes(b.key) || l.domain !== `${b.key}.com`) {
        if (!/^(www\.)?/.test(l.host)) continue;
        if (l.domain.split(".")[0] !== b.key) mismatch = true;
      }
    }
    if (claims.some((c) => !c.brand) && links.length && !claimedBrands.length && result.categoryPercents?.impersonation >= 50 && (l.flags.includes("suspicious_tld") || l.flags.includes("shortener") || l.flags.includes("ip"))) mismatch = true;
  }

  const sentences = splitSentences(text);
  const verdictKey = result.score < 0 ? "v_unknown" : result.score >= 50 ? "v_high" : result.score >= 25 ? "v_mid" : "v_low";
  const col = COLORS[result.level] || COLORS.unknown;

  const anatomyRow = (k, v) => `<tr><th>${s[k]}</th><td><code>${esc(v || s.none)}</code></td></tr>`;
  const sourceHtml = links.length ? links.map((l) => {
    const flags = l.flags.length ? l.flags : ["clean"];
    return `<div class="sr-link">
      <div class="sr-link-url"><code>${esc(l.raw.slice(0, 90))}</code></div>
      ${l.ok ? `<div class="sr-split" dir="ltr"><span class="sr-seg proto">${l.https ? "https" : "http"}://</span>${l.sub ? `<span class="sr-seg sub">${esc(l.sub)}.</span>` : ""}<span class="sr-seg dom">${esc(l.label)}</span><span class="sr-seg tld">${esc(l.isIp ? "" : l.tld)}</span><span class="sr-seg path">${esc((l.path || "").slice(0, 30))}</span></div>
      <table class="data-table sr-table"><tbody>
        ${anatomyRow("protocol", l.https ? s.secure : s.insecure)}${anatomyRow("subdomain", l.sub)}${anatomyRow("domain", l.domain)}${anatomyRow("tld", l.tld)}${anatomyRow("path", l.path)}${anatomyRow("params", l.params.join(", "))}
      </tbody></table>` : ""}
      <h4 class="sr-h4">${s.flagsTitle}</h4>
      <ul class="sr-flags">${flags.map((f) => `<li class="${f === "clean" ? "ok" : "bad"}">${f === "clean" ? "✓" : "⚠"} ${esc(s["flag_" + f] || f)}</li>`).join("")}</ul>
    </div>`;
  }).join("") : `<p class="muted">${s.noSource}</p>`;

  const claimedHtml = `
    <div class="sr-compare">
      <div class="sr-cmp-box"><span class="sr-cmp-k">${s.claimed}</span><strong>${claims.length ? esc(claims.slice(0, 3).map((c) => c[lang]).join(" · ")) : s.noClaim}</strong></div>
      <div class="sr-cmp-arrow" aria-hidden="true">${mismatch ? "≠" : "→"}</div>
      <div class="sr-cmp-box"><span class="sr-cmp-k">${s.actual}</span><strong dir="ltr">${links.length ? esc(links.map((l) => l.ok ? l.domain : l.raw).join(" · ")) : s.noLink}</strong></div>
    </div>
    ${claims.length && links.length ? `<p class="sr-note ${mismatch ? "bad" : "ok"}">${mismatch ? s.mismatch : s.match}</p>` : ""}`;

  const reasons = (result.reasons || []).map((r) => `<li>${esc(r)}</li>`).join("");
  const queries = [];
  const head = sentences[0] ? sentences[0].slice(0, 60) : "";
  if (links.find((l) => l.ok)) queries.push(`"${links.find((l) => l.ok).domain}" ${lang === "ar" ? "احتيال" : "scam"}`);
  if (head) queries.push(`"${head}" ${lang === "ar" ? "حقيقة أم إشاعة" : "fact check"}`);
  if (claims[0]) queries.push(`${claims[0][lang]} ${lang === "ar" ? "الموقع الرسمي رقم التواصل" : "official website contact"}`);

  const checks = [["c1", "c1d"], ["c2", "c2d"], ["c3", "c3d"], ["c4", "c4d"]].map(([a, b]) => `
    <li><span class="sr-pending">${s.pending}</span><div><strong>${s[a]}</strong><p>${s[b]}</p></div></li>`).join("");

  el.innerHTML = `
    <div class="sr-verdict" style="border-color:${col}">
      <div class="sr-score" style="color:${col}">${result.score < 0 ? "—" : result.score}<small>/100</small></div>
      <div><div class="sr-vlabel" style="color:${col}">${s.verdict} · ${s[result.level] || ""}</div><p>${s[verdictKey]}</p></div>
    </div>

    <section class="result-section"><h3>${s.sourceTitle}</h3>${sourceHtml}</section>
    <section class="result-section"><h3>${s.claimedTitle}</h3>${claimedHtml}</section>
    <section class="result-section"><h3>${s.arcTitle}</h3><p class="muted">${s.arcHint}</p>${arcChart(sentences, s) || `<p class="muted">${s.noSource}</p>`}</section>
    <section class="result-section"><h3>${s.graphTitle}</h3><p class="muted">${s.graphHint}</p>${flowGraph({ claims, links, result, mismatch }, s, lang)}</section>
    <section class="result-section"><h3>${s.radarTitle}</h3><p class="muted">${s.radarHint}</p>${radarChart(result, s)}</section>
    <section class="result-section"><h3>${s.checkTitle}</h3><p class="muted">${s.checkLead}</p><ul class="sr-checks">${checks}</ul>
      ${queries.length ? `<h4 class="sr-h4">${s.queryTitle}</h4><ul class="sr-queries">${queries.map((q) => `<li><code>${esc(q)}</code></li>`).join("")}</ul>` : ""}</section>`;
}
