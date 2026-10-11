/**
 * TRUST AI v2 — Suspicious phone number checker
 * Uses public patterns + local reports. Does NOT claim caller identity or exact location.
 */

import {
  escapeHtml,
  sanitizeText,
  normalizePhoneInput,
  rateLimit,
  securityLog,
} from "./security.js";
import { getStats } from "./fraud-db.js";
import { profileNumber } from "./scam-numbers.js";
import { storageGetJSON } from "./security.js";

/** Common country calling codes (subset relevant to MENA + global) */
const CALLING_CODES = [
  { code: "963", iso: "sy", name_ar: "سوريا", name_en: "Syria" },
  { code: "961", iso: "lb", name_ar: "لبنان", name_en: "Lebanon" },
  { code: "964", iso: "iq", name_ar: "العراق", name_en: "Iraq" },
  { code: "962", iso: "jo", name_ar: "الأردن", name_en: "Jordan" },
  { code: "970", iso: "ps", name_ar: "فلسطين", name_en: "Palestine" },
  { code: "972", iso: "il", name_ar: "إسرائيل / فلسطين (972)", name_en: "Israel / Palestine (972)" },
  { code: "90", iso: "tr", name_ar: "تركيا", name_en: "Turkey" },
  { code: "20", iso: "eg", name_ar: "مصر", name_en: "Egypt" },
  { code: "966", iso: "sa", name_ar: "السعودية", name_en: "Saudi Arabia" },
  { code: "971", iso: "ae", name_ar: "الإمارات", name_en: "UAE" },
  { code: "965", iso: "kw", name_ar: "الكويت", name_en: "Kuwait" },
  { code: "974", iso: "qa", name_ar: "قطر", name_en: "Qatar" },
  { code: "973", iso: "bh", name_ar: "البحرين", name_en: "Bahrain" },
  { code: "968", iso: "om", name_ar: "عُمان", name_en: "Oman" },
  { code: "1", iso: "us", name_ar: "الولايات المتحدة / كندا", name_en: "USA / Canada" },
  { code: "44", iso: "gb", name_ar: "المملكة المتحدة", name_en: "United Kingdom" },
  { code: "49", iso: "de", name_ar: "ألمانيا", name_en: "Germany" },
  { code: "33", iso: "fr", name_ar: "فرنسا", name_en: "France" },
  { code: "91", iso: "in", name_ar: "الهند", name_en: "India" },
  { code: "86", iso: "cn", name_ar: "الصين", name_en: "China" },
  { code: "7", iso: "ru", name_ar: "روسيا / كازاخستان", name_en: "Russia / Kazakhstan" },
];

/** Patterns often associated with scam traffic (not proof by themselves) */
const RISK_PATTERNS = [
  {
    id: "premium_rate",
    test: (digits) => /^(900|1900|809|829|849)/.test(digits),
    level: "high",
    ar: "قد يرتبط بأرقام مميزة أو مكلفة.",
    en: "May be associated with premium-rate numbers.",
  },
  {
    id: "very_short",
    test: (digits) => digits.length > 0 && digits.length < 7,
    level: "medium",
    ar: "الرقم قصير جداً — قد يكون غير مكتمل أو رمز خدمة.",
    en: "Number is very short — may be incomplete or a service code.",
  },
  {
    id: "repeated_digits",
    test: (digits) => /(\d)\1{6,}/.test(digits),
    level: "medium",
    ar: "تكرار مفرط للأرقام — نمط شائع في بعض الرسائل الآلية.",
    en: "Excessive digit repetition — common in some automated messages.",
  },
];

function detectCountry(normalized) {
  const digits = normalized.replace(/^\+/, "");
  // Longest prefix match
  const sorted = [...CALLING_CODES].sort((a, b) => b.code.length - a.code.length);
  for (const c of sorted) {
    if (digits.startsWith(c.code)) {
      return { ...c, national: digits.slice(c.code.length) };
    }
  }
  return null;
}

/**
 * Analyze a phone number string.
 * Returns structured result — never invents identity or precise location.
 */
export function checkPhone(rawInput) {
  const rl = rateLimit("phone_check", 30, 60000);
  if (!rl.allowed) {
    return {
      ok: false,
      level: "unknown",
      title_ar: "حد الطلبات",
      title_en: "Rate limited",
      details_ar: ["حاول مرة أخرى بعد دقيقة."],
      details_en: ["Try again in a minute."],
    };
  }

  const normalized = normalizePhoneInput(rawInput);
  if (!normalized || normalized.replace(/\D/g, "").length < 4) {
    return {
      ok: false,
      level: "unknown",
      title_ar: "رقم غير صالح",
      title_en: "Invalid number",
      details_ar: ["أدخل رقماً يحتوي على أرقام كافية مع رمز الدولة إن أمكن."],
      details_en: ["Enter a number with enough digits, preferably with country code."],
    };
  }

  const digits = normalized.replace(/\D/g, "");
  const country = detectCountry(normalized.startsWith("+") ? normalized : "+" + digits);
  const indicators = [];

  for (const p of RISK_PATTERNS) {
    if (p.test(digits)) {
      indicators.push({
        id: p.id,
        level: p.level,
        ar: p.ar,
        en: p.en,
      });
    }
  }

  // Local fraud-db phone hits (if any were stored)
  // (structure ready; seed does not ship private numbers)

  let level = "unknown";
  if (indicators.some((i) => i.level === "high" || i.level === "critical")) level = "high";
  else if (indicators.some((i) => i.level === "medium")) level = "medium";
  else if (country) level = "low"; // known country code only — not "safe"

  const details_ar = [];
  const details_en = [];

  if (country) {
    details_ar.push(`رمز الدولة المحتمل: +${country.code} (${country.name_ar}). قد يكون الرقم مستخدماً عبر تطبيقات إنترنت وليس من الشبكة المحلية.`);
    details_en.push(`Likely country code: +${country.code} (${country.name_en}). The number may be used via internet apps, not the local network.`);
  } else {
    details_ar.push("لم يتم التعرف على رمز دولة معروف من القائمة المدعومة.");
    details_en.push("No recognized country code from the supported list.");
  }

  for (const i of indicators) {
    details_ar.push(i.ar);
    details_en.push(i.en);
  }

  details_ar.push("لا يدّعي هذا الفحص معرفة هوية صاحب الرقم أو موقعه الدقيق.");
  details_en.push("This check does not claim to know the caller's identity or exact location.");

  details_ar.push("معظم عمليات الاحتيال الهاتفي تعتمد على خداع المستخدم وليس على اختراق فوري بمجرد الرد.");
  details_en.push("Most phone scams rely on social engineering, not instant device compromise merely by answering.");

  if (indicators.length === 0) {
    details_ar.push("لا توجد مؤشرات كافية في المصادر المحلية للحكم. تعامل بحذر مع أي طلب مالي أو رمز تحقق.");
    details_en.push("Insufficient local indicators to judge. Treat any request for money or verification codes with caution.");
  }

  // v3.1: caller dossier (foreign-number scam intelligence + this device's own reports)
  let localReports = [];
  try { const r = storageGetJSON("trustai_local_reports", { fallback: [], maxBytes: 400_000 }); if (Array.isArray(r)) localReports = r; } catch (_) {}
  const profile = profileNumber(rawInput, { localReports });
  if (profile.ok) {
    const rank = { unknown: 0, low: 1, medium: 2, high: 3 };
    if ((rank[profile.level] || 0) > (rank[level] || 0)) level = profile.level;
    if (profile.level === "high" && level !== "high") level = "high";
  }

  securityLog("phone_check", { hasCountry: !!country, level, indicators: indicators.length });

  return {
    ok: true,
    level,
    normalized,
    country: country
      ? { code: country.code, iso: country.iso, name_ar: country.name_ar, name_en: country.name_en }
      : null,
    indicators,
    profile: profile.ok ? profile : null,
    title_ar:
      level === "high"
        ? "مؤشرات تستدعي الحذر الشديد"
        : level === "medium"
          ? "مؤشرات تستدعي الحذر"
          : level === "low"
            ? "لا توجد تقارير محلية كافية"
            : "معلومات غير كافية",
    title_en:
      level === "high"
        ? "Indicators warrant high caution"
        : level === "medium"
          ? "Indicators warrant caution"
          : level === "low"
            ? "No sufficient local reports"
            : "Insufficient information",
    details_ar,
    details_en,
    disclaimer_ar: "النتيجة تقديرية بناءً على أنماط عامة وبيانات محلية. ليست حكماً قطعياً.",
    disclaimer_en: "Result is an estimate based on general patterns and local data. Not a definitive judgment.",
  };
}

export function getSupportedCountries() {
  return CALLING_CODES.map((c) => ({
    code: c.code,
    iso: c.iso,
    name_ar: c.name_ar,
    name_en: c.name_en,
  }));
}
