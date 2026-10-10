/**
 * TRUST AI v2 — Victim help center content
 * Practical steps + official reporting channels.
 * Only well-known public official numbers/links. No invented hotlines.
 * Always prefer verifying on the official website before calling.
 */

import { deepFreeze } from "./security.js";

export const VICTIM_HELP = deepFreeze({
  title_ar: "تعرّضت للاحتيال؟ ماذا أفعل الآن؟",
  title_en: "Were you scammed? What to do now?",
  intro_ar:
    "الخطوات التالية عامة وعملية. لا نعد باسترداد الأموال. تصرّف بسرعة ووثّق كل شيء. تحقّق دائماً من الأرقام على الموقع الرسمي للجهة قبل الاتصال.",
  intro_en:
    "The following steps are general and practical. We do not promise recovery of funds. Act quickly and document everything. Always verify numbers on the agency's official website before calling.",
  steps: [
    {
      id: "stop_contact",
      ar: "أوقف التواصل مع الجهة المشبوهة فوراً. لا ترسل المزيد من الأموال أو الرموز.",
      en: "Stop contact with the suspicious party immediately. Do not send more money or codes.",
    },
    {
      id: "bank",
      ar: "اتصل بالبنك أو مزود الدفع من رقم رسمي (من التطبيق أو خلف البطاقة) واطلب إيقاف أو الاعتراض على العملية إن أمكن.",
      en: "Contact your bank or payment provider using an official number (from the app or back of the card) and request a stop or dispute if possible.",
    },
    {
      id: "passwords",
      ar: "غيّر كلمات المرور من جهاز موثوق، وفعّل المصادقة متعددة العوامل للحسابات المهمة.",
      en: "Change passwords from a trusted device and enable multi-factor authentication on important accounts.",
    },
    {
      id: "evidence",
      ar: "احفظ الإيصالات، لقطات الشاشة، الرسائل، أرقام الحسابات، وروابط المواقع. لا تحذف المحادثات.",
      en: "Save receipts, screenshots, messages, account numbers, and website links. Do not delete conversations.",
    },
    {
      id: "report",
      ar: "أبلغ الجهات المختصة في بلدك ومزود الخدمة (البريد، المنصة، شركة الاتصالات).",
      en: "Report to competent authorities in your country and to the service provider (email, platform, telecom).",
    },
    {
      id: "recovery_scam",
      ar: "احذر من من يعِد باسترداد أموالك مقابل رسوم مقدّمة — غالباً احتيال ثانوي.",
      en: "Beware of anyone promising to recover your money for an upfront fee — often a secondary scam.",
    },
  ],
  contacts_title_ar: "قنوات الإبلاغ الرسمية (محلية ودولية)",
  contacts_title_en: "Official reporting channels (local & international)",
  contacts_note_ar:
    "هذه قنوات عامة موثقة قدر الإمكان. قد تتغيّر الأرقام. في الخطر الفوري اتصل بطوارئ بلدك. لا تعتمد على أرقام واتساب مجهولة تدّعي أنها «رسمية».",
  contacts_note_en:
    "These are publicly documented channels as far as possible. Numbers may change. In immediate danger call your local emergency number. Do not trust unknown WhatsApp numbers claiming to be “official”.",
  contacts: [
    {
      region: "international",
      region_ar: "دولي / عالمي",
      region_en: "International",
      items: [
        {
          name_ar: "FBI — مركز شكاوى جرائم الإنترنت (IC3)",
          name_en: "FBI Internet Crime Complaint Center (IC3)",
          phone: null,
          web: "https://www.ic3.gov",
          note_ar: "بلاغ إلكتروني عن الاحتيال والجرائم عبر الإنترنت (متاح لغير المقيمين أيضاً).",
          note_en: "Online reports for internet-enabled fraud and cybercrime (non-residents can file too).",
        },
        {
          name_ar: "FTC — لجنة التجارة الفيدرالية الأمريكية",
          name_en: "U.S. Federal Trade Commission (FTC)",
          phone: "+1-877-382-4357",
          phone_label: "1-877-FTC-HELP",
          web: "https://reportfraud.ftc.gov",
          note_ar: "بلاغ عن عمليات احتيال للمستهلكين. دعم لغات متعددة (اضغط 3 للمترجم).",
          note_en: "Consumer scam reports. Multiple languages (press 3 for interpreter).",
        },
        {
          name_ar: "FTC — سرقة الهوية",
          name_en: "FTC — Identity theft",
          phone: "+1-877-438-4338",
          phone_label: "1-877-ID-THEFT",
          web: "https://www.identitytheft.gov",
          note_ar: "خطة استرداد مجانية عند سرقة الهوية.",
          note_en: "Free recovery plan for identity theft.",
        },
        {
          name_ar: "المملكة المتحدة — Report Fraud / Action Fraud",
          name_en: "United Kingdom — Report Fraud",
          phone: "+44-300-123-2040",
          phone_label: "0300 123 2040",
          web: "https://www.actionfraud.police.uk",
          note_ar: "إنجلترا وويلز وإيرلندا الشمالية. من الخارج: +44 300 123 2040. اسكتلندا: 101.",
          note_en: "England, Wales & Northern Ireland. From abroad: +44 300 123 2040. Scotland: 101.",
        },
      ],
    },
    {
      region: "sa",
      region_ar: "السعودية",
      region_en: "Saudi Arabia",
      items: [
        {
          name_ar: "الطوارئ",
          name_en: "Emergency",
          phone: "911",
          phone_label: "911 / 999",
          web: null,
          note_ar: "911 في المدن الكبرى، 999 في بقية المناطق — للحالات العاجلة.",
          note_en: "911 in major cities, 999 elsewhere — for urgent cases.",
        },
        {
          name_ar: "كلنا أمن / أبشر — بلاغات الاحتيال والجرائم المعلوماتية",
          name_en: "Kolna Amn / Absher — financial fraud & cyber reports",
          phone: null,
          web: "https://www.absher.sa",
          note_ar: "عبر تطبيق كلنا أمن أو أبشر (خدمات الأمن العام) لبلاغات الاحتيال المالي والجرائم المعلوماتية.",
          note_en: "Via Kolna Amn app or Absher (Public Security services) for financial fraud and cybercrime reports.",
        },
        {
          name_ar: "هيئة الاتصالات — رسائل ومكالمات احتيالية",
          name_en: "CST — scam SMS & calls",
          phone: "330330",
          phone_label: "330330",
          web: "https://www.cst.gov.sa",
          note_ar: "أعد إرسال الرسالة النصية الاحتيالية أو رقم المتصل إلى 330330 مجاناً.",
          note_en: "Forward the scam SMS or caller number to 330330 free of charge.",
        },
        {
          name_ar: "هيئة الأمر بالمعروف — ابتزاز",
          name_en: "Commission for Promotion of Virtue — extortion",
          phone: "1909",
          phone_label: "1909",
          web: null,
          note_ar: "حالات الابتزاز (صور/محادثات) عبر الرقم الموحد 1909.",
          note_en: "Extortion cases (images/chats) via unified number 1909.",
        },
      ],
    },
    {
      region: "ae",
      region_ar: "الإمارات",
      region_en: "United Arab Emirates",
      items: [
        {
          name_ar: "الطوارئ",
          name_en: "Emergency",
          phone: "999",
          phone_label: "999",
          web: null,
          note_ar: "للحالات الطارئة.",
          note_en: "For emergencies.",
        },
        {
          name_ar: "شرطة دبي — غير طارئ",
          name_en: "Dubai Police — non-emergency",
          phone: "901",
          phone_label: "901",
          web: "https://www.dubaipolice.gov.ae",
          note_ar: "بلاغات غير طارئة في دبي؛ يمكن استخدام المنصات الإلكترونية للجرائم الإلكترونية.",
          note_en: "Non-emergency reports in Dubai; electronic platforms available for cybercrime.",
        },
        {
          name_ar: "شرطة أبوظبي — أمان",
          name_en: "Abu Dhabi Police — Aman",
          phone: "8002626",
          phone_label: "800 2626",
          web: null,
          note_ar: "خدمة أمان للإبلاغ عن محاولات الاحتيال في أبوظبي.",
          note_en: "Aman service for reporting scam attempts in Abu Dhabi.",
        },
      ],
    },
    {
      region: "eg",
      region_ar: "مصر",
      region_en: "Egypt",
      items: [
        {
          name_ar: "الطوارئ / الشرطة",
          name_en: "Emergency / Police",
          phone: "122",
          phone_label: "122",
          web: null,
          note_ar: "رقم الشرطة. للجرائم الإلكترونية راجع الإدارة العامة لمباحث الإنترنت عبر القنوات الرسمية.",
          note_en: "Police number. For cybercrime, use official channels of the Internet Investigation department.",
        },
        {
          name_ar: "الجهاز القومي لتنظيم الاتصالات (NTRA)",
          name_en: "NTRA (telecom regulator)",
          phone: null,
          web: "https://www.tra.gov.eg",
          note_ar: "للإبلاغ عن رسائل ومكالمات مزعجة أو احتيالية عبر قنوات الجهاز الرسمية.",
          note_en: "Report nuisance or scam SMS/calls via official NTRA channels.",
        },
      ],
    },
    {
      region: "jo",
      region_ar: "الأردن",
      region_en: "Jordan",
      items: [
        {
          name_ar: "الطوارئ",
          name_en: "Emergency",
          phone: "911",
          phone_label: "911",
          web: null,
          note_ar: "للحالات الطارئة.",
          note_en: "For emergencies.",
        },
        {
          name_ar: "وحدة الجرائم الإلكترونية / الأمن العام",
          name_en: "Cybercrime Unit / Public Security",
          phone: null,
          web: "https://www.psd.gov.jo",
          note_ar: "تقديم الشكوى في أقرب مركز أمني أو وحدة الجرائم الإلكترونية (عمان). احفظ الأدلة الرقمية.",
          note_en: "File at the nearest police station or the Cybercrime Unit (Amman). Preserve digital evidence.",
        },
      ],
    },
    {
      region: "lb",
      region_ar: "لبنان",
      region_en: "Lebanon",
      items: [
        {
          name_ar: "الطوارئ / الشرطة",
          name_en: "Emergency / Police",
          phone: "112",
          phone_label: "112 / 999",
          web: null,
          note_ar: "أبلغ أقرب مخفر أو مكتب مكافحة الجرائم الإلكترونية. احتفظ بنسخ التحويلات.",
          note_en: "Report to the nearest station or cybercrime office. Keep copies of transfers.",
        },
      ],
    },
    {
      region: "iq",
      region_ar: "العراق",
      region_en: "Iraq",
      items: [
        {
          name_ar: "الطوارئ",
          name_en: "Emergency",
          phone: "104",
          phone_label: "104 / 115",
          web: null,
          note_ar: "أبلغ البنك والجهات الأمنية المختصة. لا تتعامل مع وسطاء مجهولين يعدون بالاسترداد.",
          note_en: "Report to the bank and specialized security bodies. Avoid unknown recovery intermediaries.",
        },
      ],
    },
    {
      region: "sy",
      region_ar: "سوريا",
      region_en: "Syria",
      items: [
        {
          name_ar: "الطوارئ المحلية",
          name_en: "Local emergency",
          phone: "112",
          phone_label: "112 / 110",
          web: null,
          note_ar: "وثّق الأدلة جيداً. استخدم القنوات الرسمية المتاحة محلياً عند الإمكان. تحقق من أي رقم قبل الاتصال.",
          note_en: "Document evidence carefully. Use locally available official channels when possible. Verify any number before calling.",
        },
      ],
    },
    {
      region: "other",
      region_ar: "دول أخرى / عامة",
      region_en: "Other / general",
      items: [
        {
          name_ar: "الشرطة / الطوارئ في بلدك",
          name_en: "Your local police / emergency",
          phone: null,
          web: null,
          note_ar: "ابحث عن رقم الطوارئ المحلي (مثل 112 في أوروبا، 999 أو 911 حسب البلد) وموقع الشرطة أو هيئة حماية المستهلك.",
          note_en: "Look up your local emergency number (e.g. 112 in Europe, 999 or 911 by country) and the police or consumer protection website.",
        },
        {
          name_ar: "البنك المركزي / هيئة الرقابة المالية",
          name_en: "Central bank / financial regulator",
          phone: null,
          web: null,
          note_ar: "للإبلاغ عن شركات استثمار أو تداول غير مرخصة — راجع موقع الهيئة الرسمية في بلدك.",
          note_en: "To report unlicensed investment/trading firms — check your country's official regulator website.",
        },
      ],
    },
  ],
  by_country_notes: {
    sy: {
      ar: "في سوريا: وثّق الأدلة جيداً. استخدم القنوات الرسمية المتاحة محلياً للإبلاغ عن الجرائم الإلكترونية عند الإمكان. تحقق من أي رقم أو جهة قبل التواصل.",
      en: "In Syria: document evidence carefully. Use locally available official channels to report cybercrime when possible. Verify any number or entity before contact.",
    },
    lb: {
      ar: "في لبنان: يمكن التواصل مع الجهات الأمنية المختصة بالجرائم الإلكترونية والبنك المعني. احتفظ بنسخ من كل التحويلات.",
      en: "In Lebanon: contact authorities specialized in cybercrime and the relevant bank. Keep copies of all transfers.",
    },
    iq: {
      ar: "في العراق: أبلغ البنك والجهات الأمنية المختصة. لا تتعامل مع وسطاء مجهولين يعدون بالاسترداد.",
      en: "In Iraq: report to the bank and specialized security bodies. Do not deal with unknown intermediaries promising recovery.",
    },
    default: {
      ar: "راجع موقع البنك المركزي أو هيئة حماية المستهلك أو الشرطة في بلدك لمعرفة قنوات الإبلاغ الرسمية.",
      en: "Check your central bank, consumer protection authority, or police website for official reporting channels.",
    },
  },
  important_ar: [
    "لا نشارك أرقام هواتف غير متحقق منها من مصادر عامة موثقة.",
    "لا نضمن استرداد أي مبلغ.",
    "الوقت عامل حاسم في الاعتراض على التحويلات.",
    "تحقّق من الرقم على الموقع الرسمي قبل الاتصال — المحتالون ينتحلون أحياناً أرقام جهات رسمية.",
  ],
  important_en: [
    "We only list numbers verified from documented public official sources.",
    "We do not guarantee recovery of any amount.",
    "Time is critical when disputing transfers.",
    "Verify the number on the official website before calling — scammers sometimes impersonate official numbers.",
  ],
});

export function getVictimHelp() {
  return VICTIM_HELP;
}
