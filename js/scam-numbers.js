/**
 * TRUST AI v3.1 — Suspicious foreign phone numbers (قاعدة الأرقام المشبوهة من الخارج)
 *
 * Pure data + pure functions (no DOM) so it runs offline and is unit-testable.
 *
 * HONESTY RULES (deliberate):
 *  - We do NOT ship a list of individual people's phone numbers: that would be invented data
 *    and would defame whoever really owns those numbers. What is publicly documented by
 *    regulators and carriers (FCC, FTC, Ofcom, Action Fraud, BBB…) are scam TYPES and the
 *    country/area-code RANGES that they are most often seen from — that is what we ship.
 *  - A prefix match is an INDICATOR, never proof. Most numbers from these countries are legitimate,
 *    and scammers can also spoof local numbers. The UI says so every time.
 *  - Answering a call does not by itself "hack" a phone. The real danger is what the caller makes
 *    you do next (say a code, press a key, dial a code, install an app, open a link, call back).
 *    The dossier states this plainly and lists exactly what to do if you already did any of those.
 */

/* ── Country calling codes (longest-prefix match) ──────────────────────── */
// [code, iso, name_ar, name_en]
const C = [
  ["963", "sy", "سوريا", "Syria"], ["961", "lb", "لبنان", "Lebanon"], ["964", "iq", "العراق", "Iraq"],
  ["962", "jo", "الأردن", "Jordan"], ["970", "ps", "فلسطين", "Palestine"], ["972", "il", "إسرائيل / فلسطين (972)", "Israel / Palestine (972)"],
  ["90", "tr", "تركيا", "Turkey"], ["20", "eg", "مصر", "Egypt"], ["966", "sa", "السعودية", "Saudi Arabia"],
  ["971", "ae", "الإمارات", "UAE"], ["965", "kw", "الكويت", "Kuwait"], ["974", "qa", "قطر", "Qatar"],
  ["973", "bh", "البحرين", "Bahrain"], ["968", "om", "عُمان", "Oman"], ["967", "ye", "اليمن", "Yemen"],
  ["218", "ly", "ليبيا", "Libya"], ["216", "tn", "تونس", "Tunisia"], ["213", "dz", "الجزائر", "Algeria"],
  ["212", "ma", "المغرب", "Morocco"], ["249", "sd", "السودان", "Sudan"], ["252", "so", "الصومال", "Somalia"],
  ["222", "mr", "موريتانيا", "Mauritania"], ["224", "gn", "غينيا", "Guinea"], ["225", "ci", "ساحل العاج", "Côte d'Ivoire"],
  ["232", "sl", "سيراليون", "Sierra Leone"], ["233", "gh", "غانا", "Ghana"], ["234", "ng", "نيجيريا", "Nigeria"],
  ["242", "cg", "الكونغو", "Congo"], ["243", "cd", "الكونغو الديمقراطية", "DR Congo"], ["254", "ke", "كينيا", "Kenya"],
  ["255", "tz", "تنزانيا", "Tanzania"], ["257", "bi", "بوروندي", "Burundi"], ["258", "mz", "موزمبيق", "Mozambique"],
  ["27", "za", "جنوب أفريقيا", "South Africa"], ["260", "zm", "زامبيا", "Zambia"], ["263", "zw", "زيمبابوي", "Zimbabwe"],
  ["1", "us", "الولايات المتحدة / كندا", "USA / Canada"], ["44", "gb", "المملكة المتحدة", "United Kingdom"],
  ["49", "de", "ألمانيا", "Germany"], ["33", "fr", "فرنسا", "France"], ["39", "it", "إيطاليا", "Italy"],
  ["34", "es", "إسبانيا", "Spain"], ["31", "nl", "هولندا", "Netherlands"], ["46", "se", "السويد", "Sweden"],
  ["7", "ru", "روسيا / كازاخستان", "Russia / Kazakhstan"], ["380", "ua", "أوكرانيا", "Ukraine"], ["375", "by", "بيلاروسيا", "Belarus"],
  ["91", "in", "الهند", "India"], ["92", "pk", "باكستان", "Pakistan"], ["86", "cn", "الصين", "China"],
  ["852", "hk", "هونغ كونغ", "Hong Kong"], ["62", "id", "إندونيسيا", "Indonesia"], ["84", "vn", "فيتنام", "Vietnam"],
  ["60", "my", "ماليزيا", "Malaysia"], ["63", "ph", "الفلبين", "Philippines"], ["66", "th", "تايلاند", "Thailand"],
  ["855", "kh", "كمبوديا", "Cambodia"], ["856", "la", "لاوس", "Laos"], ["95", "mm", "ميانمار", "Myanmar"],
  ["81", "jp", "اليابان", "Japan"], ["82", "kr", "كوريا الجنوبية", "South Korea"], ["61", "au", "أستراليا", "Australia"],
  ["55", "br", "البرازيل", "Brazil"], ["52", "mx", "المكسيك", "Mexico"], ["57", "co", "كولومبيا", "Colombia"],
];

/** Caribbean / NANP area codes (+1 xxx): look like US numbers but are international and may be billed as such. */
// code: [name_ar, name_en, flaggedByRegulators]
const NANP_CARIBBEAN = {
  242: ["جزر البهاما", "Bahamas", false], 246: ["بربادوس", "Barbados", false], 264: ["أنغويلا", "Anguilla", false],
  268: ["أنتيغوا وباربودا", "Antigua & Barbuda", true], 284: ["جزر العذراء البريطانية", "British Virgin Islands", true],
  345: ["جزر كايمان", "Cayman Islands", false], 441: ["برمودا", "Bermuda", false], 473: ["غرينادا", "Grenada", true],
  649: ["جزر تركس وكايكوس", "Turks & Caicos", true], 664: ["مونتسيرات", "Montserrat", false], 721: ["سانت مارتن", "Sint Maarten", false],
  758: ["سانت لوسيا", "Saint Lucia", false], 767: ["دومينيكا", "Dominica", false], 784: ["سانت فنسنت", "St Vincent", false],
  809: ["جمهورية الدومينيكان", "Dominican Republic", true], 829: ["جمهورية الدومينيكان", "Dominican Republic", true],
  849: ["جمهورية الدومينيكان", "Dominican Republic", true], 868: ["ترينيداد وتوباغو", "Trinidad & Tobago", false],
  869: ["سانت كيتس ونيفيس", "St Kitts & Nevis", false], 876: ["جامايكا", "Jamaica", true],
};

/** Non-geographic / satellite / international-premium ranges: calling back can be very expensive. */
const SPECIAL_RANGES = [
  { re: /^(881|882|883)/, ar: "شبكات دولية غير جغرافية (+881/882/883)", en: "International non-geographic networks (+881/882/883)" },
  { re: /^870/, ar: "اتصالات الأقمار الصناعية (+870 Inmarsat)", en: "Satellite telephony (+870 Inmarsat)" },
  { re: /^878/, ar: "خدمة الأرقام الشخصية العالمية (+878)", en: "Universal personal numbering (+878)" },
  { re: /^979/, ar: "خدمات دولية مرتفعة التكلفة (+979)", en: "International premium-rate services (+979)" },
];

/* ── Scam typologies (publicly documented) ─────────────────────────────── */

export const TYPOLOGIES = {
  wangiri: {
    level: "high",
    title_ar: "احتيال «الرنّة الواحدة» (Wangiri)",
    title_en: "“One-ring” callback scam (Wangiri)",
    how_ar: "يرنّ الهاتف رنّة أو رنّتين ثم يُقطع، لتتصل بالرقم الدولي فتُحتسب عليك مكالمة بتعرفة مرتفعة تذهب لجهة المحتال. أحياناً يترك رسالة صوتية أو SMS «لديك مكالمة فائتة».",
    how_en: "The phone rings once or twice and stops so that you call back; the international premium-rate call is billed to you and the fraudster collects the revenue. Sometimes comes with a voicemail or an SMS saying “missed call”.",
    wants_ar: "أن تعاود الاتصال (المال يأتي من رصيدك/فاتورتك).",
    wants_en: "You calling back (the money comes from your credit/bill).",
    script_ar: ["«مكالمة فائتة» ثم قطع فوراً", "رسالة صوتية قصيرة أو صامتة", "إعادة الرنين من أرقام متقاربة"],
    script_en: ["A missed call that stops instantly", "A short or silent voicemail", "Repeated rings from numbers in the same range"],
  },
  premium: {
    level: "high",
    title_ar: "أرقام دولية مرتفعة التكلفة / أقمار صناعية",
    title_en: "International premium / satellite numbers",
    how_ar: "نطاقات (مثل +881 و+882 و+883 و+870 و+979) قد تكلّف دقيقة الاتصال بها أضعاف المعتاد، ويُستغل ذلك في رنّات تدفعك للاتصال.",
    how_en: "Ranges such as +881/+882/+883/+870/+979 can cost many times the normal rate per minute and are abused to bait callbacks.",
    wants_ar: "أن تتصل أو تردّ فيُسحب رصيدك.",
    wants_en: "You calling or answering so your credit is drained.",
    script_ar: ["رنّة قصيرة من رقم غير مألوف", "رسالة «اتصل بنا بخصوص طرد/جائزة/قريب»"],
    script_en: ["A short ring from an unfamiliar number", "A message like “call us about a parcel/prize/relative”"],
  },
  otp_hijack: {
    level: "high",
    title_ar: "سرقة حساب واتساب / تيليغرام برمز التحقق",
    title_en: "WhatsApp / Telegram account takeover via verification code",
    how_ar: "يتصل أو يراسلك شخص (غالباً بصفة صديق/جهة رسمية/شركة اتصالات) ويطلب «رمزاً من 6 أرقام وصلك بالخطأ». هذا الرمز يمكّنه من تسجيل حسابك على جهازه وسرقته ثم مراسلة جهات اتصالك وطلب المال.",
    how_en: "Someone calls or messages (posing as a friend, an official or your telecom) and asks for a “6-digit code sent to you by mistake”. That code lets them register your account on their device and then message your contacts asking for money.",
    wants_ar: "رمز التحقق (OTP) أو رمز التسجيل بخطوتين.",
    wants_en: "Your OTP / two-step verification code.",
    script_ar: ["«وصلك رمز بالخطأ، أرسله لي»", "«أنا من شركة الاتصالات، أحتاج الرمز لتحديث خطك»", "«رمز تأكيد للفوز بجائزة»"],
    script_en: ["“A code reached you by mistake, send it to me”", "“I’m from your telecom, I need the code to update your line”", "“Confirmation code to claim your prize”"],
  },
  remote_access: {
    level: "high",
    title_ar: "الدعم الفني الوهمي والتحكم عن بُعد (اختراق الجهاز)",
    title_en: "Fake tech-support & remote access (device takeover)",
    how_ar: "يدّعي المتصل أن جهازك مخترق أو أن حسابك البنكي في خطر، ويطلب تثبيت تطبيق تحكم عن بُعد (مثل AnyDesk أو TeamViewer أو QuickSupport). بعد التثبيت يرى شاشتك ويقرأ الرسائل ويحوّل الأموال.",
    how_en: "The caller claims your device is hacked or your bank account is at risk and asks you to install a remote-control app (AnyDesk, TeamViewer, QuickSupport…). Once installed they can see your screen, read messages and move money.",
    wants_ar: "تثبيت تطبيق، أو فتح رابط، أو إعطاء صلاحيات.",
    wants_en: "You installing an app, opening a link or granting permissions.",
    script_ar: ["«جهازك مصاب بفيروس خطير»", "«نحن من الدعم الفني، ثبّت هذا التطبيق»", "«سنؤمّن حسابك، أعطنا رقم الدخول»"],
    script_en: ["“Your device has a serious virus”", "“We’re tech support, install this app”", "“We’ll secure your account, give us the login”"],
  },
  vishing: {
    level: "high",
    title_ar: "انتحال بنك أو شركة اتصالات أو جهة رسمية",
    title_en: "Bank / telecom / official impersonation (vishing)",
    how_ar: "اتصال يدّعي أنه من البنك أو الاتصالات أو الأمن أو الجمارك، يخيفك بتجميد حساب أو غرامة أو طرد محتجز ويطلب بيانات البطاقة أو كلمات المرور أو رموز التحقق أو تحويلاً «لحماية أموالك».",
    how_en: "A call posing as your bank, telecom, police or customs, scaring you with a frozen account, a fine or a held parcel and asking for card details, passwords, codes or a “safe-account” transfer.",
    wants_ar: "بيانات البطاقة، كلمات المرور، رموز التحقق، أو تحويل مالي.",
    wants_en: "Card data, passwords, codes or a money transfer.",
    script_ar: ["«حسابك سيُجمَّد خلال ساعة»", "«هناك عملية مشبوهة، أعطنا الرقم السري»", "«طردك محتجز، ادفع رسوماً»"],
    script_en: ["“Your account will be frozen within an hour”", "“Suspicious transaction — give us your PIN”", "“Your parcel is held, pay a fee”"],
  },
  forwarding: {
    level: "high",
    title_ar: "خدعة رموز تحويل المكالمات (*21* / **21*)",
    title_en: "Call-forwarding code trick (*21* / **21*)",
    how_ar: "يطلب منك المحتال طلب رمز يبدأ بـ *21* أو **21* أو *401* بحجة «اختبار الخط». هذا يحوّل مكالماتك ورسائل التحقق الصوتية إلى رقمه فيسرق حساباتك.",
    how_en: "The caller asks you to dial a code starting with *21*, **21* or *401* “to test your line”. It forwards your calls (and voice OTPs) to their number so they can take over your accounts.",
    wants_ar: "أن تُدخل رمزاً على لوحة الاتصال.",
    wants_en: "You typing a code on your dialer.",
    script_ar: ["«اطلب هذا الرمز لتفعيل العرض/الخدمة»"],
    script_en: ["“Dial this code to activate the offer/service”"],
  },
  prize: {
    level: "medium",
    title_ar: "جوائز ويانصيب وهمي ورسوم مسبقة",
    title_en: "Fake prizes, lotteries & advance fees",
    how_ar: "تُبلَّغ بفوزك بجائزة أو إرث أو منحة، ثم يُطلب منك دفع «رسوم/ضريبة/شحن» أو بيانات هويتك وحسابك لتسلّمها.",
    how_en: "You are told you won a prize, inheritance or grant, then asked to pay a “fee/tax/shipping” or hand over ID and bank details to receive it.",
    wants_ar: "دفعة مقدّمة أو بيانات هوية.",
    wants_en: "An advance payment or ID data.",
    script_ar: ["«مبروك! فزتَ بجائزة كبرى»", "«ادفع رسوم التسليم أولاً»"],
    script_en: ["“Congratulations, you won a big prize!”", "“Pay the delivery fee first”"],
  },
  romance_invest: {
    level: "high",
    title_ar: "علاقات وهمية واستثمار/عملات رقمية عبر واتساب",
    title_en: "Fake relationships & crypto/investment lures on WhatsApp",
    how_ar: "رسالة «خاطئة» ودّية من رقم أجنبي تتحول إلى صداقة أو علاقة ثم تدفعك لاستثمار في منصة وهمية. ترتبط أيضاً بعروض عمل «سهلة» تستدرج الضحايا لمنصات وعمليات احتيال منظّمة.",
    how_en: "A friendly “wrong number” message from a foreign number grows into a friendship or romance, then pushes you into a fake investment platform. Also linked to “easy job” offers that funnel victims into organised fraud.",
    wants_ar: "إيداعات متتالية في منصة وهمية، أو بيانات شخصية.",
    wants_en: "Repeated deposits to a fake platform, or personal data.",
    script_ar: ["«مرحباً، هل هذا فلان؟ آسف، رقم خاطئ»", "«أربح يومياً من هذه المنصة، أريد مساعدتك»", "«وظيفة: قيّم منتجات واربح عمولة»"],
    script_en: ["“Hi, is this John? Sorry, wrong number”", "“I earn daily on this platform, let me help you”", "“Job: rate products and earn commission”"],
  },
  extortion: {
    level: "high",
    title_ar: "ابتزاز وطوارئ مفتعلة («قريبك محتجز»)",
    title_en: "Extortion & fake emergencies (“your relative is in custody”)",
    how_ar: "اتصال يدّعي أن ابنك/قريبك في حادث أو محتجز ويحتاج مالاً فوراً، أو تهديد بنشر صور/بيانات. يعتمد على الذعر وقطع الاتصال بك بأي شخص تتحقق منه.",
    how_en: "A call claiming your child/relative had an accident or is detained and needs money now, or threatening to leak photos/data. Relies on panic and keeping you from checking with anyone.",
    wants_ar: "تحويلاً مالياً عاجلاً.",
    wants_en: "An urgent money transfer.",
    script_ar: ["«ابنك عندنا، حوّل المبلغ الآن»", "«لا تغلق الخط ولا تتصل بأحد»"],
    script_en: ["“We have your son, transfer the money now”", "“Don’t hang up and don’t call anyone”"],
  },
  generic_intl: {
    level: "medium",
    title_ar: "اتصال دولي غير متوقّع",
    title_en: "Unexpected international call",
    how_ar: "لا يوجد نمط محدّد مرتبط بهذا الرمز، لكن الاتصال الدولي غير المتوقع ممّن لا تعرفه يستحق الحذر: أغلب الاحتيال يبدأ بمكالمة أو رسالة من رقم غريب.",
    how_en: "No specific pattern is tied to this code, but an unexpected international call from a stranger deserves caution: most scams start with a call or message from an unknown number.",
    wants_ar: "غير معروف.",
    wants_en: "Unknown.",
    script_ar: [],
    script_en: [],
  },
};

/* Country → typologies most often documented with it (indicator only). */
const WANGIRI_CC = new Set(["216", "222", "224", "225", "232", "233", "234", "242", "243", "252", "257", "258", "260", "263"]);
const MESSAGING_LURE_CC = new Set(["62", "84", "92", "60", "234", "254", "63", "66"]);
const COMPOUND_CC = new Set(["855", "856", "95"]);

const HOME_DEFAULT = "963";

/* ── Helpers ───────────────────────────────────────────────────────────── */

const AR_DIGITS = "٠١٢٣٤٥٦٧٨٩";
const FA_DIGITS = "۰۱۲۳۴۵۶۷۸۹";

/** Normalise any typed number to digits with an optional leading "+" (handles 00 prefix and Arabic digits). */
export function normalizeIntl(raw) {
  let s = String(raw ?? "").trim();
  s = s.replace(/[٠-٩]/g, (d) => String(AR_DIGITS.indexOf(d))).replace(/[۰-۹]/g, (d) => String(FA_DIGITS.indexOf(d)));
  const plus = /^\s*\+/.test(s);
  s = s.replace(/[^\d]/g, "");
  if (!plus && s.startsWith("00")) return { digits: s.slice(2), explicitIntl: true };
  return { digits: s, explicitIntl: plus };
}

function findCountry(digits) {
  const sorted = C.slice().sort((a, b) => b[0].length - a[0].length);
  for (const [code, iso, ar, en] of sorted) if (digits.startsWith(code)) return { code, iso, name_ar: ar, name_en: en, national: digits.slice(code.length) };
  return null;
}

/* ── Main API ──────────────────────────────────────────────────────────── */

/**
 * Build a caller dossier from a number. Never claims identity or exact location.
 * @param {string} raw typed number
 * @param {{homeCc?:string, localReports?:Array}} opts
 */
export function profileNumber(raw, opts = {}) {
  const home = opts.homeCc || HOME_DEFAULT;
  const { digits, explicitIntl } = normalizeIntl(raw);
  if (digits.length < 4) return { ok: false, reason: "short" };

  const indicators = [];
  const typeIds = [];
  const addType = (id) => { if (!typeIds.includes(id)) typeIds.push(id); };
  const flag = (level, ar, en) => indicators.push({ level, ar, en });

  /* special ranges first (only meaningful when written internationally) */
  const special = explicitIntl || !digits.startsWith("0") ? SPECIAL_RANGES.find((r) => r.re.test(digits)) : null;

  let country = null;
  let region = null; // NANP area
  let intl = true;
  if (!special) {
    const cand = digits.startsWith("0") && !explicitIntl ? null : findCountry(digits);
    country = cand;
  }

  if (!explicitIntl && digits.startsWith("0") && !special) {
    // Local format (0xxxxxxxxx): assume the person's own country.
    const hc = C.find((c) => c[0] === home);
    country = hc ? { code: hc[0], iso: hc[1], name_ar: hc[2], name_en: hc[3], national: digits.replace(/^0+/, "") } : null;
    intl = false;
  }

  let score = 0;

  if (special) {
    addType("premium"); addType("wangiri"); score = 80;
    flag("high", `النطاق ${special.ar} — قد تكون تكلفة الاتصال العكسي مرتفعة جداً.`, `Range: ${special.en} — calling back can be extremely expensive.`);
  }

  if (country && country.code === "1") {
    const area = country.national.slice(0, 3);
    const car = NANP_CARIBBEAN[area];
    if (car) {
      region = { area, name_ar: car[0], name_en: car[1] };
      addType("generic_intl");
      if (car[2]) { addType("wangiri"); addType("prize"); score = Math.max(score, 72); flag("high", `رمز المنطقة +1 ${area} يخص ${car[0]}، لا الولايات المتحدة، وهو من النطاقات التي حذّرت منها جهات حماية المستهلك في رنّات الاتصال العكسي.`, `Area code +1 ${area} belongs to ${car[1]}, not the USA, and is among ranges consumer-protection agencies warn about for callback scams.`); }
      else { score = Math.max(score, 48); flag("medium", `رمز المنطقة +1 ${area} يخص ${car[0]} (يبدو كرقم أمريكي لكنه دولي).`, `Area code +1 ${area} is ${car[1]} (looks American but is international).`); }
    } else {
      addType("vishing"); addType("remote_access");
      score = Math.max(score, 35);
      flag("low", "رقم أمريكي/كندي: الخطر الأكبر هنا انتحال الجهات الرسمية والدعم الفني، وقد يكون الرقم مزيّفاً (Spoofing).", "US/Canada number: the main risks are official-impersonation and tech-support scams, and the number may be spoofed.");
    }
  }

  if (country && country.code !== "1" && country.code !== home) {
    const cc = country.code;
    if (WANGIRI_CC.has(cc)) { addType("wangiri"); addType("prize"); addType("otp_hijack"); score = Math.max(score, 70); flag("high", `رمز الدولة +${cc} (${country.name_ar}) ضمن النطاقات التي يكثر ورودها في تحذيرات «الرنّة الواحدة» والاتصال العكسي.`, `Country code +${cc} (${country.name_en}) is among ranges often cited in one-ring/callback warnings.`); }
    if (MESSAGING_LURE_CC.has(cc)) { addType("romance_invest"); addType("otp_hijack"); score = Math.max(score, 62); flag("high", `رمز الدولة +${cc} (${country.name_ar}) يكثر ورود أرقامه في رسائل واتساب الاستدراجية (استثمار/وظائف/علاقات وهمية).`, `Country code +${cc} (${country.name_en}) is frequently reported in WhatsApp lures (investment/jobs/fake relationships).`); }
    if (COMPOUND_CC.has(cc)) { addType("romance_invest"); addType("extortion"); score = Math.max(score, 66); flag("high", `رمز +${cc} (${country.name_ar}) ارتبط بتحذيرات دولية من مراكز احتيال منظّمة تستدرج الضحايا بوظائف واستثمارات وهمية.`, `Code +${cc} (${country.name_en}) is tied to international warnings about organised scam compounds luring victims with fake jobs and investments.`); }
    if (!typeIds.length) { addType("generic_intl"); addType("vishing"); score = Math.max(score, 40); flag("medium", `اتصال دولي من +${cc} (${country.name_ar}). غير مألوف لك؟ تعامل معه كمشبوه حتى تتحقق من هوية المتصل بقناة أخرى.`, `International call from +${cc} (${country.name_en}). Unfamiliar? Treat as suspicious until you verify the caller through another channel.`); }
  }

  if (country && country.code === home && !special) {
    addType("vishing"); addType("otp_hijack");
    score = Math.max(score, 22);
    flag("low", "رقم من بلدك: لا يعني أنه آمن. المحتالون يزوّرون أرقاماً محلية، وينتحلون شركات الاتصالات والبنوك.", "A number from your own country is not automatically safe: scammers spoof local numbers and pose as telecoms and banks.");
  }

  if (!country && !special) {
    addType("generic_intl"); score = Math.max(score, 38);
    flag("medium", "لم يُعرَف رمز الدولة من القائمة. إن كان الرقم دولياً فاحذر.", "Country code not recognised from the supported list. Be careful if it is international.");
  }

  /* generic shape signals */
  if (/(\d)\1{6,}/.test(digits)) { score = Math.max(score, 45); flag("medium", "تكرار مفرط للأرقام — نمط شائع في الاتصالات الآلية.", "Excessive repeated digits — common in automated calling."); }
  if (digits.length > 15) flag("medium", "الرقم أطول من الحد الدولي (15 خانة).", "Number is longer than the international maximum (15 digits).");
  if (digits.length < 7) flag("medium", "الرقم قصير جداً وقد يكون ناقصاً أو رمز خدمة.", "Number is very short and may be incomplete or a service code.");

  /* local reports kept on this device */
  const reports = (opts.localReports || []).filter((r) => r && r.phone && normalizeIntl(r.phone).digits.replace(/^0+/, "").endsWith(digits.replace(/^0+/, "").slice(-8)) && digits.length >= 8);
  if (reports.length) { score = Math.max(score, 85); flag("high", `سبق أن أبلغتَ (${reports.length}) عن هذا الرقم على هذا الجهاز.`, `You reported this number ${reports.length} time(s) on this device.`); }

  score = Math.max(0, Math.min(100, score));
  const level = score >= 70 ? "high" : score >= 45 ? "medium" : score >= 20 ? "low" : "unknown";

  const types = typeIds.map((id) => ({ id, ...TYPOLOGIES[id] }));
  const e164 = "+" + digits.replace(/^0+/, (m) => (explicitIntl ? "" : m));
  const display = explicitIntl || !digits.startsWith("0") ? "+" + digits : raw.toString().trim();
  const q = encodeURIComponent(`"${display}" scam`);

  return {
    ok: true,
    digits, e164, display, intl, explicitIntl,
    country: country ? { code: country.code, iso: country.iso, name_ar: country.name_ar, name_en: country.name_en } : null,
    region, special: special ? { ar: special.ar, en: special.en } : null,
    score, level, indicators, types, reports: reports.length,
    lookups: [
      { id: "google", label_ar: "ابحث عن الرقم في Google", label_en: "Search the number on Google", url: `https://www.google.com/search?q=${q}` },
      { id: "ddg", label_ar: "ابحث في DuckDuckGo", label_en: "Search on DuckDuckGo", url: `https://duckduckgo.com/?q=${q}` },
    ],
    cannot_ar: ["هوية صاحب الرقم الحقيقية", "موقعه الدقيق (قد يكون عبر الإنترنت VoIP أو مزيَّفاً Spoofing)", "ما إذا كان الرقم مُسجَّلاً باسم شخص بريء"],
    cannot_en: ["The real identity of the number's owner", "Their exact location (may be VoIP or spoofed)", "Whether the number is registered to an innocent person"],
  };
}

/* ── Honest "what is the real risk" + what to do ───────────────────────── */

export const REAL_RISK = {
  ar: "الرد على المكالمة وحده لا يخترق هاتفك في العادة. الخطر الحقيقي يبدأ حين يجعلك المتصل تفعل شيئاً: تقول رمز تحقق، تضغط رقماً، تطلب رمزاً على لوحة الاتصال، تثبّت تطبيقاً، تفتح رابطاً، أو تعاود الاتصال برقم مرتفع التكلفة.",
  en: "Merely answering a call does not normally hack your phone. The real danger starts when the caller gets you to DO something: read out a code, press a key, dial a code, install an app, open a link, or call back a premium number.",
};

export const IF_DONE = [
  { k: "code", ar: "أعطيتَ رمز تحقق (واتساب/تيليغرام/بنك):", en: "You gave a verification code (WhatsApp/Telegram/bank):", do_ar: ["افتح التطبيق فوراً وفعّل «التحقق بخطوتين» وسجّل خروج كل الأجهزة", "أبلغ جهات اتصالك أن حسابك قد يُستخدم لطلب المال", "اتصل بالبنك لتجميد أي عملية إن كان الرمز بنكياً"], do_en: ["Open the app now, enable two-step verification and log out all devices", "Warn your contacts the account may be used to ask for money", "Call your bank to freeze activity if it was a bank code"] },
  { k: "app", ar: "ثبّتَ تطبيقاً بطلب المتصل (AnyDesk وغيره):", en: "You installed an app at the caller's request (AnyDesk etc.):", do_ar: ["فعّل وضع الطيران وافصل الإنترنت فوراً", "احذف التطبيق من الإعدادات ← التطبيقات", "غيّر كلمات مرور البريد والبنك من جهاز آخر نظيف", "إن لم تثق بالجهاز: إعادة ضبط المصنع بعد نسخ احتياطي للصور فقط"], do_en: ["Enable airplane mode / cut the internet now", "Uninstall it from Settings → Apps", "Change email and bank passwords from a different clean device", "If unsure: factory reset after backing up photos only"] },
  { k: "dial", ar: "طلبتَ رمزاً يبدأ بـ *21* أو **21*:", en: "You dialled a code starting with *21* or **21*:", do_ar: ["اطلب ##21# لإلغاء تحويل المكالمات", "تحقق من الإعدادات ← المكالمات ← تحويل المكالمات", "اتصل بشركة الاتصالات للتأكد من إلغائه"], do_en: ["Dial ##21# to cancel call forwarding", "Check Settings → Calls → Call forwarding", "Call your carrier to confirm it was removed"] },
  { k: "callback", ar: "عاودتَ الاتصال أو ضغطتَ رقماً:", en: "You called back or pressed a key:", do_ar: ["راجع رصيدك/فاتورتك فوراً", "اتصل بشركة الاتصالات وأبلغ عن الرقم واطلب حظر المكالمات الدولية المرتفعة", "لا تعاود الاتصال مرة أخرى"], do_en: ["Check your credit/bill right away", "Call your carrier, report the number and ask to block premium international calls", "Do not call back again"] },
  { k: "money", ar: "حوّلتَ مالاً:", en: "You transferred money:", do_ar: ["اتصل بالبنك/المحفظة فوراً واطلب إيقاف أو استرجاع الحوالة", "احتفظ بلقطات شاشة وأرقام العمليات", "قدّم بلاغاً رسمياً لدى الجهات المختصة في بلدك"], do_en: ["Call your bank/wallet immediately and ask to stop or recall the transfer", "Keep screenshots and transaction IDs", "File an official report with the authorities in your country"] },
];

export const DO_NOW = {
  ar: ["لا تردّ ولا تعاود الاتصال برقم دولي لا تعرفه", "لا تعطِ أي رمز وصلك برسالة أو مكالمة لأي أحد مهما ادّعى", "لا تثبّت أي تطبيق ولا تفتح أي رابط بطلب من متصل", "أنهِ المكالمة وتحقق من الجهة بالاتصال بالرقم الرسمي المنشور على موقعها", "احظر الرقم وأبلغ شركة الاتصالات"],
  en: ["Don't answer or call back an unknown international number", "Never give a code you received by SMS or call to anyone, whatever they claim", "Don't install apps or open links at a caller's request", "Hang up and verify the organisation via its officially published number", "Block the number and report it to your carrier"],
};

/* ── Search support (for the fraud-database search box) ─────────────────── */

/** Browsable cards: one per documented scam type, plus one per flagged range. */
export function listScamNumberCards() {
  const cards = [];
  const mk = (id, title_ar, title_en, desc_ar, desc_en, level, tags) => cards.push({ id, title_ar, title_en, desc_ar, desc_en, level, tags: tags.join(" ").toLowerCase() });
  mk("rng-wangiri", "رنّات الاتصال العكسي من أفريقيا والكاريبي", "Callback (one-ring) ranges: Africa & Caribbean",
    `رموز دول يكثر ورودها في تحذيرات الرنّة الواحدة: ${[...WANGIRI_CC].map((c) => "+" + c).join("، ")}. ومن الكاريبي (تبدو أمريكية): ${Object.entries(NANP_CARIBBEAN).filter(([, v]) => v[2]).map(([k]) => "+1 " + k).join("، ")}.`,
    `Country codes often cited in one-ring warnings: ${[...WANGIRI_CC].map((c) => "+" + c).join(", ")}. Caribbean (look American): ${Object.entries(NANP_CARIBBEAN).filter(([, v]) => v[2]).map(([k]) => "+1 " + k).join(", ")}.`,
    "high", ["wangiri", "callback", "رنة", "عكسي", ...WANGIRI_CC, ...Object.keys(NANP_CARIBBEAN)]);
  mk("rng-premium", "نطاقات دولية/أقمار صناعية مرتفعة التكلفة", "Premium / satellite ranges",
    "+881 و+882 و+883 و+870 و+878 و+979: قد تكون كلفة الدقيقة عالية جداً. لا تعاود الاتصال بها.", "+881, +882, +883, +870, +878, +979: per-minute cost can be very high. Do not call back.",
    "high", ["881", "882", "883", "870", "878", "979", "premium", "satellite", "قمر", "مكلف"]);
  mk("rng-messaging", "أرقام واتساب الاستدراجية (استثمار/وظائف/علاقات)", "WhatsApp lure numbers (investment/jobs/romance)",
    `رموز يكثر ورودها في الرسائل الاستدراجية: ${[...MESSAGING_LURE_CC, ...COMPOUND_CC].map((c) => "+" + c).join("، ")}.`, `Codes frequently reported in lure messages: ${[...MESSAGING_LURE_CC, ...COMPOUND_CC].map((c) => "+" + c).join(", ")}.`,
    "high", ["whatsapp", "واتساب", "investment", "استثمار", "job", "وظيفة", "romance", ...MESSAGING_LURE_CC, ...COMPOUND_CC]);
  for (const [id, ty] of Object.entries(TYPOLOGIES)) {
    if (id === "generic_intl") continue;
    mk("ty-" + id, ty.title_ar, ty.title_en, ty.how_ar, ty.how_en, ty.level, [id, ty.title_ar, ty.title_en, ...ty.script_ar, ...ty.script_en]);
  }
  return cards;
}

/** Search the cards by number prefix, country name, scam type or Arabic/English keyword. */
export function searchScamNumbers(query) {
  const raw = String(query ?? "").trim().toLowerCase();
  if (raw.length < 2) return [];
  const { digits } = normalizeIntl(raw);
  const cards = listScamNumberCards();
  const words = raw.split(/\s+/).filter(Boolean);
  const byText = cards.filter((c) => words.every((w) => c.tags.includes(w) || c.title_ar.includes(w) || c.title_en.toLowerCase().includes(w) || c.desc_ar.includes(w)));
  if (digits.length >= 2 && /^[+\d\s٠-٩()-]+$/.test(raw)) {
    const variants = [digits, ...(digits.startsWith("1") && digits.length > 3 ? [digits.slice(1)] : [])];
    const prefix = cards.filter((c) => c.id.startsWith("rng-") && c.tags.split(" ").some((t) => /^\d+$/.test(t) && variants.some((d) => d.startsWith(t) || (d.length >= 2 && t.startsWith(d)))));
    const p = digits.length >= 4 ? profileNumber(raw) : { ok: false };
    const ids = new Set(p.ok ? p.types.map((t) => "ty-" + t.id) : []);
    const typed = cards.filter((c) => ids.has(c.id));
    return [...new Map([...prefix, ...typed, ...byText].map((c) => [c.id, c])).values()];
  }
  return byText;
}
