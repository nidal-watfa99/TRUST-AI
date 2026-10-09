/**
 * TRUST AI Risk Engine v1.2
 * Rule-based offline analysis — works fully without any API key.
 * Strong detection for pyramid / network marketing schemes (QuestNet style).
 * Transparent scoring 0–100 with category breakdown.
 * Arabic + English pattern libraries.
 */

export const WEIGHTS = {
  urgency: 14,
  impersonation: 18,
  money: 18,
  sensitive: 18,
  link: 12,
  unrealistic: 8,
  socialEngineering: 6,
  pyramid: 22,   // وزن عالي جداً للتسويق الهرمي
};

export const LEVELS = {
  low:      { min: 0,  max: 24, key: "low",      color: "#22c55e" },
  medium:   { min: 25, max: 49, key: "medium",   color: "#eab308" },
  high:     { min: 50, max: 74, key: "high",     color: "#f97316" },
  severe:   { min: 75, max: 100, key: "severe",  color: "#ef4444" },
  unknown:  { min: -1, max: -1, key: "unknown",  color: "#94a3b8" },
};

// ── Pattern libraries ────────────────────────────────────────────────────

const URGENCY_PATTERNS = [
  /تصرف\s*(الآن|فوراً|فورًا)/i,
  /مطلوب\s*(إجراء|اجراء)\s*فوري/i,
  /حسابك.*?(سيتم|سوف|راح).*?(إغلاق|اغلاق|تعليق|قفل)/i,
  /لديك\s*\d+\s*(دقائق|دقيقة|ساعات|ساعة)\s*فقط/i,
  /آخر\s*فرصة/i,
  /يجب\s*(التأكيد|التفعيل|التحقق)\s*فوراً/i,
  /عاجل\s*جداً/i,
  /انته[تة]\s*المهلة/i,
  /خلال\s*\d+\s*(ساعة|ساعات|دقيقة|دقائق)/i,
  /فوراً|فورًا/i,
  /الآن\s*(وإلا|قبل|أو)/i,
  /act\s*(now|immediately)/i,
  /immediate\s*action\s*required/i,
  /your\s*account\s*(will\s*be|is\s*being)\s*(closed|suspended|locked)/i,
  /you\s*have\s*(only\s*)?\d+\s*(minutes?|hours?)\s*(left|remaining)/i,
  /last\s*chance/i,
  /confirm\s*immediately/i,
  /urgent\s*(action|response|attention)/i,
  /within\s*\d+\s*(hours?|minutes?)/i,
  /expires?\s*(soon|today|in)/i,
  /limited\s*time/i,
  /respond\s*(now|immediately|asap)/i,
];

const IMPERSONATION_PATTERNS = [
  /(?:من\s*)?(?:البنك|بنك\s+\S+)/i,
  /(?:ال)?حكومة|وزارة|الجه[ةا]ت?\s*الحكومية/i,
  /شركة\s*(?:ال)?(?:توصيل|شحن|النقل)/i,
  /(?:ال)?شرطة|الأمن\s*(?:العام|الوطني)/i,
  /جهة\s*قانونية|محام[يى]|القضاء/i,
  /صاحب\s*(?:العمل|الشركة)|المدير\s*العام/i,
  /(?:دعم|خدمة)\s*(?:فني|العملاء|العميل)/i,
  /(?:Apple|Google|Microsoft|Meta|Facebook|Instagram|WhatsApp|Amazon|PayPal|Netflix|Spotify)/i,
  /(?:bank|government|ministry|police|delivery|courier|support\s*team|legal\s*(?:department|team))/i,
  /this\s*is\s*(?:official|from\s*(?:the\s*)?(?:bank|government|police))/i,
  /(?:we\s*are\s*from|representing)\s*(?:your\s*)?(?:bank|provider)/i,
  /(?:DHL|FedEx|UPS|Aramex|SMSA)/i,
  /(?:الضرائب|الزكاة|الجمارك)/i,
  /(?:IRS|tax\s*(?:office|authority)|customs)/i,
];

const MONEY_PATTERNS = [
  /تحويل\s*(?:الأموال|مبلغ|مالي)/i,
  /(?:ادفع|دفع)\s*(?:رسوم|مبلغ|مقدم|عمولة)/i,
  /بطاقات?\s*(?:الهدايا|الائتمان)/i,
  /(?:عملات?\s*رقمية|بيتكوين|USDT|crypto)/i,
  /تحويل\s*بنكي/i,
  /دفع\s*(?:مقابل|للحصول\s*على)\s*(?:جائزة|وظيفة|عرض)/i,
  /أرسل\s*(?:المال|المبلغ|النقود)/i,
  /رسوم\s*(?:التخليص|التسجيل|الشحن)/i,
  /(?:send|transfer|wire)\s*(?:money|funds|payment)/i,
  /(?:pay|payment\s*(?:of|for))\s*(?:fee|fees|deposit|advance)/i,
  /gift\s*cards?/i,
  /(?:bitcoin|crypto|USDT|cryptocurrency|BTC|ETH)/i,
  /bank\s*transfer/i,
  /(?:pay|send)\s*(?:to\s*)?(?:claim|receive)\s*(?:prize|job|offer)/i,
  /(?:western\s*union|moneygram|paypal)/i,
];

const SENSITIVE_PATTERNS = [
  /(?:كلمة|كود)\s*(?:المرور|السر|التحقق)/i,
  /(?:رقم|أرقام)\s*(?:البطاقة|الائتمان|الحساب)/i,
  /(?:CVV|CVC|تاريخ\s*الانتهاء)/i,
  /(?:رقم\s*الهوية|رقم\s*الوطني|رقم\s*الإقامة)/i,
  /(?:password|passwd|passcode)/i,
  /(?:OTP|one[- ]time\s*(?:password|code|pin)|verification\s*code)/i,
  /(?:credit\s*card|card\s*number|account\s*number)/i,
  /(?:CVV|CVC|expiry|expiration\s*date)/i,
  /(?:SSN|social\s*security|national\s*ID|passport\s*number)/i,
  /(?:PIN|pin\s*code)/i,
  /أرسل\s*(?:رمز|كود)/i,
  /share\s*(?:your\s*)?(?:code|password|pin)/i,
];

const UNREALISTIC_PATTERNS = [
  /(?:فزت|ربحت|جائزة)\s*(?:كبرى|ضخمة|مليون)/i,
  /أرباح\s*(?:مضمونة|سريعة|خالية\s*من\s*المخاطر)/i,
  /(?:راتب|مرتب)\s*(?:ضخم|خيالي|مرتفع\s*جداً)/i,
  /بدون\s*(?:خبرة|مؤهلات|مقابلة)/i,
  /(?:you\s*(?:won|have\s*won)|congratulations.*(?:winner|prize))/i,
  /guaranteed\s*(?:profit|returns|income)/i,
  /(?:huge|massive|incredible)\s*(?:salary|earnings|prize)/i,
  /no\s*(?:experience|qualifications|interview)\s*required/i,
  /(?:make|earn)\s*\$?\d+[kK]?\s*(?:per|a)\s*(?:day|week|month)/i,
  /(?:100%|fully)\s*(?:guaranteed|risk[- ]free)/i,
  /وراثة\s*(?:من|غير\s*معروفة)/i,
  /inheritance\s*(?:from|unclaimed)/i,
];

const SOCIAL_ENGINEERING_PATTERNS = [
  /لا\s*(?:تخبر|تُخبر|تبلغ)\s*(?:أحد|أحداً|أي\s*شخص)/i,
  /(?:سري|سرية)\s*(?:جداً|تامة)/i,
  /تجنب\s*(?:الاتصال|التواصل)\s*(?:بالبنك|بالشركة)/i,
  /هذا\s*(?:بيننا|خاص)/i,
  /(?:don't|do\s*not)\s*(?:tell|inform|share\s*with)\s*(?:anyone|anybody)/i,
  /(?:keep\s*(?:this\s*)?(?:secret|confidential)|between\s*us)/i,
  /(?:avoid|don't)\s*(?:calling|contacting)\s*(?:the\s*)?(?:bank|company|support)/i,
  /(?:this\s*is\s*)?(?:private|confidential)\s*(?:matter|conversation)/i,
  /حذف\s*(?:هذه|الرسالة)\s*بعد/i,
  /delete\s*(?:this|the)\s*(?:message|chat)\s*after/i,
];

// ===== أنماط قوية ضد التسويق الهرمي (مستمدة من وصف QuestNet) =====
const PYRAMID_PATTERNS = [
  // شرط تجنيد 3 أشخاص
  /(?:ادعُ|ادعو|يجب\s*أن\s*(?:تجند|تحضر|تجيب|تجمع)|شرط).{0,50}(?:3|ثلاثة|ثلاث)\s*(?:أشخاص|شخص|أفراد|من\s*(?:أهلك|عائلتك|أصدقائك))/i,
  /كل\s*(?:شخص|عضو).{0,30}(?:يجب|لازم|يشترط).{0,30}(?:يدخل|يجند|يحضر).{0,20}(?:3|ثلاثة)/i,
  /(?:تجند|تحضر|تجيب).{0,25}(?:3|ثلاثة)\s*(?:من\s*)?(?:أهلك|عائلتك|أصدقائك|معارفك)/i,

  // مبلغ التسجيل المرتفع
  /(?:مبلغ|رسوم|تكلفة|قيمة)\s*(?:التسجيل|الانضمام|الاشتراك|العضوية).{0,40}(?:1500|1600|1650|1700|1800|2000|\$\s*1[5-9]\d{2}|\$\s*2\d{3})/i,
  /(?:ادفع|دفع|تسديد|مطلوب).{0,25}(?:1650|1500|1600|2000)\s*(?:دولار|\$|دولار أمريكي)/i,

  // السرية التامة
  /(?:سرية|كتمان|لا\s*تخبر|لا\s*تبوح|ممنوع\s*(?:التكلم|الإخبار)).{0,50}(?:حتى|ولو).{0,30}(?:أهلك|عائلتك|أقرب\s*الناس|أقرب\s*المقربين|زوجتك)/i,
  /(?:لا\s*تخبر|لا\s*تُخبر|ممنوع\s*إخبار).{0,40}(?:أحد|أي\s*شخص|حتى\s*(?:أهلك|زوجتك|إخوتك))/i,

  // وعود ثراء سريع
  /(?:ثراء|غني|مليونير|ثري|ثروتك).{0,40}(?:خلال|في)\s*(?:أشهر|شهور|3\s*أشهر|6\s*أشهر|سنة|وقت\s*قصير)/i,
  /(?:غير\s*حياتك|اقلب\s*حياتك|تصبح\s*ثرياً|أصبحت\s*ثرياً).{0,40}(?:خلال|في)\s*(?:أشهر|شهور)/i,
  /دخل\s*(?:سلبي|مضمون|خالي\s*من\s*المخاطر|بدون\s*جهد|بدون\s*عمل)/i,

  // شروط سحب مستحيلة
  /(?:لا\s*تستطيع|ممنوع|لا\s*يحق\s*لك|لن\s*تتمكن).{0,40}(?:سحب|قبض|استلام|أخذ).{0,40}(?:الأرباح|المال|العمولة|الدخل).{0,50}(?:حتى|قبل).{0,40}(?:تنفيذ|استيفاء|تحقيق|إكمال)\s*(?:الشروط|التجنيد)/i,

  // ضغط بيع الممتلكات
  /(?:بع|بيع|رهن|تخلص\s*من).{0,30}(?:بيتك|أرضك|سيارتك|ذهبك|ممتلكاتك|عقاراتك)/i,
];

// قائمة الشركات والمخططات المعروفة
const KNOWN_PYRAMID_COMPANIES = [
  "questnet", "qnet", "كويست نت", "كيونت", "كويستنت", "quest net", "q-net",
  "qi group", "goldquest", "كويست نت", "شركة كويست", "شبكة كويست",
  "كويستنت", "كيو نت", "كيونيت"
];

const SUSPICIOUS_TLDS = [
  ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work",
  ".click", ".link", ".info", ".online", ".site", ".website", ".space",
  ".icu", ".buzz", ".rest", ".fit", ".monster", ".lol",
];

const SUSPICIOUS_HOST_PATTERNS = [
  /(?:secure|login|verify|account|update|confirm|banking|support)[-.]/i,
  /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
  /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|rebrand\.ly/i,
  /[а-яА-ЯёЁ]/,
  /xn--/i,
];

const KNOWN_BRANDS = [
  "apple", "google", "microsoft", "amazon", "paypal", "facebook", "instagram",
  "whatsapp", "netflix", "spotify", "bank", "dhl", "fedex", "ups", "aramex",
];

// ── Helper functions ─────────────────────────────────────────────────────

function matchPatterns(text, patterns) {
  const hits = [];
  for (const p of patterns) {
    if (p.test(text)) hits.push(p.source.slice(0, 40));
  }
  return hits;
}

function extractUrls(text) {
  const urlRegex = /https?:\/\/[^\s<>"{}|\\^`[\]]+/gi;
  return text.match(urlRegex) || [];
}

function analyzeSingleLink(url) {
  let score = 0;
  const indicators = [];
  try {
    const u = new URL(url);
    const host = u.hostname.toLowerCase();
    const path = u.pathname.toLowerCase();

    for (const tld of SUSPICIOUS_TLDS) {
      if (host.endsWith(tld)) {
        indicators.push({ code: "suspicious_tld", weight: 8 });
        score += 8;
      }
    }
    for (const p of SUSPICIOUS_HOST_PATTERNS) {
      if (p.test(host) || p.test(path)) {
        indicators.push({ code: "suspicious_host", weight: 6 });
        score += 6;
      }
    }
    for (const brand of KNOWN_BRANDS) {
      if (host.includes(brand) && !host.match(new RegExp(`(^|\\.)\( {brand}\\.(com|net|org|co|io) \)`))) {
        indicators.push({ code: "brand_spoof", weight: 10 });
        score += 10;
      }
    }
    if (host.split(".").length > 4) {
      indicators.push({ code: "many_subdomains", weight: 4 });
      score += 4;
    }
    if (url.length > 120) {
      indicators.push({ code: "long_url", weight: 3 });
      score += 3;
    }
    if (url.includes("@") && url.indexOf("@") < url.lastIndexOf(".")) {
      indicators.push({ code: "at_symbol", weight: 12 });
      score += 12;
    }
  } catch (_) {}
  return { score: Math.min(score, 15), indicators };
}

export function scoreToLevel(score) {
  if (score < 0) return LEVELS.unknown;
  if (score <= 24) return LEVELS.low;
  if (score <= 49) return LEVELS.medium;
  if (score <= 74) return LEVELS.high;
  return LEVELS.severe;
}

/**
 * Main analysis entry point
 */
export function analyze(input = {}) {
  const text = (input.text || "").trim();
  const explicitUrl = (input.url || "").trim();
  const hasImage = !!input.hasImage;

  if (!text && !explicitUrl && !hasImage) {
    return {
      score: -1,
      level: "unknown",
      levelColor: LEVELS.unknown.color,
      categories: {},
      categoryPercents: {},
      reasons: ["insufficient"],
      indicators: [],
      links: [],
      actions: ["unknown"],
      mode: "offline",
      hasImage,
      transparent: { totalPossible: 100, breakdown: [] },
    };
  }

  const fullText = [text, explicitUrl].filter(Boolean).join("\n");
  const categories = {
    urgency: 0,
    impersonation: 0,
    money: 0,
    sensitive: 0,
    link: 0,
    unrealistic: 0,
    socialEngineering: 0,
    pyramid: 0,
  };
  const indicators = [];
  const reasons = new Set();

  // Urgency
  const urgHits = matchPatterns(fullText, URGENCY_PATTERNS);
  if (urgHits.length) {
    categories.urgency = Math.min(WEIGHTS.urgency, 5 + urgHits.length * 3);
    reasons.add("urgency");
    indicators.push({ category: "urgency", hits: urgHits.length, weight: categories.urgency });
  }

  // Impersonation
  const impHits = matchPatterns(fullText, IMPERSONATION_PATTERNS);
  if (impHits.length) {
    categories.impersonation = Math.min(WEIGHTS.impersonation, 6 + impHits.length * 4);
    reasons.add("impersonation");
    indicators.push({ category: "impersonation", hits: impHits.length, weight: categories.impersonation });
  }

  // Money
  const moneyHits = matchPatterns(fullText, MONEY_PATTERNS);
  if (moneyHits.length) {
    categories.money = Math.min(WEIGHTS.money, 6 + moneyHits.length * 4);
    reasons.add("money");
    indicators.push({ category: "money", hits: moneyHits.length, weight: categories.money });
  }

  // Sensitive
  const sensHits = matchPatterns(fullText, SENSITIVE_PATTERNS);
  if (sensHits.length) {
    categories.sensitive = Math.min(WEIGHTS.sensitive, 8 + sensHits.length * 5);
    reasons.add("sensitive");
    indicators.push({ category: "sensitive", hits: sensHits.length, weight: categories.sensitive });
  }

  // Unrealistic
  const unrealHits = matchPatterns(fullText, UNREALISTIC_PATTERNS);
  if (unrealHits.length) {
    categories.unrealistic = Math.min(WEIGHTS.unrealistic, 4 + unrealHits.length * 3);
    reasons.add("unrealistic");
    indicators.push({ category: "unrealistic", hits: unrealHits.length, weight: categories.unrealistic });
  }

  // Social Engineering
  const seHits = matchPatterns(fullText, SOCIAL_ENGINEERING_PATTERNS);
  if (seHits.length) {
    categories.socialEngineering = Math.min(WEIGHTS.socialEngineering, 3 + seHits.length * 2);
    reasons.add("socialEngineering");
    indicators.push({ category: "socialEngineering", hits: seHits.length, weight: categories.socialEngineering });
  }

  // ===== كشف التسويق الهرمي (القوي) =====
  const pyramidHits = matchPatterns(fullText, PYRAMID_PATTERNS);
  if (pyramidHits.length) {
    categories.pyramid = Math.min(WEIGHTS.pyramid, 10 + pyramidHits.length * 5);
    reasons.add("pyramid");
    indicators.push({
      category: "pyramid",
      hits: pyramidHits.length,
      weight: categories.pyramid,
      detail: "مؤشرات تسويق هرمي / شبكي قوية"
    });
  }

  // كشف أسماء الشركات المعروفة
  const lowerText = fullText.toLowerCase();
  for (const company of KNOWN_PYRAMID_COMPANIES) {
    if (lowerText.includes(company)) {
      categories.pyramid = Math.max(categories.pyramid, 20);
      reasons.add("known_pyramid_company");
      indicators.push({
        category: "pyramid",
        weight: 20,
        detail: `تم رصد اسم شركة معروفة بالتسويق الهرمي: ${company}`
      });
      break;
    }
  }

  // Links
  const urls = extractUrls(fullText);
  if (explicitUrl && !urls.includes(explicitUrl)) urls.push(explicitUrl);
  const linkDetails = [];
  let linkScore = 0;
  for (const u of urls) {
    const la = analyzeSingleLink(u);
    linkScore = Math.max(linkScore, la.score);
    linkDetails.push({ url: u, ...la });
  }
  if (linkScore > 0) {
    categories.link = Math.min(WEIGHTS.link, linkScore);
    reasons.add("link");
    indicators.push({ category: "link", hits: urls.length, weight: categories.link });
  }

  if (hasImage && !text && !explicitUrl) {
    reasons.add("image_unavailable");
  }

  // Total score
  let score = Object.values(categories).reduce((a, b) => a + b, 0);
  score = Math.min(100, Math.round(score));

  if (hasImage && !text && !explicitUrl) {
    score = -1;
  }

  const levelObj = scoreToLevel(score);
  const level = levelObj.key;

  const categoryPercents = {};
  for (const [k, v] of Object.entries(categories)) {
    categoryPercents[k] = WEIGHTS[k] ? Math.round((v / WEIGHTS[k]) * 100) : 0;
  }

  const breakdown = Object.entries(categories)
    .filter(([, v]) => v > 0)
    .map(([k, v]) => ({
      category: k,
      points: v,
      max: WEIGHTS[k],
      percentOfMax: categoryPercents[k],
      percentOfTotal: score > 0 ? Math.round((v / score) * 100) : 0,
    }))
    .sort((a, b) => b.points - a.points);

  const actions = [];
  if (score < 0) {
    actions.push("unknown");
  } else if (score <= 24) {
    actions.push("low");
  } else {
    if (reasons.has("link")) actions.push("no_link");
    if (reasons.has("money") || reasons.has("pyramid")) actions.push("no_money");
    if (reasons.has("sensitive")) actions.push("no_sensitive");
    if (reasons.has("pyramid") || reasons.has("known_pyramid_company")) {
      actions.push("pyramid_warning");
    }
    actions.push("contact_official", "verify", "delete");
  }

  return {
    score,
    level,
    levelColor: levelObj.color,
    categories,
    categoryPercents,
    reasons: [...reasons],
    indicators,
    links: linkDetails,
    actions,
    mode: "offline",
    hasImage,
    transparent: {
      totalPossible: 100,
      score,
      breakdown,
      weights: { ...WEIGHTS },
    },
  };
}

export function analyzeLink(url) {
  return analyzeSingleLink(url);
}
