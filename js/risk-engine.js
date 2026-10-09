/**
 * TRUST AI Risk Engine v1.0
 * Rule-based offline analysis — works fully without any API key.
 * Transparent scoring 0–100 with category breakdown percentages.
 * Arabic + English pattern libraries.
 */

export const WEIGHTS = {
  urgency: 15,
  impersonation: 20,
  money: 20,
  sensitive: 20,
  link: 15,
  unrealistic: 5,
  socialEngineering: 5,
};

export const LEVELS = {
  low:      { min: 0,  max: 24, key: "low",      color: "#22c55e" },
  medium:   { min: 25, max: 49, key: "medium",   color: "#eab308" },
  high:     { min: 50, max: 74, key: "high",     color: "#f97316" },
  severe:   { min: 75, max: 100, key: "severe",  color: "#ef4444" },
  unknown:  { min: -1, max: -1, key: "unknown",  color: "#94a3b8" },
};

// ── Pattern libraries (AR + EN) ──────────────────────────────────────────

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
  /(?:عملات?\s*رقمية|بيتكوين|USDT|crypto|بيتكoin)/i,
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
  /(?:iTunes|Amazon|Google\s*Play)\s*(?:card|gift)/i,
];

const SENSITIVE_PATTERNS = [
  /كلمة\s*(?:المرور|السر)/i,
  /(?:رمز|كود)\s*(?:التحقق|OTP|التأكيد)/i,
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

// Suspicious TLDs and link heuristics
const SUSPICIOUS_TLDS = [
  ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work",
  ".click", ".link", ".info", ".online", ".site", ".website", ".space",
  ".icu", ".buzz", ".rest", ".fit", ".monster", ".lol",
];

const SUSPICIOUS_HOST_PATTERNS = [
  /(?:secure|login|verify|account|update|confirm|banking|support)[-.]/i,
  /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/, // raw IP
  /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|rebrand\.ly/i,
  /[а-яА-ЯёЁ]/, // Cyrillic (homograph)
  /xn--/i, // punycode
];

const KNOWN_BRANDS = [
  "apple", "google", "microsoft", "amazon", "paypal", "facebook", "instagram",
  "whatsapp", "netflix", "spotify", "bank", "dhl", "fedex", "ups", "aramex",
];

// ── Helpers ──────────────────────────────────────────────────────────────

function matchPatterns(text, patterns) {
  const hits = [];
  for (const p of patterns) {
    if (p.test(text)) hits.push(p.source.slice(0, 40));
  }
  return hits;
}

function extractUrls(text) {
  const found = new Set();
  const urlRegex = /https?:\/\/[^\s<>"']+/gi;
  const bareDomain = /(?:www\.)?[a-z0-9][-a-z0-9]*\.[a-z]{2,}(?:\.[a-z]{2,})?(?:\/[^\s]*)?/gi;
  let m;
  while ((m = urlRegex.exec(text)) !== null) found.add(m[0]);
  while ((m = bareDomain.exec(text)) !== null) {
    if (m[0].includes(".")) found.add(m[0]);
  }
  return [...found];
}

function analyzeSingleLink(url) {
  const indicators = [];
  let score = 0;
  let host = "";
  let path = "";
  try {
    const normalized = url.startsWith("http") ? url : "https://" + url;
    const u = new URL(normalized);
    host = u.hostname.toLowerCase();
    path = u.pathname + u.search;
  } catch {
    indicators.push({ code: "invalid_url", weight: 10 });
    return { score: 10, indicators, host: url, path: "" };
  }

  // Suspicious TLD
  for (const tld of SUSPICIOUS_TLDS) {
    if (host.endsWith(tld)) {
      indicators.push({ code: "suspicious_tld", weight: 8, detail: tld });
      score += 8;
      break;
    }
  }

  // Host patterns
  for (const p of SUSPICIOUS_HOST_PATTERNS) {
    if (p.test(host) || p.test(path)) {
      indicators.push({ code: "suspicious_host", weight: 6, detail: p.source.slice(0, 30) });
      score += 6;
    }
  }

  // Brand in subdomain but not main domain (typosquatting-ish)
  for (const brand of KNOWN_BRANDS) {
    if (host.includes(brand) && !host.endsWith(brand + ".com") && !host.endsWith(brand + ".net") && !host.endsWith(brand + ".org")) {
      // e.g. apple-secure-login.tk
      if (!host.match(new RegExp(`(^|\\.)${brand}\\.(com|net|org|co|io)$`))) {
        indicators.push({ code: "brand_spoof", weight: 10, detail: brand });
        score += 10;
      }
    }
  }

  // Very long URL or many subdomains
  const parts = host.split(".");
  if (parts.length > 4) {
    indicators.push({ code: "many_subdomains", weight: 4 });
    score += 4;
  }
  if (url.length > 120) {
    indicators.push({ code: "long_url", weight: 3 });
    score += 3;
  }

  // @ in URL (credential phishing)
  if (url.includes("@") && url.indexOf("@") < url.lastIndexOf(".")) {
    indicators.push({ code: "at_symbol", weight: 12 });
    score += 12;
  }

  return { score: Math.min(score, 15), indicators, host, path };
}

export function scoreToLevel(score) {
  if (score < 0) return LEVELS.unknown;
  if (score <= 24) return LEVELS.low;
  if (score <= 49) return LEVELS.medium;
  if (score <= 74) return LEVELS.high;
  return LEVELS.severe;
}

/**
 * Main analysis entry point (offline layer).
 * @param {{ text?: string, url?: string, hasImage?: boolean }} input
 * @returns {object} full transparent result
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
      transparent: {
        totalPossible: 100,
        breakdown: [],
      },
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
    categories.impersonation = Math.min(WEIGHTS.impersonation, 8 + impHits.length * 4);
    reasons.add("impersonation");
    indicators.push({ category: "impersonation", hits: impHits.length, weight: categories.impersonation });
  }

  // Money
  const moneyHits = matchPatterns(fullText, MONEY_PATTERNS);
  if (moneyHits.length) {
    categories.money = Math.min(WEIGHTS.money, 10 + moneyHits.length * 4);
    reasons.add("money");
    indicators.push({ category: "money", hits: moneyHits.length, weight: categories.money });
  }

  // Sensitive
  const sensHits = matchPatterns(fullText, SENSITIVE_PATTERNS);
  if (sensHits.length) {
    categories.sensitive = Math.min(WEIGHTS.sensitive, 12 + sensHits.length * 4);
    reasons.add("sensitive");
    indicators.push({ category: "sensitive", hits: sensHits.length, weight: categories.sensitive });
  }

  // Unrealistic
  const unrealHits = matchPatterns(fullText, UNREALISTIC_PATTERNS);
  if (unrealHits.length) {
    categories.unrealistic = Math.min(WEIGHTS.unrealistic, 3 + unrealHits.length * 1);
    reasons.add("unrealistic");
    indicators.push({ category: "unrealistic", hits: unrealHits.length, weight: categories.unrealistic });
  }

  // Social engineering
  const seHits = matchPatterns(fullText, SOCIAL_ENGINEERING_PATTERNS);
  if (seHits.length) {
    categories.socialEngineering = Math.min(WEIGHTS.socialEngineering, 3 + seHits.length * 1);
    reasons.add("socialEngineering");
    indicators.push({ category: "socialEngineering", hits: seHits.length, weight: categories.socialEngineering });
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

  // Image without text → needs verification
  if (hasImage && !text && !explicitUrl) {
    reasons.add("image_unavailable");
  }

  // Total score
  let score = Object.values(categories).reduce((a, b) => a + b, 0);
  score = Math.min(100, Math.round(score));

  // If only image and no text, mark unknown
  if (hasImage && !text && !explicitUrl) {
    score = -1;
  }

  const levelObj = scoreToLevel(score);
  const level = levelObj.key;

  // Category percentages relative to their max weight
  const categoryPercents = {};
  for (const [k, v] of Object.entries(categories)) {
    categoryPercents[k] = WEIGHTS[k] ? Math.round((v / WEIGHTS[k]) * 100) : 0;
  }

  // Transparent breakdown
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

  // Recommended actions
  const actions = [];
  if (score < 0) {
    actions.push("unknown");
  } else if (score <= 24) {
    actions.push("low");
  } else {
    if (reasons.has("link")) actions.push("no_link");
    if (reasons.has("money")) actions.push("no_money");
    if (reasons.has("sensitive")) actions.push("no_sensitive");
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
