/**
 * TRUST AI Risk Engine v1.2
 * Rule-based offline analysis — works fully without any API key.
 * Transparent scoring 0–100 with category breakdown percentages.
 * Arabic + English pattern libraries.
 * Expanded heavily for: X/Twitter crypto scams, Telegram channels,
 * Facebook inheritance/bank scams, email lottery prizes, fake news,
 * Nigerian networks, casinos, investment platforms, companies & brands,
 * and strong pyramid / network marketing detection.
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

// ── Pattern libraries (AR + EN) — heavily expanded ───────────────────────

const URGENCY_PATTERNS = [
  /تصرف\s*(الآن|فوراً|فورًا)/i,
  /مطلوب\s*(إجراء|اجراء)\s*فوري/i,
  /حسابك.*?(سيتم|سوف|راح).*?(إغلاق|اغلاق|تعليق|قفل|إيقاف|ايقاف|حظر|تجميد)/i,
  /عاجل\s*[!！]/i,
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
  /account\s*(will\s*be|is\s*being|has\s*been)\s*(closed|suspended|locked|blocked)/i,
  /\burgent\s*[!:]/i,
  /you\s*have\s*(only\s*)?\d+\s*(minutes?|hours?)\s*(left|remaining)/i,
  /last\s*chance/i,
  /confirm\s*immediately/i,
  /urgent\s*(action|response|attention)/i,
  /within\s*\d+\s*(hours?|minutes?)/i,
  /expires?\s*(soon|today|in)/i,
  /limited\s*time/i,
  /respond\s*(now|immediately|asap)/i,
  /join\s*(now|immediately|fast)/i,
  /sniper\s*bot\s*(live|ready)/i,
  /next\s*100x/i,
  /buy\s*now\s*or\s*miss/i,
  /القناة\s*مقفلة|انضم\s*الآن/i,
  /الفرصة\s*تنتهي/i,
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
  /(?:Binance|Bybit|KuCoin|Coinbase|OKX|Bitget|Crypto\.com|Kraken|Gate\.io)/i,
  /(?:مدير\s*بنك|مدير\s*الفرع|مسؤول\s*الحساب)/i,
  /(?:bank\s*manager|account\s*manager|compliance\s*officer)/i,
  /(?:قريب|عم|خال|أخ|أخت).*?(توفى|توفي|مات)/i,
  /(?:relative|uncle|brother|sister).*?(died|passed\s*away)/i,
  /ترك\s*(مبلغ|ثروة|أموال)/i,
  /unclaimed\s*(inheritance|funds|estate)/i,
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
  /(?:bitcoin|crypto|USDT|cryptocurrency|BTC|ETH|SOL|TON)/i,
  /bank\s*transfer/i,
  /(?:pay|send)\s*(?:to\s*)?(?:claim|receive)\s*(?:prize|job|offer)/i,
  /(?:western\s*union|moneygram|paypal)/i,
  /(?:iTunes|Amazon|Google\s*Play)\s*(?:card|gift)/i,
  /(?:airdrop|claim\s*(?:your\s*)?(?:free\s*)?(?:tokens?|USDT|ETH))/i,
  /(?:seed\s*phrase|private\s*key|recovery\s*phrase|mnemonic)/i,
  /connect\s*(?:your\s*)?wallet/i,
  /(?:approve|sign)\s*(?:the\s*)?transaction/i,
  /(?:guaranteed|مضمون)\s*(?:profit|return|ربح|أرباح)/i,
  /(?:100%|fifty\s*percent|50%)\s*(?:profit|return)/i,
  /(?:daily|weekly)\s*(?:profit|earnings|دخل)/i,
  /(?:pump|dump|sniper|presale|whitelist)/i,
  /(?:كازينو|casino|betting|مراهنة|قمار)/i,
  // Pyramid specific
  /(?:رسوم\s*تسجيل|registration\s*fee|عضوية)/i,
  /(?:1500|2000|ألف\s*وخمس|ألفي)\s*(?:دولار|\$|USD)/i,
  /(?:تجنيد|recruit|تجنّد)\s*(?:3|ثلاثة|ثلاث)/i,
  /(?:دخل\s*سلبي|passive\s*income|حرية\s*مالية|financial\s*freedom)/i,
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
  /(?:seed|private\s*key|recovery|mnemonic|12\s*words|24\s*words)/i,
  /(?:أرسل|send)\s*(?:عبارة\s*الاسترداد|المفتاح\s*الخاص)/i,
  /2FA|authenticator|google\s*auth/i,
];

const UNREALISTIC_PATTERNS = [
  /(?:فزت|ربحت|جائزة)\s*(?:كبرى|ضخمة|مليون)/i,
  /(?:مبروك|تهانينا).*?(?:ربحت|فزت)/i,
  /(?:ربحت|فزت)\s*(?:ب)?جائزة/i,
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
  /(?:world\s*cup|مونديال|كأس\s*العالم).*?(?:جائزة|prize|winner)/i,
  /(?:2\s*billion|مليارين|مليار\s*دولار)/i,
  /(?:lottery|يانصيب|سحب\s*كبير)/i,
  /(?:claim\s*your\s*prize|استلم\s*جائزتك)/i,
  /(?:fees?|taxes?|رسوم|ضرائب).*?(?:to\s*claim|لاستلام)/i,
  /(?:خبر\s*عاجل|breaking\s*news).*?(?:وفاة|انفجار|حرب|زلزال)/i,
  /(?:share\s*immediately|انشر\s*فوراً)/i,
  // Pyramid
  /(?:مليونير|millionaire)\s*(?:خلال|in)\s*(?:أشهر|months)/i,
  /(?:غيّر\s*حياتك|change\s*your\s*life)/i,
  /(?:فرصتك\s*الوحيدة|only\s*chance)/i,
  /(?:QuestNet|QNET|كويست\s*نت|كيونت|QI\s*Group|GoldQuest)/i,
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
  /(?:انضم\s*للقناة|join\s*(?:the\s*)?(?:channel|group|tg))/i,
  /(?:only\s*for\s*members|للأعضاء\s*فقط)/i,
  /(?:don't\s*share\s*outside|لا\s*تنشر\s*خارج)/i,
  // Pyramid secrecy
  /(?:لا\s*تخبر\s*(?:حتى|حتى\s*أقرب)|don't\s*tell\s*(?:even|family))/i,
  /(?:سرية\s*تامة|absolute\s*secrecy)/i,
];

const SUSPICIOUS_TLDS = [
  ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top", ".club", ".work",
  ".click", ".link", ".info", ".online", ".site", ".website", ".space",
  ".icu", ".buzz", ".rest", ".fit", ".monster", ".lol", ".sbs", ".cyou",
  ".cfd", ".bond", ".hair", ".skin", ".quest", ".zip", ".mov",
];

const SUSPICIOUS_HOST_PATTERNS = [
  /(?:secure|login|verify|account|update|confirm|banking|support)[-.]/i,
  /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/,
  /bit\.ly|tinyurl|t\.co|goo\.gl|ow\.ly|is\.gd|buff\.ly|rebrand\.ly|t\.me|telegram\.me|rb\.gy|cutt\.ly|shorturl|tiny\.cc/i,
  /[а-яА-ЯёЁ]/,
  /xn--/i,
  /(?:airdrop|claim|free-?usdt|giveaway|presale)/i,
];

const URL_SHORTENERS = [
  "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
  "rebrand.ly", "rb.gy", "cutt.ly", "tiny.cc", "shorturl.at", "t.me",
  "telegram.me", "wa.me", "s.id", "v.gd", "clck.ru", "tr.im",
];

const KNOWN_BRANDS = [
  "apple", "google", "microsoft", "amazon", "meta", "facebook", "instagram",
  "whatsapp", "netflix", "spotify", "twitter", "x.com", "telegram", "discord",
  "tiktok", "snapchat", "linkedin", "youtube",
  "paypal", "visa", "mastercard", "stripe", "wise", "revolut", "westernunion",
  "moneygram", "bank", "citi", "hsbc", "barclays", "chase", "wells", "fargo",
  "binance", "bybit", "kucoin", "coinbase", "okx", "bitget", "kraken", "gateio",
  "crypto.com", "huobi", "mexc", "bitfinex", "gemini",
  "dhl", "fedex", "ups", "aramex", "smsa", "usps", "royalmail",
  "irs", "gov", "customs", "tax",
  "netflix", "spotify", "steam", "epicgames", "playstation", "xbox",
  "qnet", "questnet", "goldquest",
];

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
  let isShortener = false;
  let isBrandSpoof = false;
  try {
    const normalized = url.startsWith("http") ? url : "https://" + url;
    const u = new URL(normalized);
    host = u.hostname.toLowerCase().replace(/^www\./, "");
    path = u.pathname + u.search;
  } catch {
    indicators.push({ code: "invalid_url", weight: 10 });
    return { score: 10, indicators, host: url, path: "", url, isShortener: false, isBrandSpoof: false, flags: ["invalid_url"] };
  }

  const flags = [];

  for (const tld of SUSPICIOUS_TLDS) {
    if (host.endsWith(tld)) {
      indicators.push({ code: "suspicious_tld", weight: 8, detail: tld });
      score += 8;
      flags.push("suspicious_tld");
      break;
    }
  }

  for (const p of SUSPICIOUS_HOST_PATTERNS) {
    if (p.test(host) || p.test(path)) {
      indicators.push({ code: "suspicious_host", weight: 6, detail: p.source.slice(0, 30) });
      score += 6;
      flags.push("suspicious_host");
    }
  }

  for (const brand of KNOWN_BRANDS) {
    if (host.includes(brand) && !host.endsWith(brand + ".com") && !host.endsWith(brand + ".net") && !host.endsWith(brand + ".org") && !host.endsWith(brand + ".io")) {
      if (!host.match(new RegExp(`(^|\\.)${brand}\\.(com|net|org|co|io|app|me)$`))) {
        indicators.push({ code: "brand_spoof", weight: 10, detail: brand });
        score += 10;
        isBrandSpoof = true;
        flags.push("brand_spoof:" + brand);
      }
    }
  }

  // Typosquatting-ish: brand name with extra chars (paypal-secure.com, micros0ft.com)
  for (const brand of ["paypal", "microsoft", "apple", "google", "amazon", "binance", "facebook", "instagram", "whatsapp", "netflix"]) {
    const re = new RegExp(brand.split("").join("[^a-z0-9]?") + "|[0o]" + brand.slice(1), "i");
    if (re.test(host) && !host.includes(brand + ".com") && host !== brand + ".com") {
      if (!flags.some((f) => f.startsWith("brand_spoof"))) {
        indicators.push({ code: "typosquat", weight: 9, detail: brand });
        score += 9;
        isBrandSpoof = true;
        flags.push("typosquat:" + brand);
      }
    }
  }

  const parts = host.split(".");
  if (parts.length > 4) {
    indicators.push({ code: "many_subdomains", weight: 4 });
    score += 4;
    flags.push("many_subdomains");
  }
  if (url.length > 120) {
    indicators.push({ code: "long_url", weight: 3 });
    score += 3;
    flags.push("long_url");
  }

  if (url.includes("@")) {
    indicators.push({ code: "at_symbol", weight: 9 });
    score += 9;
    flags.push("at_symbol");
  }

  if (url.startsWith("http://")) {
    indicators.push({ code: "http", weight: 5 });
    score += 5;
    flags.push("http_not_https");
  }

  if (URL_SHORTENERS.some((s) => host === s || host.endsWith("." + s))) {
    indicators.push({ code: "shortener", weight: 5 });
    score += 5;
    isShortener = true;
    flags.push("shortener");
  }

  return { score, indicators, host, path, url, isShortener, isBrandSpoof, flags };
}

export function scoreToLevel(score) {
  if (score < 0) return LEVELS.unknown;
  if (score <= 24) return LEVELS.low;
  if (score <= 49) return LEVELS.medium;
  if (score <= 74) return LEVELS.high;
  return LEVELS.severe;
}

export function analyze(input = {}) {
  const text = (input.text || "").trim();
  const imageHint = (input.imageHint || "").trim();
  const fullText = (text + " " + imageHint).trim();
  const hasImage = !!input.hasImage;

  if (!fullText && !hasImage) {
    return {
      score: -1,
      level: "unknown",
      levelColor: LEVELS.unknown.color,
      categories: {},
      categoryPercents: {},
      reasons: [],
      indicators: [],
      links: [],
      actions: ["unknown"],
      mode: "offline",
      hasImage: false,
      transparent: { totalPossible: 100, score: -1, breakdown: [], weights: { ...WEIGHTS } },
    };
  }

  // Image only, no text: the offline engine cannot read pixels, so it must
  // never report "low risk". Return "unknown" and let a vision model decide.
  if (!fullText && hasImage) {
    return {
      score: -1,
      level: "unknown",
      levelColor: LEVELS.unknown.color,
      categories: {},
      categoryPercents: {},
      reasons: ["image_unavailable"],
      indicators: [],
      links: [],
      actions: ["unknown"],
      mode: "offline",
      hasImage: true,
      transparent: { totalPossible: 100, score: -1, breakdown: [], weights: { ...WEIGHTS } },
    };
  }

  const categories = {
    urgency: 0,
    impersonation: 0,
    money: 0,
    sensitive: 0,
    link: 0,
    unrealistic: 0,
    socialEngineering: 0,
  };
  const reasons = new Set();
  const indicators = [];

  const urgHits = matchPatterns(fullText, URGENCY_PATTERNS);
  if (urgHits.length) {
    categories.urgency = Math.min(WEIGHTS.urgency, 5 + urgHits.length * 3);
    reasons.add("urgency");
    indicators.push({ category: "urgency", detail: urgHits[0], severity: Math.min(10, 4 + urgHits.length) });
  }

  const impHits = matchPatterns(fullText, IMPERSONATION_PATTERNS);
  if (impHits.length) {
    categories.impersonation = Math.min(WEIGHTS.impersonation, 6 + impHits.length * 4);
    reasons.add("impersonation");
    indicators.push({ category: "impersonation", detail: impHits[0], severity: Math.min(10, 5 + impHits.length) });
  }

  const moneyHits = matchPatterns(fullText, MONEY_PATTERNS);
  if (moneyHits.length) {
    categories.money = Math.min(WEIGHTS.money, 7 + moneyHits.length * 4);
    reasons.add("money");
    indicators.push({ category: "money", detail: moneyHits[0], severity: Math.min(10, 6 + moneyHits.length) });
  }

  const sensHits = matchPatterns(fullText, SENSITIVE_PATTERNS);
  if (sensHits.length) {
    categories.sensitive = Math.min(WEIGHTS.sensitive, 8 + sensHits.length * 4);
    reasons.add("sensitive");
    indicators.push({ category: "sensitive", detail: sensHits[0], severity: Math.min(10, 7 + sensHits.length) });
  }

  const unrealHits = matchPatterns(fullText, UNREALISTIC_PATTERNS);
  if (unrealHits.length) {
    categories.unrealistic = Math.min(WEIGHTS.unrealistic, 3 + unrealHits.length * 2);
    reasons.add("unrealistic");
    indicators.push({ category: "unrealistic", detail: unrealHits[0], severity: Math.min(10, 4 + unrealHits.length) });
  }

  const seHits = matchPatterns(fullText, SOCIAL_ENGINEERING_PATTERNS);
  if (seHits.length) {
    categories.socialEngineering = Math.min(WEIGHTS.socialEngineering, 3 + seHits.length * 2);
    reasons.add("socialEngineering");
    indicators.push({ category: "socialEngineering", detail: seHits[0], severity: Math.min(10, 4 + seHits.length) });
  }

  const urls = extractUrls(fullText);
  const linkDetails = [];
  let linkScore = 0;
  for (const u of urls) {
    const res = analyzeSingleLink(u);
    linkScore += res.score;
    linkDetails.push(res);
    for (const ind of res.indicators) {
      indicators.push({ category: "link", detail: ind.code + (ind.detail ? ": " + ind.detail : ""), severity: Math.min(10, ind.weight) });
    }
  }
  if (linkScore > 0) {
    categories.link = Math.min(WEIGHTS.link, Math.round(linkScore * 0.8));
    reasons.add("link");
  }

  let score = 0;
  for (const k of Object.keys(categories)) score += categories[k];
  score = Math.min(100, Math.round(score));

  const levelObj = scoreToLevel(score);
  const level = levelObj.key;

  const categoryPercents = {};
  for (const k of Object.keys(categories)) {
    categoryPercents[k] = WEIGHTS[k] > 0 ? Math.round((categories[k] / WEIGHTS[k]) * 100) : 0;
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

/** Detect likely real secrets in pasted text — for client-side warning only */
export function detectSensitivePaste(text) {
  if (!text || text.length < 4) return [];
  const hits = [];
  // OTP / PIN style 4–8 digits alone
  if (/\b\d{4,8}\b/.test(text) && /(?:otp|رمز|كود|code|pin|تحقق|verification)/i.test(text)) {
    hits.push("otp");
  }
  // Card-like 13–19 digits with optional spaces/dashes
  if (/\b(?:\d[ -]*?){13,19}\b/.test(text)) hits.push("card");
  // IBAN-ish
  if (/\b[A-Z]{2}\d{2}[A-Z0-9]{10,30}\b/i.test(text)) hits.push("iban");
  // Seed / mnemonic keywords
  if (/(?:seed\s*phrase|recovery\s*phrase|private\s*key|مفتاح\s*خاص|عبارة\s*الاسترداد)/i.test(text)) {
    hits.push("seed");
  }
  // Password-looking assignment
  if (/(?:password|passwd|كلمة\s*المرور|كلمة\s*السر)\s*[:=]\s*\S+/i.test(text)) {
    hits.push("password");
  }
  return hits;
}
