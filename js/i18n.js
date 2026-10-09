/**
 * TRUST AI — Arabic (RTL) / English (LTR) translations
 */

const translations = {
  ar: {
    title: "TRUST AI",
    tagline: "تحقق قبل أن تثق.",
    description: "منصّتك الموثوقة للسلامة الرقمية.",
    extra: "حلّل الرسائل والروابط ولقطات الشاشة قبل أن تضغط أو تدفع أو ترد أو تشارك معلوماتك.",
    inputLabel: "ألصق الرسالة أو الرابط هنا",
    inputPlaceholder: "ألصق الرسالة أو الرابط أو الخبر هنا...",
    btnAnalyze: "تحقق الآن",
    btnUpload: "رفع لقطة شاشة",
    uploadHint: "إن لم تفتح نافذة الاختيار: اسحب الصورة وأفلتها هنا، أو انسخها والصقها (Ctrl+V).",
    btnExample: "تجربة مثال",
    btnSettings: "الإعدادات",
    privacyNote: "لأمانك: لا ترسل كلمات المرور أو رموز OTP أو بياناتك البنكية الحقيقية. التحليل يتم محلياً أو عبر مزوّدك فقط.",
    analyzing: "جارٍ التحليل...",
    analysisDone: "اكتمل التحليل.",
    resultTitle: "نتيجة التحليل",
    riskScore: "درجة الخطورة",
    indicatorsCount: "مؤشرات الخطر",
    whyTitle: "لماذا؟",
    actionTitle: "ماذا تفعل؟",
    breakdownTitle: "تفصيل النقاط من الجذور",
    categoriesTitle: "نسب الفئات",
    linksTitle: "تحليل الروابط",
    modeOffline: "وضع بدون عميل (قواعد محلية)",
    modeAI: "وضع مع عميل (ذكاء اصطناعي)",
    modeHybrid: "وضع هجين (قواعد + ذكاء اصطناعي)",
    disclaimer: "TRUST AI يقدّم تقييماً للمخاطر بناءً على أنماط معروفة وتحليل اختياري بالذكاء الاصطناعي. لا يضمن الأمان بشكل مطلق 100%. القرار النهائي لك.",
    btnAgain: "تحليل جديد",
    btnBack: "العودة",
    examplesTitle: "أمثلة تجريبية",
    examplesNote: "هذه أمثلة خيالية لأغراض التجربة فقط.",
    footer: "TRUST AI v1.0 — تحقق قبل أن تثق. منصة مفتوحة للسلامة الرقمية.",
    removeImage: "حذف الصورة",
    close: "إغلاق",
    settingsTitle: "إعدادات الذكاء الاصطناعي (اختياري)",
    settingsDesc: "يعمل التطبيق بالكامل بدون أي مفتاح. أضف مفتاحاً مجانياً لتعزيز التحليل والصور.",
    modelLabel: "النموذج",
    apiKeyLabel: "مفتاح API (مخفي)",
    apiKeyPlaceholder: "الصق المفتاح هنا — يبقى في هذه الجلسة فقط",
    btnSaveAI: "حفظ وتفعيل",
    btnClearAI: "إلغاء التفعيل",
    btnTestAI: "اختبار الاتصال",
    aiConnected: "متصل",
    aiDisconnected: "غير متصل — يعمل بالوضع المحلي",
    freeModelsNote: "نماذج مجانية — احصل على المفتاح من الرابط الرسمي:",
    getKey: "الحصول على المفتاح",
    connectionOk: "الاتصال ناجح ✓",
    connectionFail: "فشل الاتصال",
    confidence: "ثقة التحليل",
    aiSummary: "ملخص الذكاء الاصطناعي",
    percentOfMax: "% من الحد الأقصى",
    points: "نقاط",
    host: "المضيف",
    linkScore: "درجة الرابط",
    noLinks: "لا توجد روابط",
    imageNote: "تم رفع صورة — التحليل الكامل يتطلب نموذجاً يدعم الرؤية",
    layerOffline: "الطبقة 1: محرك القواعد (بدون إنترنت)",
    layerAI: "الطبقة 2: نموذج الذكاء الاصطناعي",

    level_low: "خطر منخفض",
    level_medium: "خطر متوسط",
    level_high: "خطر مرتفع",
    level_severe: "خطر شديد",
    level_unknown: "يحتاج إلى تحقق إضافي",

    cat_urgency: "الاستعجال والضغط",
    cat_impersonation: "انتحال الهوية",
    cat_money: "طلب أموال",
    cat_sensitive: "معلومات حساسة",
    cat_link: "مؤشرات الرابط",
    cat_unrealistic: "عروض غير واقعية",
    cat_socialEngineering: "هندسة اجتماعية",

    reason_urgency: "الرسالة تستخدم أسلوب الاستعجال والضغط الزمني.",
    reason_impersonation: "تحتوي على نمط قد يشير إلى انتحال هوية جهة رسمية أو معروفة.",
    reason_money: "تطلب تحويل أموال أو دفع رسوم أو بطاقات هدايا.",
    reason_sensitive: "تطلب معلومات حساسة مثل كلمة مرور أو رمز تحقق أو بيانات بنكية.",
    reason_unrealistic: "تحتوي على وعود أو عروض غير منطقية (جائزة، أرباح مضمونة، إلخ).",
    reason_socialEngineering: "تحاول عزل المستخدم عن وسائل التحقق الطبيعية أو تفرض السرية.",
    reason_link: "الرابط يحتوي على خصائص تستحق التحقق الإضافي.",
    reason_insufficient: "المعلومات غير كافية لإجراء تحليل موثوق.",
    reason_image_unavailable: "تحليل لقطات الشاشة الكامل يتطلب نموذجاً يدعم الرؤية (Gemini أو GPT-4o).",

    action_no_link: "لا تضغط على الرابط.",
    action_no_money: "لا ترسل أموالاً أو تدفع رسوماً.",
    action_no_sensitive: "لا تشارك كلمة المرور أو رمز OTP أو بياناتك البنكية.",
    action_contact_official: "تواصل مع الجهة عبر موقعها الرسمي أو رقمها الرسمي فقط.",
    action_verify: "تحقق من المصدر من خلال قناة مستقلة موثوقة.",
    action_delete: "احذف الرسالة أو تجاهلها إن كانت مشبوهة.",
    action_low: "لم يتم اكتشاف مؤشرات احتيال واضحة، لكن هذا لا يضمن الأمان. كن حذراً.",
    action_unknown: "يرجى تقديم نص الرسالة أو الرابط لتحليل أدق.",

    error_empty: "يرجى إدخال رسالة أو رابط أو رفع صورة.",
    error_generic: "حدث خطأ أثناء التحليل. حاول مرة أخرى.",
    error_image_type: "نوع الصورة غير مدعوم. استخدم JPG أو PNG أو WEBP.",
    error_image_size: "الصورة كبيرة جداً. الحد الأقصى 5 ميجابايت.",
    error_invalid_url: "رابط غير صالح.",

    ex1_title: "رسالة بنك مزيفة",
    ex1_desc: "تطلب تأكيد الحساب برمز OTP",
    ex2_title: "رسالة توصيل مزيفة",
    ex2_desc: "رسوم توصيل عاجلة",
    ex3_title: "عرض وظيفة مزيف",
    ex3_desc: "راتب ضخم بدون شروط",
    ex4_title: "جائزة مزيفة",
    ex4_desc: "فزت بجائزة لم تدخلها",
    ex5_title: "طلب رمز OTP",
    ex5_desc: "دعم فني يطلب رمز التحقق",
    ex6_title: "دعم فني مزيف",
    ex6_desc: "حسابك في خطر",
    ex7_title: "احتيال استثماري",
    ex7_desc: "أرباح سريعة مضمونة",
    ex8_title: "رسالة عادية مشروعة",
    ex8_desc: "تذكير بموعد",

    btnAbout: "عن التطبيق",
    btnMic: "بحث صوتي",
    micListening: "جارٍ الاستماع...",
    micNotSupported: "البحث الصوتي غير مدعوم في هذا المتصفح.",
    micError: "تعذّر الوصول إلى الميكروفون.",
    footerContact: "ملاحظات للمطوّر",

    aboutTitle: "كيف يعمل TRUST AI؟",
    aboutLead: "شرح موثوق وشفاف لمنهجية التحليل — بدون وعود مبالغ فيها.",
    aboutWhatTitle: "ما هو TRUST AI؟",
    aboutWhat: "منصة مفتوحة للسلامة الرقمية تساعد على تقييم الرسائل والروابط ولقطات الشاشة قبل اتخاذ قرار قد يكون خطيراً (الضغط على رابط، إرسال أموال، مشاركة بيانات حساسة). النتيجة تقييم مخاطر وليس حكماً مطلقاً.",
    aboutLayersTitle: "الطبقات المزدوجة",
    aboutLayer1Title: "الطبقة 1 — محرك القواعد (بدون إنترنت):",
    aboutLayer1: "يحلل النص محلياً في المتصفح وفق أنماط معروفة: الاستعجال، انتحال الهوية، طلب أموال، معلومات حساسة، روابط مشبوهة، عروض غير واقعية، وهندسة اجتماعية. لا يحتاج اتصالاً ولا مفتاحاً.",
    aboutLayer2Title: "الطبقة 2 — ذكاء اصطناعي (اختياري):",
    aboutLayer2: "عند تفعيل مفتاح API من مزوّدك (Groq أو Gemini أو OpenRouter أو OpenAI)، يُضاف تحليل لغوي أعمق وتحليل صور (رؤية) إن دعم النموذج ذلك. المفتاح يبقى في ذاكرة الجلسة فقط ولا يُرسل إلى أي خادم لـ TRUST AI.",
    aboutScoreTitle: "كيف تُحسب درجة الخطورة؟",
    aboutScore: "درجة من 0 إلى 100 تُبنى من فئات شفافة بأوزان ثابتة:",
    aboutCatUrgency: "الاستعجال والضغط — حتى 15 نقطة",
    aboutCatImpersonation: "انتحال الهوية — حتى 20 نقطة",
    aboutCatMoney: "طلب أموال — حتى 20 نقطة",
    aboutCatSensitive: "معلومات حساسة — حتى 20 نقطة",
    aboutCatLink: "مؤشرات الرابط — حتى 15 نقطة",
    aboutCatUnrealistic: "عروض غير واقعية — حتى 5 نقاط",
    aboutCatSocial: "هندسة اجتماعية — حتى 5 نقاط",
    aboutLevels: "المستويات: 0–24 منخفض · 25–49 متوسط · 50–74 مرتفع · 75–100 شديد. إن كانت المعلومات غير كافية يظهر «يحتاج تحقق إضافي».",
    aboutLinksTitle: "تحليل الروابط",
    aboutLinks: "يفحص المحرك نطاقات مشبوهة، انتحال علامات تجارية، عناوين IP، روابط مختصرة، ونطاقات punycode. النتيجة مؤشر مساعدة وليست دليلاً قاطعاً على الخطر.",
    aboutPrivacyTitle: "الخصوصية والحدود",
    aboutPrivacy1: "لا حسابات مستخدمين ولا تخزين دائم لمحتوى رسائلك أو صورك.",
    aboutPrivacy2: "مفاتيح API في الذاكرة فقط وتُمسح عند إغلاق الجلسة أو إلغاء التفعيل.",
    aboutPrivacy3: "لا ترسل كلمات مرور أو OTP أو بيانات بنكية حقيقية إلى أي خدمة.",
    aboutPrivacy4: "لا يضمن أي نظام أماناً بنسبة 100%. القرار النهائي دائماً لك.",
    aboutContactTitle: "تواصل مع المطوّر",
    aboutContactDesc: "لملاحظاتك أو اقتراحاتك أو الإبلاغ عن مشكلة، راسل المطوّر مباشرة:",
    aboutContactHint: "نرحب بملاحظاتكم لتحسين المنصة.",
  },

  en: {
    title: "TRUST AI",
    tagline: "Verify before you trust.",
    description: "Your trusted digital safety platform.",
    extra: "Analyze messages, links, and screenshots before you click, pay, reply, or share information.",
    inputLabel: "Paste the message or link here",
    inputPlaceholder: "Paste the message, link, or news here...",
    btnAnalyze: "Analyze now",
    btnUpload: "Upload screenshot",
    uploadHint: "If the file picker does not open: drag & drop the image here, or paste it (Ctrl+V).",
    btnExample: "Try an example",
    btnSettings: "Settings",
    privacyNote: "For your safety: do not send real passwords, OTPs, or banking data. Analysis runs locally or only via your chosen provider.",
    analyzing: "Analyzing...",
    analysisDone: "Analysis complete.",
    resultTitle: "Analysis result",
    riskScore: "Risk score",
    indicatorsCount: "Risk indicators",
    whyTitle: "Why?",
    actionTitle: "What to do?",
    breakdownTitle: "Point breakdown from the roots",
    categoriesTitle: "Category percentages",
    linksTitle: "Link analysis",
    modeOffline: "Offline mode (local rules)",
    modeAI: "AI client mode",
    modeHybrid: "Hybrid mode (rules + AI)",
    disclaimer: "TRUST AI provides a risk assessment based on known patterns and optional AI analysis. It cannot guarantee absolute 100% safety. The final decision is yours.",
    btnAgain: "New analysis",
    btnBack: "Back",
    examplesTitle: "Demo examples",
    examplesNote: "These are fictional scenarios for testing only.",
    footer: "TRUST AI v1.0 — Verify before you trust. Open platform for digital safety.",
    removeImage: "Remove image",
    close: "Close",
    settingsTitle: "AI Settings (optional)",
    settingsDesc: "The app works fully without any key. Add a free key to enhance analysis and images.",
    modelLabel: "Model",
    apiKeyLabel: "API Key (hidden)",
    apiKeyPlaceholder: "Paste key here — stays in this session only",
    btnSaveAI: "Save & enable",
    btnClearAI: "Disable",
    btnTestAI: "Test connection",
    aiConnected: "Connected",
    aiDisconnected: "Disconnected — running in local mode",
    freeModelsNote: "Free models — get your key from the official link:",
    getKey: "Get API key",
    connectionOk: "Connection successful ✓",
    connectionFail: "Connection failed",
    confidence: "Analysis confidence",
    aiSummary: "AI summary",
    percentOfMax: "% of max",
    points: "points",
    host: "Host",
    linkScore: "Link score",
    noLinks: "No links found",
    imageNote: "Image uploaded — full analysis requires a vision-capable model",
    layerOffline: "Layer 1: Rule engine (offline)",
    layerAI: "Layer 2: AI model",

    level_low: "Low risk",
    level_medium: "Medium risk",
    level_high: "High risk",
    level_severe: "Severe risk",
    level_unknown: "Needs further verification",

    cat_urgency: "Urgency / pressure",
    cat_impersonation: "Impersonation",
    cat_money: "Money request",
    cat_sensitive: "Sensitive data",
    cat_link: "Link indicators",
    cat_unrealistic: "Unrealistic offers",
    cat_socialEngineering: "Social engineering",

    reason_urgency: "The message uses urgency and time pressure.",
    reason_impersonation: "Contains patterns that may indicate impersonation of an official or known entity.",
    reason_money: "Requests money transfer, fees, or gift cards.",
    reason_sensitive: "Requests sensitive information such as password, OTP, or banking data.",
    reason_unrealistic: "Contains unrealistic promises or offers (prize, guaranteed profits, etc.).",
    reason_socialEngineering: "Tries to isolate you from normal verification channels or demands secrecy.",
    reason_link: "The link has characteristics that warrant extra verification.",
    reason_insufficient: "Insufficient information for a reliable analysis.",
    reason_image_unavailable: "Full screenshot analysis requires a vision-capable model (Gemini or GPT-4o).",

    action_no_link: "Do not click the link.",
    action_no_money: "Do not send money or pay fees.",
    action_no_sensitive: "Do not share your password, OTP, or banking data.",
    action_contact_official: "Contact the entity only via its official website or phone number.",
    action_verify: "Verify the source through an independent trusted channel.",
    action_delete: "Delete or ignore the message if it looks suspicious.",
    action_low: "No clear fraud indicators detected, but this does not guarantee safety. Stay cautious.",
    action_unknown: "Please provide the message text or link for a more accurate analysis.",

    error_empty: "Please enter a message, a link, or upload an image.",
    error_generic: "An error occurred during analysis. Please try again.",
    error_image_type: "Unsupported image type. Use JPG, PNG, or WEBP.",
    error_image_size: "Image is too large. Maximum size is 5 MB.",
    error_invalid_url: "Invalid URL.",

    ex1_title: "Fake bank message",
    ex1_desc: "Requests account confirmation with OTP",
    ex2_title: "Fake delivery message",
    ex2_desc: "Urgent delivery fee",
    ex3_title: "Fake job offer",
    ex3_desc: "Huge salary with no requirements",
    ex4_title: "Fake prize",
    ex4_desc: "You won a prize you never entered",
    ex5_title: "OTP request",
    ex5_desc: "Tech support asks for verification code",
    ex6_title: "Fake tech support",
    ex6_desc: "Your account is at risk",
    ex7_title: "Investment scam",
    ex7_desc: "Guaranteed quick profits",
    ex8_title: "Legitimate normal message",
    ex8_desc: "Meeting reminder",

    btnAbout: "About",
    btnMic: "Voice input",
    micListening: "Listening...",
    micNotSupported: "Voice input is not supported in this browser.",
    micError: "Could not access the microphone.",
    footerContact: "Feedback to developer",

    aboutTitle: "How does TRUST AI work?",
    aboutLead: "A reliable, transparent explanation of the analysis methodology — no exaggerated promises.",
    aboutWhatTitle: "What is TRUST AI?",
    aboutWhat: "An open digital safety platform that helps assess messages, links, and screenshots before a risky decision (clicking a link, sending money, sharing sensitive data). The result is a risk assessment, not an absolute verdict.",
    aboutLayersTitle: "Dual layers",
    aboutLayer1Title: "Layer 1 — Rule engine (offline):",
    aboutLayer1: "Analyzes text locally in the browser against known patterns: urgency, impersonation, money requests, sensitive data, suspicious links, unrealistic offers, and social engineering. No connection or key required.",
    aboutLayer2Title: "Layer 2 — AI (optional):",
    aboutLayer2: "When you enable an API key from your provider (Groq, Gemini, OpenRouter, or OpenAI), deeper language analysis and image (vision) analysis are added if the model supports it. The key stays in session memory only and is never sent to any TRUST AI server.",
    aboutScoreTitle: "How is the risk score calculated?",
    aboutScore: "A score from 0 to 100 built from transparent categories with fixed weights:",
    aboutCatUrgency: "Urgency / pressure — up to 15 points",
    aboutCatImpersonation: "Impersonation — up to 20 points",
    aboutCatMoney: "Money request — up to 20 points",
    aboutCatSensitive: "Sensitive data — up to 20 points",
    aboutCatLink: "Link indicators — up to 15 points",
    aboutCatUnrealistic: "Unrealistic offers — up to 5 points",
    aboutCatSocial: "Social engineering — up to 5 points",
    aboutLevels: "Levels: 0–24 low · 25–49 medium · 50–74 high · 75–100 severe. If information is insufficient, “Needs further verification” is shown.",
    aboutLinksTitle: "Link analysis",
    aboutLinks: "The engine checks suspicious TLDs, brand spoofing, IP hosts, shorteners, and punycode. The result is a helpful indicator, not definitive proof of danger.",
    aboutPrivacyTitle: "Privacy and limits",
    aboutPrivacy1: "No user accounts and no permanent storage of your messages or images.",
    aboutPrivacy2: "API keys stay in memory only and are cleared when the session ends or you disable them.",
    aboutPrivacy3: "Do not send real passwords, OTPs, or banking data to any service.",
    aboutPrivacy4: "No system can guarantee 100% safety. The final decision is always yours.",
    aboutContactTitle: "Contact the developer",
    aboutContactDesc: "For feedback, suggestions, or to report an issue, email the developer directly:",
    aboutContactHint: "We welcome your feedback to improve the platform.",
  },
};

let currentLang = "ar";

export function getLang() {
  return currentLang;
}

export function setLang(lang) {
  if (!translations[lang]) return;
  currentLang = lang;
  document.documentElement.lang = lang;
  document.documentElement.dir = lang === "ar" ? "rtl" : "ltr";
  applyTranslations();
  try {
    localStorage.setItem("trustai_lang", lang);
  } catch (_) {}
}

export function t(key) {
  return translations[currentLang][key] || translations.en[key] || key;
}

export function applyTranslations() {
  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.getAttribute("data-i18n");
    if (key && translations[currentLang][key] !== undefined) {
      el.textContent = translations[currentLang][key];
    }
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    const key = el.getAttribute("data-i18n-placeholder");
    if (key && translations[currentLang][key] !== undefined) {
      el.placeholder = translations[currentLang][key];
    }
  });
  document.querySelectorAll("[data-i18n-aria]").forEach((el) => {
    const key = el.getAttribute("data-i18n-aria");
    if (key && translations[currentLang][key] !== undefined) {
      el.setAttribute("aria-label", translations[currentLang][key]);
    }
  });
}

export function initI18n() {
  let saved = null;
  try {
    saved = localStorage.getItem("trustai_lang");
  } catch (_) {}
  const lang = saved === "en" || saved === "ar" ? saved : "ar";
  setLang(lang);
}

export { translations };
