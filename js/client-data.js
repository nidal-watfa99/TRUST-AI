/**
 * TRUST AI — Client data (بيانات العميل)
 * Playbooks that explain each kind of event, detection patterns,
 * and official verification tools. Pure data — no DOM.
 */

/** Event types, scored by how many signal groups match the input. */
export const TYPE_SIGNALS = {
  phishing: [
    /otp|رمز\s*(?:التحقق|التأكيد|الدخول|الأمان)|verification code|one[- ]time/i,
    /تسجيل\s*الدخول|log\s*in|sign\s*in|كلمة\s*(?:المرور|السر)|password/i,
    /تعليق|تجميد|إغلاق|حظر|suspend|locked|blocked|deactivat|restricted/i,
    /تحقق\s*من\s*(?:حسابك|هويتك|بياناتك)|verify\s*(?:your\s*)?(?:account|identity|details)/i,
    /بنك|مصرف|bank|paypal|apple\s*id|microsoft|netflix|حسابك/i,
  ],
  advance_fee: [
    /ميراث|وصية|تركة|inheritance|beneficiary|next of kin|late (?:client|father|husband)/i,
    /جائزة|فزت|ربحت|يانصيب|سحب|lottery|winner|you (?:have )?won|prize/i,
    /رسوم\s*(?:تحويل|تسجيل|شحن|جمارك|إفراج|ضريبة)|(?:transfer|processing|clearance|release|customs)\s*fee/i,
    /مليون|million|ملايين/i,
    /تحويل\s*(?:سري|مبلغ)|funds? transfer|confidential\s*(?:business|transaction)/i,
  ],
  pyramid: [
    /شبكة\s*(?:تسويق|أعضاء)|تسويق\s*(?:شبكي|هرمي)|network marketing|mlm|pyramid|downline|upline/i,
    /(?:اجلب|استقطب|جنّد|اضم|أحضر)\s*\S*\s*(?:3|ثلاثة|أشخاص|أصدقاء)|recruit|refer\s*\d+\s*(?:people|friends)/i,
    /رسوم\s*(?:اشتراك|انتساب|تسجيل)|membership fee|registration fee|starter pack|عضوية/i,
    /دخل\s*(?:سلبي|ثابت|شهري)|passive income|financial freedom|حرية\s*مالية|غيّر\s*حياتك|change your life/i,
    /qnet|questnet|quest\s*net|كويست\s*نت|كيونت|qi\s*group|goldquest|forsage|onecoin|hyperverse/i,
  ],
  crypto_invest: [
    /crypto|bitcoin|btc|usdt|ethereum|trx|عملات?\s*(?:رقمية|مشفرة)|بيتكوين|تداول/i,
    /airdrop|إيردروب|presale|بيع\s*مسبق|token|توكن|nft/i,
    /seed\s*phrase|recovery phrase|private key|عبارة\s*(?:الاسترداد|الاستعادة)|مفتاح\s*خاص|wallet|محفظة/i,
    /signals?|إشارات|توصيات|أرباح\s*(?:مضمونة|يومية)|guaranteed\s*(?:profit|returns?)|roi|عائد\s*يومي/i,
    /مضاعفة|double your|x\d{2,}|\d{2,}\s*%\s*(?:يومياً|شهرياً|daily|weekly|monthly)/i,
  ],
  impersonation: [
    /الدعم\s*الفني|technical support|help\s*desk|customer (?:care|service)|خدمة\s*العملاء/i,
    /أنا\s*(?:من|موظف|ضابط|مدير)|this is\s*(?:the\s*)?(?:officer|agent|manager|department)|وزارة|شرطة|police|fbi|interpol|الأمم\s*المتحدة/i,
    /رقمي\s*(?:الجديد|تغيّر)|new number|my phone (?:broke|is broken)|جوالي\s*(?:انكسر|تعطل)|ماما|بابا|mom|dad/i,
    /أرسل\s*(?:لي|شحن|رصيد)|send me (?:money|a gift card)|بطاقات?\s*(?:هدايا|شحن)|gift\s*cards?/i,
  ],
  job_scam: [
    /وظيفة|فرصة\s*عمل|توظيف|job offer|hiring|remote job|work from home|عمل\s*من\s*(?:المنزل|البيت)/i,
    /راتب\s*(?:مغري|عالٍ|\d+)|salary|per\s*(?:day|hour)|يومياً\s*\$?\d+/i,
    /رسوم\s*(?:تدريب|تأمين|ملف|معاينة)|training fee|deposit|equipment fee|تأمين\s*مسترد/i,
    /بدون\s*(?:خبرة|مؤهل)|no experience|لا\s*تحتاج\s*خبرة/i,
  ],
  romance: [
    /حبيبي|عزيزي|حبيبتي|my love|darling|sweetheart|i love you|أحبك/i,
    /جندي|ضابط|طبيب\s*في|مهندس\s*(?:نفط|بحري)|soldier|oil rig|deployed|widow|أرمل/i,
    /طارئ|مستشفى|تذكرة|emergency|hospital|plane ticket|customs/i,
    /ساعدني|لا\s*أستطيع\s*الوصول|can'?t access my (?:account|funds)|need your help/i,
  ],
  parcel: [
    /طرد|شحنة|بضاعة|parcel|package|shipment|delivery|توصيل|تتبع/i,
    /dhl|fedex|ups|aramex|smsa|usps|البريد|الجمارك|customs/i,
    /رسوم\s*(?:توصيل|جمارك|إعادة\s*جدولة)|redelivery|reschedule|delivery fee/i,
  ],
  extortion: [
    /سأ?نشر|سنفضح|سأرسل\s*(?:صورك|فيديو)|i will (?:leak|expose|publish|send)|your (?:photos|videos|secrets)/i,
    /ادفع\s*(?:وإلا|أو)|pay\s*(?:or|else|within)|bitcoin\s*(?:or|else)|لدي\s*(?:صور|فيديو|تسجيل)|i have (?:recorded|hacked|access)/i,
    /اخترقت|hacked your|webcam|كاميرا\s*(?:جهازك|الكمبيوتر)/i,
  ],
  charity: [
    /تبرع|تبرعات|إغاثة|زكاة|صدقة|donat|charity|relief fund|gofundme|crowdfund/i,
    /أطفال|ضحايا|زلزال|حرب|victims|earthquake|orphans|refugees/i,
    /حوّل\s*(?:إلى|على)|wallet|رقم\s*(?:حساب|محفظة)|iban|account number/i,
  ],
  fake_news: [
    /عاجل|breaking|خبر\s*(?:عاجل|صادم|خطير)|just in|urgent news/i,
    /مصادر\s*(?:مطلعة|خاصة|موثوقة)|insiders?|sources?\s*(?:say|said|close)|يقال|تقول\s*التقارير|ذكرت\s*مصادر/i,
    /شارك|انشر|وزّع|forward|share\s*(?:this|it|before)|قبل\s*أن\s*(?:يحذف|تُحذف)|before (?:it'?s |they )?(?:deleted|removed|banned)/i,
    /لن\s*تصدق|الإعلام\s*(?:يخفي|لا\s*يريدك)|they don'?t want you|mainstream media|cover[- ]?up|مؤامرة|فضيحة|shocking/i,
  ],
  health_hoax: [
    /علاج\s*(?:نهائي|معجزة|سحري)|miracle cure|cures?\s*(?:cancer|diabetes|covid)|يشفي\s*من|شفاء\s*تام/i,
    /الأطباء\s*(?:يخفون|لا\s*يريدونك)|doctors? (?:hate|don'?t want|hide)|big pharma|شركات\s*الأدوية/i,
    /لقاح|vaccine|سرطان|cancer|سكري|diabetes|فيروس|virus/i,
    /طبيعي\s*100|100%\s*(?:natural|طبيعي)|بدون\s*آثار\s*جانبية|no side effects/i,
  ],
};

/** Detection helpers used by the engine */
export const PATTERNS = {
  secrecy: /لا\s*ت(?:ُ)?خبر|لا\s*تشارك\s*(?:مع)?\s*أحد|بسرية(?:\s*تامة)?|سرّ?ي\s*للغاية|keep (?:it )?(?:a )?secret|don'?t tell (?:anyone|your)|strictly confidential|between us/i,
  sensational: /عاجل|صادم|خطير|فضيحة|كارثة|لن\s*تصدق|مرعب|يهز|shocking|bombshell|breaking|unbelievable|you won'?t believe|outrage|scandal|horrifying/i,
  anonymousSource: /مصادر\s*(?:مطلعة|خاصة|مجهولة)|يقال|يُقال|تردد|حسب\s*ما\s*تردد|insiders?|sources?\s*(?:say|said|claim|close to)|reportedly|allegedly|rumou?rs?|some say|people are saying/i,
  absolute: /الجميع|كل\s*(?:الناس|العالم)|لا\s*أحد|دائماً|أبداً|100\s*%|مضمون|بدون\s*استثناء|everyone|nobody|always|never|guaranteed|proven|100\s*%/i,
  shareBait: /شارك|انشر|وزّع|أرسلها|حتى\s*يعرف|قبل\s*أن\s*يحذف|forward (?:this|to)|share (?:this|before|with)|spread the word|send to \d+/i,
  conspiracy: /الإعلام\s*(?:يخفي|لا\s*يريدك|الكاذب)|يخفون\s*(?:عنك|الحقيقة)|مؤامرة|cover[- ]?up|they don'?t want you|hidden truth|wake up|mainstream media/i,
  fear: /خطر|تهديد|هجوم|موت|وباء|انهيار|حرب|danger|threat|attack|death|collapse|war|deadly|crisis/i,
  dated: /\b(?:19|20)\d{2}\b|\b\d{1,2}[\/\-.]\d{1,2}[\/\-.]\d{2,4}\b|يناير|فبراير|مارس|أبريل|مايو|يونيو|يوليو|أغسطس|سبتمبر|أكتوبر|نوفمبر|ديسمبر|january|february|march|april|may|june|july|august|september|october|november|december/i,
  namedSource: /(?:وكالة|رويترز|الجزيرة|العربية|بي\s*بي\s*سي|سانا|وفا|reuters|associated press|\bap\b|\bafp\b|bbc|cnn|al jazeera|الأمم\s*المتحدة|منظمة\s*الصحة|\bwho\b|\bun\b|وزارة|بيان\s*رسمي|official statement|press release)/i,
  attribution: /(?:قال|صرّح|أعلن|وفقاً\s*ل|بحسب|نقلاً\s*عن|according to|said|stated|announced|told)\s+[\p{L}]{3,}/iu,
};

/** Known names flagged in public regulatory warnings / fraud cases */
export const WATCHLIST = [
  { re: /qnet|questnet|quest\s*net|كويست\s*نت|كيونت|qi\s*group/i, label: "QNET / QuestNet / QI Group" },
  { re: /onecoin|one\s*coin/i, label: "OneCoin" },
  { re: /bitconnect|bit\s*connect/i, label: "BitConnect" },
  { re: /forsage/i, label: "Forsage" },
  { re: /hyperverse|hyper\s*verse/i, label: "HyperVerse" },
  { re: /goldquest|gold\s*quest/i, label: "GoldQuest" },
];

/** Brands commonly impersonated — a name match means "verify the channel", not "bad" */
export const BRANDS = /paypal|binance|coinbase|amazon|apple|microsoft|google|facebook|meta|instagram|whatsapp|telegram|netflix|dhl|fedex|aramex|western union|moneygram|visa|mastercard|stc|بنك|مصرف|وزارة|الأمم\s*المتحدة|interpol|fbi|europol|واتساب|تيليجرام|باي\s*بال|بينانس/i;

export const HONORIFICS = /barrister|prince|princess|general|diplomat|ambassador|sheikh|الأمير|الأميرة|السفير|جنرال|المحامي|الشيخ|الدكتور|المدير\s*العام/i;

/** Playbooks: plain-language explanation for every event type */
export const PLAYBOOKS = {
  phishing: {
    ar: {
      title: "تصيّد احتيالي (Phishing)",
      what: "رسالة تنتحل جهة تثق بها — بنك أو منصة أو شركة — لتدفعك إلى فتح رابط مزيّف وإدخال كلمة المرور أو رمز التحقق.",
      how: ["تصلك رسالة تدّعي مشكلة في حسابك وتمنحك مهلة قصيرة جداً", "الرابط يقود إلى صفحة تشبه الموقع الحقيقي تماماً", "كل ما تكتبه فيها (كلمة مرور، OTP، بطاقة) يصل مباشرة للمحتال", "يستخدمه فوراً لسحب المال أو الاستيلاء على حسابك وحسابات أخرى"],
      harm: "سرقة الحساب والأموال وانتحال هويتك أمام معارفك.",
    },
    en: {
      title: "Phishing",
      what: "A message impersonates a party you trust — a bank, platform or company — to push you onto a fake link and get your password or verification code.",
      how: ["You get a message about a 'problem' with your account and a very short deadline", "The link leads to a page that looks exactly like the real site", "Whatever you type there (password, OTP, card) goes straight to the scammer", "They use it immediately to drain money or take over your accounts"],
      harm: "Account and money theft, and impersonation of you to your contacts.",
    },
  },
  advance_fee: {
    ar: {
      title: "احتيال الدفع المسبق (ميراث / جائزة / تحويل)",
      what: "وعد بمبلغ ضخم — ميراث أو جائزة أو تحويل سري — مقابل رسوم «بسيطة» تدفعها أولاً. المبلغ الموعود غير موجود.",
      how: ["يُعرض عليك مبلغ كبير بلا أي مجهود منك", "يُطلب منك دفع رسوم تحويل أو جمارك أو ضريبة", "بعد الدفع تظهر رسوم جديدة وأسباب جديدة للتأخير", "تستمر المطالب حتى تتوقف أنت، ولا يصلك شيء"],
      harm: "خسارة مبالغ متتالية، وغالباً تسليم صورة هويتك وبياناتك.",
    },
    en: {
      title: "Advance-fee fraud (inheritance / prize / transfer)",
      what: "A huge sum — inheritance, prize or secret transfer — is promised in exchange for a 'small' fee you pay first. The promised money does not exist.",
      how: ["You are offered a large sum with no effort", "You are asked to pay a transfer, customs or tax fee", "After you pay, new fees and new reasons for delay appear", "Demands continue until you stop — nothing ever arrives"],
      harm: "Repeated payments lost, and often your ID and personal data handed over.",
    },
  },
  pyramid: {
    ar: {
      title: "هرم مالي / تسويق شبكي مشبوه",
      what: "نظام يعتمد على رسوم اشتراك وتجنيد أشخاص جدد، لا على بيع منتج حقيقي. أرباح المنضمين الأوائل تأتي من أموال المنضمين الجدد.",
      how: ["وعد بدخل كبير أو «حرية مالية» خلال أشهر", "رسوم انضمام مرتفعة أو «باقة بداية»", "شرط تجنيد أشخاص (غالباً الأهل والأصدقاء) للحصول على العمولة", "ضغط للسرية أو لبيع ممتلكات أو الاستدانة، ثم ينهار الهرم عند نفاد الداخلين"],
      harm: "خسارة رأس المال والديون، وتخريب العلاقات بعد استقطاب المقرّبين، وغالباً ملاحقة قانونية.",
    },
    en: {
      title: "Pyramid scheme / suspicious network marketing",
      what: "A system that depends on joining fees and recruiting new people rather than selling a real product. Early members are paid from newcomers' money.",
      how: ["Promise of big income or 'financial freedom' within months", "High joining fee or a 'starter pack'", "You must recruit people (often family and friends) to earn commission", "Pressure for secrecy, selling assets or borrowing — then it collapses when recruits run out"],
      harm: "Lost capital and debt, damaged relationships after recruiting loved ones, and possible legal exposure.",
    },
  },
  crypto_invest: {
    ar: {
      title: "استثمار / عملات رقمية وهمية",
      what: "عرض ربح مضمون أو مضاعفة أموال بالعملات الرقمية، أو طلب «عبارة الاسترداد» للمحفظة، أو إيردروب مزيّف.",
      how: ["يظهر عرض أرباح يومية أو «توصيات مضمونة»", "تُعرض أرباح صغيرة مبكرة لبناء الثقة", "يُطلب إيداع أكبر أو ربط محفظتك بموقع", "ينسحب المحتال أو تُفرَّغ محفظتك عبر عقد خبيث"],
      harm: "خسارة كاملة للأصول الرقمية، ولا تُسترد التحويلات في الغالب.",
    },
    en: {
      title: "Fake investment / crypto scam",
      what: "A guaranteed-profit or 'double your money' offer, a request for your wallet recovery phrase, or a fake airdrop.",
      how: ["Daily profits or 'guaranteed signals' are advertised", "Small early 'returns' are shown to build trust", "You are asked for a bigger deposit or to connect your wallet to a site", "The operator disappears or a malicious contract drains your wallet"],
      harm: "Total loss of digital assets — transfers are rarely recoverable.",
    },
  },
  impersonation: {
    ar: {
      title: "انتحال هوية (دعم فني / جهة رسمية / قريب)",
      what: "شخص يدّعي أنه موظف دعم أو ضابط أو قريب بجهاز جديد، ليطلب منك مالاً أو وصولاً إلى جهازك أو بياناتك.",
      how: ["يتصل أو يراسل بصفة تثير الثقة أو الخوف", "يخلق موقفاً عاجلاً (حسابك مخترق، قريبك في ورطة)", "يطلب تحويلاً أو بطاقات شحن أو تثبيت برنامج تحكّم عن بُعد", "يختفي فور استلام المال"],
      harm: "خسارة مالية مباشرة أو سيطرة كاملة على جهازك.",
    },
    en: {
      title: "Impersonation (support / official / relative)",
      what: "Someone claims to be support staff, an officer or a relative on a new phone, to get money, device access or data from you.",
      how: ["They call or message in a role that builds trust or fear", "They create urgency (your account is hacked, a relative is in trouble)", "They ask for a transfer, gift cards or a remote-control app", "They vanish once the money lands"],
      harm: "Direct financial loss or full takeover of your device.",
    },
  },
  job_scam: {
    ar: {
      title: "وظيفة وهمية",
      what: "عرض عمل مغرٍ يطلب منك دفع رسوم تدريب أو تأمين أو معدات، أو يستخدم «المهمة» لتبييض أموال أو جمع بياناتك.",
      how: ["راتب مرتفع بلا خبرة ولا مقابلة حقيقية", "تواصل عبر واتساب أو تيليجرام فقط", "طلب رسوم أو بيانات هوية وحساب بنكي", "قد تُستغل في استلام وتحويل أموال مسروقة"],
      harm: "خسارة الرسوم، وسرقة الهوية، وأحياناً تورّطك قانونياً في تحويل أموال مشبوهة.",
    },
    en: {
      title: "Fake job offer",
      what: "A tempting job that asks you to pay training, deposit or equipment fees — or uses the 'work' to launder money or harvest your data.",
      how: ["High pay with no experience and no real interview", "Contact only via WhatsApp or Telegram", "Requests for fees, ID and bank details", "You may be used to receive and forward stolen money"],
      harm: "Lost fees, identity theft, and sometimes legal exposure for moving illicit funds.",
    },
  },
  romance: {
    ar: {
      title: "احتيال عاطفي",
      what: "علاقة تُبنى عن بُعد بسرعة، ثم تظهر «أزمة» تحتاج مالاً: مستشفى، تذكرة، جمارك.",
      how: ["ملف جذّاب وتودّد سريع وكلمات حب مبكرة", "رفض المكالمات المرئية وتأجيل اللقاء", "ظهور أزمة مفاجئة وطلب مساعدة مالية", "تتكرر الطلبات وتزيد قيمتها"],
      harm: "خسائر مالية كبيرة وأذى نفسي، وقد تُستخدم صورك لابتزازك.",
    },
    en: {
      title: "Romance scam",
      what: "A relationship built quickly at a distance, followed by a 'crisis' that needs money: hospital, ticket, customs.",
      how: ["Attractive profile and fast affection, early declarations of love", "Refuses video calls and keeps postponing meetings", "A sudden emergency and a request for money", "Requests repeat and grow"],
      harm: "Major financial loss and emotional harm; your photos may be used to blackmail you.",
    },
  },
  parcel: {
    ar: {
      title: "طرد / جمارك / توصيل مزيّف",
      what: "رسالة عن شحنة معلّقة تطلب «رسوم صغيرة» أو تحديث عنوانك عبر رابط مزيّف.",
      how: ["رسالة قصيرة عن طرد لم يُسلَّم", "رابط لتتبّع الشحنة أو دفع رسم", "صفحة دفع تسرق بيانات بطاقتك", "تُستخدم البيانات لاحقاً في عمليات شراء"],
      harm: "سرقة بيانات البطاقة والدفع بلا مقابل.",
    },
    en: {
      title: "Fake parcel / customs / delivery notice",
      what: "A message about a pending parcel asking for a 'small fee' or an address update through a fake link.",
      how: ["A short text about an undelivered parcel", "A link to track the parcel or pay a fee", "A payment page that steals your card details", "The data is used later for purchases"],
      harm: "Card data theft and payment for nothing.",
    },
  },
  extortion: {
    ar: {
      title: "ابتزاز / تهديد",
      what: "تهديد بنشر صور أو معلومات أو بوجود اختراق لجهازك، مقابل مبلغ يُدفع فوراً — وغالباً التهديد كاذب.",
      how: ["رسالة مخيفة تدّعي امتلاك مواد عنك", "قد تتضمن كلمة مرور قديمة لإثبات المصداقية (من تسريبات قديمة)", "مهلة قصيرة للدفع بعملة رقمية", "بعد الدفع تتكرر المطالب"],
      harm: "ضغط نفسي وخسارة مالية، والدفع لا يوقف الابتزاز.",
    },
    en: {
      title: "Extortion / threat",
      what: "A threat to publish photos or data, or a claim your device was hacked, unless you pay immediately — usually a bluff.",
      how: ["A scary message claims to hold material about you", "It may quote an old password from a past leak as 'proof'", "A short deadline to pay in crypto", "After you pay, demands repeat"],
      harm: "Psychological pressure and financial loss; paying does not stop it.",
    },
  },
  charity: {
    ar: {
      title: "تبرعات / إغاثة وهمية",
      what: "نداء عاطفي بعد كارثة أو لحالة إنسانية، برقم حساب أو محفظة لا تعود لجهة موثّقة.",
      how: ["قصة مؤثرة وصور بلا مصدر", "حساب شخصي أو محفظة رقمية بدل جهة مسجّلة", "ضغط للتحويل السريع وللنشر", "لا تقارير ولا إيصالات"],
      harm: "تذهب أموالك للمحتال ولا تصل لمحتاج.",
    },
    en: {
      title: "Fake charity / relief appeal",
      what: "An emotional appeal after a disaster or for a humanitarian case, with an account or wallet that does not belong to a verified organization.",
      how: ["A moving story and photos with no source", "A personal account or crypto wallet instead of a registered body", "Pressure to transfer quickly and to share", "No reports and no receipts"],
      harm: "Your money goes to the scammer and never reaches anyone in need.",
    },
  },
  fake_news: {
    ar: {
      title: "خبر مضلّل / شائعة",
      what: "محتوى مصاغ ليُصدَّق وينتشر، لا ليُوثَّق: عنوان صادم، مصدر مجهول، وطلب مشاركة قبل التحقق.",
      how: ["عنوان عاطفي («عاجل»، «فضيحة») يستثير الخوف أو الغضب", "مصدر غير مسمّى أو «مصادر مطلعة»", "تعميمات مطلقة ولا تواريخ أو أرقام قابلة للتحقق", "طلب نشره فوراً، فينتشر قبل أن يُدحض"],
      harm: "ذعر وقرارات خاطئة وتشويه سمعة أشخاص أو جهات، وقد يُستخدم لتمهيد احتيال.",
    },
    en: {
      title: "Misleading news / rumor",
      what: "Content built to be believed and spread, not verified: a shocking headline, an unknown source and a request to share before checking.",
      how: ["An emotional headline ('BREAKING', 'scandal') triggers fear or anger", "An unnamed source or 'insiders'", "Sweeping claims with no verifiable dates or figures", "A push to share at once so it spreads before it is debunked"],
      harm: "Panic, bad decisions and reputational damage — and it can pave the way for fraud.",
    },
  },
  health_hoax: {
    ar: {
      title: "معلومة صحية مضلّلة / علاج معجزة",
      what: "ادّعاء علاجي بلا دليل علمي، يعد بشفاء تام أو يتهم الأطباء بالإخفاء، غالباً لبيع منتج.",
      how: ["وعد بشفاء من مرض خطير بوصفة بسيطة", "اتهام الأطباء وشركات الأدوية بإخفاء الحقيقة", "غياب أي دراسة أو جهة طبية مسمّاة", "رابط لشراء المنتج أو الانضمام لمجموعة"],
      harm: "تأخير العلاج الحقيقي وأضرار صحية ومالية.",
    },
    en: {
      title: "Health misinformation / miracle cure",
      what: "A medical claim without scientific evidence that promises a full cure or accuses doctors of hiding the truth — usually to sell a product.",
      how: ["A simple recipe promised to cure a serious disease", "Doctors and drug companies accused of a cover-up", "No study and no named medical body", "A link to buy the product or join a group"],
      harm: "Delayed real treatment and health and financial damage.",
    },
  },
  neutral: {
    ar: {
      title: "لا نمط احتيال واضح",
      what: "لم يطابق المحتوى أي نمط احتيال معروف في المحرك المحلي. هذا لا يثبت صحته: التحليل المحلي لا يستطيع التحقق من الوقائع.",
      how: ["المحرك يفحص أنماط اللغة والروابط فقط", "صحة الادعاءات تتطلب مصدراً ثانياً مستقلاً", "فعّل نموذجاً من لوحة النماذج لفحص منطقي أعمق"],
      harm: "غياب المؤشرات ليس ضماناً؛ راجع أدوات التحقق أدناه.",
    },
    en: {
      title: "No clear fraud pattern",
      what: "The content matched no known fraud pattern in the local engine. That does not prove it is true: local analysis cannot verify facts.",
      how: ["The engine checks language patterns and links only", "Verifying claims needs an independent second source", "Enable a model from the models panel for deeper reasoning"],
      harm: "No signals is not a guarantee; use the verification tools below.",
    },
  },
};

/** Official / well-known verification tools. {q} is replaced by the encoded query. */
export const TOOLS = [
  { id: "search", ar: "بحث عن الاسم أو العنوان مع كلمة «احتيال»", en: "Search the name/headline plus 'scam'", url: "https://www.google.com/search?q={q}%20%D8%A7%D8%AD%D8%AA%D9%8A%D8%A7%D9%84%20OR%20scam%20OR%20fake", kinds: ["name", "news", "message", "url", "mixed", "image"] },
  { id: "factcheck", ar: "مستكشف تدقيق الحقائق (Google)", en: "Google Fact Check Explorer", url: "https://toolbox.google.com/factcheck/explorer/search/{q}", kinds: ["news", "name", "message", "mixed"] },
  { id: "afp", ar: "تدقيق الحقائق — AFP", en: "AFP Fact Check", url: "https://factcheck.afp.com/", kinds: ["news", "mixed", "image"] },
  { id: "lens", ar: "بحث عكسي عن الصورة — Google Lens", en: "Reverse image search — Google Lens", url: "https://lens.google.com/", kinds: ["image", "mixed", "news"] },
  { id: "tineye", ar: "بحث عكسي عن الصورة — TinEye", en: "Reverse image search — TinEye", url: "https://tineye.com/", kinds: ["image", "mixed", "news"] },
  { id: "virustotal", ar: "فحص الرابط — VirusTotal", en: "Scan the link — VirusTotal", url: "https://www.virustotal.com/gui/home/url", kinds: ["url", "message", "mixed"] },
  { id: "urlscan", ar: "فحص الرابط — urlscan.io", en: "Scan the link — urlscan.io", url: "https://urlscan.io/", kinds: ["url", "message", "mixed"] },
  { id: "whois", ar: "عمر النطاق ومالكه — ICANN Lookup", en: "Domain age & owner — ICANN Lookup", url: "https://lookup.icann.org/", kinds: ["url", "message", "mixed"] },
  { id: "opencorp", ar: "سجل الشركات — OpenCorporates", en: "Company registry — OpenCorporates", url: "https://opencorporates.com/companies?q={q}", kinds: ["name", "message"] },
  { id: "wayback", ar: "أرشيف الإنترنت (Wayback Machine)", en: "Internet Archive (Wayback Machine)", url: "https://web.archive.org/", kinds: ["url", "news", "mixed"] },
];

/** UI strings */
export const L = {
  ar: {
    title: "العميل",
    subtitle: "أدخل أي شيء: رابطاً أو صورة أو اسماً أو خبراً أو رسالة. يعرض لك العميل ما يحدث بالضبط، وما خطره، وماذا تفعل.",
    close: "إغلاق", models: "لوحة النماذج",
    accepts: "يقبل: روابط · صور · أسماء · أخبار · رسائل · ملفات نصية",
    kindAuto: "تلقائي", kindUrl: "رابط", kindName: "اسم", kindNews: "خبر", kindMsg: "رسالة", kindImage: "صورة", kindMixed: "متعدد",
    placeholder: "الصق هنا رابطاً، أو اسم شخص/شركة، أو عنوان خبر، أو نص رسالة، أو اسحب صورة…",
    addFiles: "إضافة صور أو ملف", analyze: "حلّل الحدث", example: "مثال", clear: "مسح",
    dropHint: "اسحب الصور أو الملفات النصية هنا، أو الصقها (Ctrl+V). حتى ٤ صور.",
    stepOffline: "فحص محلي", stepAI: "تحليل النموذج", stepReport: "إعداد التقرير",
    empty: "أدخل محتوى أو أضف صورة أولاً.",
    verdict: "الحكم", detectedKind: "نوع المدخل", unverified: "غياب مؤشرات الخطر لا يعني أن المحتوى صحيح. التحقق من الوقائع يحتاج مصدراً مستقلاً.",
    unknownLevel: "يحتاج تحقق",
    eventTitle: "ما الحدث؟", eventType: "نوع الحدث", howTitle: "كيف يعمل عادةً", harmTitle: "الضرر المحتمل",
    warnTitle: "التحذيرات", noWarn: "لا تحذيرات حرجة مُكتشفة.",
    chartsTitle: "الرسوم البيانية",
    gaugeTitle: "مقياس الخطر", radarTitle: "بصمة المخاطر (٦ محاور)", donutTitle: "حصة كل فئة من الدرجة",
    arcTitle: "خطورة كل جملة بالترتيب", arcHint: "الاحتيال يتصاعد غالباً: ادّعاء ← استعجال ← طلب.", dimsTitle: "مستويات المحاور",
    credTitle: "مؤشرات المصداقية (من النموذج)", cred_source: "المصدر", cred_evidence: "الأدلة", cred_consistency: "الاتساق", cred_neutrality: "الحياد",
    d_manipulation: "تلاعب عاطفي", d_urgency: "استعجال", d_financial: "مطلب مالي/بيانات", d_impersonation: "انتحال", d_link: "الروابط", d_unverifiability: "صعوبة التحقق",
    noChartData: "لا توجد فئات مرصودة لعرضها.", cat_pattern: "نمط الحدث العام",
    entitiesTitle: "ما استُخرج من المدخل", e_urls: "روابط", e_emails: "بريد", e_phones: "هواتف", e_amounts: "مبالغ", e_crypto: "عناوين محافظ", e_handles: "حسابات", e_names: "أسماء وجهات",
    noEntities: "لم تُستخرج عناصر محددة.",
    linksTitle: "فحص الروابط", linkScore: "درجة",
    claimsTitle: "الادعاءات", v_supported: "مدعوم", v_unsupported: "بلا دليل", v_false: "خاطئ", v_misleading: "مضلّل", v_unverifiable: "غير قابل للتحقق",
    claimsOffline: "ادعاءات تحتاج إثباتاً (رصد محلي)",
    imagesTitle: "الصور المرفقة", imgNoVision: "الصور مرفقة لكن النموذج الحالي لا يدعم الرؤية. اختر نموذجاً بشارة «رؤية» (مثل Gemini) ليقرأ العميل نص الصورة ويحلل محتواها.",
    imgNoAI: "لتحليل محتوى الصور فعّل نموذجاً بشارة «رؤية» من لوحة النماذج. بدونه لا يستطيع العميل قراءة الصورة.",
    extracted: "النص المقروء من الصورة",
    aiTitle: "تحليل النموذج", aiOff: "العميل يعمل الآن بالقواعد المحلية فقط. أضف مفتاحاً من لوحة النماذج ليقرأ الصور ويحلل الأخبار والأسماء بعمق.",
    openModels: "فتح لوحة النماذج", aiRunning: "جارٍ تحليل النموذج…", aiFail: "تعذّر تحليل النموذج", confidence: "الثقة", limits: "حدود التحليل",
    aiPrivacy: "عند تفعيل نموذج، يُرسل النص والصور إلى مزوّدك المختار فقط.",
    verifyTitle: "أدوات التحقق الرسمية", queriesTitle: "عبارات بحث مقترحة", open: "فتح",
    actionsTitle: "ماذا تفعل الآن؟", doTitle: "افعل", dontTitle: "لا تفعل",
    sourceTitle: "التقرير التفصيلي للمصدر", sourceOpen: "عرض هوية المصدر وتسلسل الخبر والرسم الانسيابي",
    cannotOpen: "العميل لا يفتح الروابط ولا يتصفح الإنترنت. لا تفتح رابطاً مشبوهاً لاختباره.",
    copy: "نسخ التقرير", share: "مشاركة", print: "طباعة / PDF", again: "تحليل جديد", toMain: "عرض في الشاشة الرئيسية",
    copied: "تم نسخ التقرير ✓", done: "اكتمل التحليل", mode_offline: "محلي", mode_hybrid: "محلي + نموذج",
    fileTooBig: "الملف كبير جداً (الحد ٥ ميغابايت للصورة و٢٠٠ كيلوبايت للنص).", fileType: "نوع ملف غير مدعوم. المسموح: صور JPG/PNG/WEBP أو ملفات نصية.", maxImages: "الحد الأقصى ٤ صور.",
    d_do_default: ["لا تتصرف قبل التحقق من مصدر ثانٍ مستقل", "تواصل مع الجهة عبر قناتها الرسمية التي تعرفها أنت", "احتفظ بنسخة من الرسالة أو لقطة الشاشة"],
    d_dont_default: ["لا تشارك كلمات المرور أو الرموز أو بيانات البطاقة", "لا تحوّل مالاً لأي طلب عاجل أو سري", "لا تنشر المحتوى قبل التحقق"],
    levels: { low: "منخفض", medium: "متوسط", high: "مرتفع", severe: "شديد", unknown: "يحتاج تحقق" },
    sev: { critical: "حرج", high: "مرتفع", medium: "متوسط", info: "معلومة" },
    kindName2: { url: "رابط", name: "اسم", news: "خبر", message: "رسالة", image: "صورة", mixed: "متعدد", file: "ملف" },
    arcCol: "ج",
  },
  en: {
    title: "Client",
    subtitle: "Enter anything: a link, image, name, news item or message. The client shows exactly what is going on, how dangerous it is, and what to do.",
    close: "Close", models: "Models panel",
    accepts: "Accepts: links · images · names · news · messages · text files",
    kindAuto: "Auto", kindUrl: "Link", kindName: "Name", kindNews: "News", kindMsg: "Message", kindImage: "Image", kindMixed: "Mixed",
    placeholder: "Paste a link, a person/company name, a headline, a message — or drop an image…",
    addFiles: "Add images or file", analyze: "Analyze event", example: "Example", clear: "Clear",
    dropHint: "Drop images or text files here, or paste (Ctrl+V). Up to 4 images.",
    stepOffline: "Local scan", stepAI: "Model analysis", stepReport: "Building report",
    empty: "Enter content or add an image first.",
    verdict: "Verdict", detectedKind: "Input type", unverified: "No risk signals does not mean the content is true. Verifying facts needs an independent source.",
    unknownLevel: "Needs verification",
    eventTitle: "What is the event?", eventType: "Event type", howTitle: "How it usually works", harmTitle: "Potential harm",
    warnTitle: "Warnings", noWarn: "No critical warnings detected.",
    chartsTitle: "Charts",
    gaugeTitle: "Risk meter", radarTitle: "Risk fingerprint (6 axes)", donutTitle: "Each category's share of the score",
    arcTitle: "Risk of each sentence, in order", arcHint: "Scams usually escalate: claim → urgency → ask.", dimsTitle: "Axis levels",
    credTitle: "Credibility indicators (from model)", cred_source: "Source", cred_evidence: "Evidence", cred_consistency: "Consistency", cred_neutrality: "Neutrality",
    d_manipulation: "Emotional manipulation", d_urgency: "Urgency", d_financial: "Money / data ask", d_impersonation: "Impersonation", d_link: "Links", d_unverifiability: "Hard to verify",
    noChartData: "No categories detected to chart.", cat_pattern: "Overall event pattern",
    entitiesTitle: "Extracted from the input", e_urls: "Links", e_emails: "Emails", e_phones: "Phones", e_amounts: "Amounts", e_crypto: "Wallet addresses", e_handles: "Handles", e_names: "Names & orgs",
    noEntities: "No specific items extracted.",
    linksTitle: "Link inspection", linkScore: "Score",
    claimsTitle: "Claims", v_supported: "Supported", v_unsupported: "No evidence", v_false: "False", v_misleading: "Misleading", v_unverifiable: "Unverifiable",
    claimsOffline: "Claims that need proof (local detection)",
    imagesTitle: "Attached images", imgNoVision: "Images are attached but the current model has no vision. Pick a model with the 'Vision' badge (e.g. Gemini) so the client can read and analyze the image.",
    imgNoAI: "To analyze image content, enable a 'Vision' model from the models panel. Without it the client cannot read the image.",
    extracted: "Text read from the image",
    aiTitle: "Model analysis", aiOff: "The client is running on local rules only. Add a key from the models panel to read images and analyze news and names in depth.",
    openModels: "Open models panel", aiRunning: "Model analysis running…", aiFail: "Model analysis failed", confidence: "Confidence", limits: "Analysis limits",
    aiPrivacy: "When a model is enabled, text and images are sent only to your chosen provider.",
    verifyTitle: "Official verification tools", queriesTitle: "Suggested search phrases", open: "Open",
    actionsTitle: "What to do now", doTitle: "Do", dontTitle: "Don't",
    sourceTitle: "Detailed source report", sourceOpen: "Show source identity, story arc and flow graph",
    cannotOpen: "The client does not open links or browse the web. Never open a suspicious link to 'test' it.",
    copy: "Copy report", share: "Share", print: "Print / PDF", again: "New analysis", toMain: "Show in main screen",
    copied: "Report copied ✓", done: "Analysis complete", mode_offline: "Local", mode_hybrid: "Local + model",
    fileTooBig: "File too large (5 MB per image, 200 KB for text).", fileType: "Unsupported file. Allowed: JPG/PNG/WEBP images or text files.", maxImages: "Maximum 4 images.",
    d_do_default: ["Do nothing before checking an independent second source", "Contact the party through an official channel you already know", "Keep a copy of the message or a screenshot"],
    d_dont_default: ["Never share passwords, codes or card data", "Never transfer money for an urgent or secret request", "Don't share the content before verifying"],
    levels: { low: "Low", medium: "Medium", high: "High", severe: "Severe", unknown: "Needs verification" },
    sev: { critical: "Critical", high: "High", medium: "Medium", info: "Info" },
    kindName2: { url: "Link", name: "Name", news: "News", message: "Message", image: "Image", mixed: "Mixed", file: "File" },
    arcCol: "S",
  },
};

/** Warning texts */
export const W = {
  ar: {
    secrecy: "يُطلب منك الكتمان وعدم إخبار أحد — من أخطر علامات الاحتيال، لأن العزل يمنع أي شخص من إيقافك.",
    pyramid_name: "الاسم «{x}» ورد في تحذيرات رسمية أو قضايا احتيال/تسويق هرمي في بعض الدول. تحقق من تصريح الجهة المنظِّمة في بلدك قبل أي دفع.",
    brand_name: "الاسم «{x}» علامة يكثر انتحالها. تأكد من القناة الرسمية (موقع أو تطبيق تفتحه بنفسك) وليس من الرابط المُرسل.",
    honorific: "ألقاب فخمة (أمير، سفير، محامٍ…) تُستخدم كثيراً لإضفاء مصداقية في احتيال الدفع المسبق.",
    money: "الرسالة تطلب مالاً أو تحويلاً. لا تدفع قبل التحقق من الجهة عبر قناة رسمية مستقلة.",
    sensitive: "طلب بيانات حساسة (رمز/كلمة مرور/بطاقة). لا جهة رسمية تطلبها عبر رسالة أو رابط.",
    urgency: "ضغط زمني مصطنع. الاحتيال يعتمد على منعك من التفكير والتحقق.",
    impersonation: "الرسالة تنتحل جهة معروفة. اتصل بالجهة من رقمها الرسمي الذي تعرفه.",
    link: "الرابط يحمل مؤشرات تلاعب. لا تفتحه، ولا تُدخل أي بيانات فيه.",
    unrealistic: "عرض أو وعد غير واقعي. الربح المضمون والسريع مؤشر احتيال قوي.",
    sensational: "لغة صادمة أو عاطفية مصمَّمة للانتشار لا للتوثيق.",
    anonymous: "الخبر يستند إلى مصادر غير مسمّاة. الخبر الموثوق ينسب المعلومة لجهة يمكن التحقق منها.",
    shareBait: "يطلب منك النشر الفوري. المحتوى المضلّل ينتشر بهذه الطريقة قبل أن يُدحض.",
    absolute: "تعميمات مطلقة («الجميع»، «مضمون 100%») نادراً ما تصح في الواقع.",
    conspiracy: "خطاب «يخفون الحقيقة عنك» أسلوب شائع في المعلومات المضللة.",
    noSource: "لا مصدر مسمّى ولا تاريخ ولا رابط للتحقق — الخبر غير قابل للتوثيق كما هو.",
    sensitive_paste: "مدخلك يحتوي ما يشبه بياناً حساساً ({x}). احذفه فوراً ولا ترسله لأي خدمة، خصوصاً مزوّد النموذج.",
    image_no_vision: "لم تُحلَّل الصورة لأن لا نموذج رؤية مفعّل. لا تعتمد على هذه النتيجة وحدها.",
    name_only: "اسم مجرد: لا يستطيع العميل المحلي التحقق من هوية صاحبه. ابحث عنه في سجلات رسمية، ولا تحكم على شخص بدون دليل.",
    url_only: "لا يفتح العميل الرابط ولا يرى محتواه — الحكم مبني على شكل الرابط فقط.",
    offline_limit: "التحليل المحلي يكشف أنماط الاحتيال، ولا يتحقق من صحة الوقائع.",
    ai_privacy: "عند تفعيل نموذج، يُرسل المحتوى إلى مزوّد النموذج الذي اخترته.",
  },
  en: {
    secrecy: "You are asked to keep it secret and tell no one — one of the most dangerous scam signs, because isolation stops anyone from intervening.",
    pyramid_name: "The name “{x}” appears in public regulatory warnings or fraud/pyramid cases in some countries. Check your local regulator before paying anything.",
    brand_name: "“{x}” is a brand that is impersonated a lot. Confirm via the official channel (a site or app you open yourself) — not via the link you were sent.",
    honorific: "Grand titles (prince, ambassador, barrister…) are often used to lend credibility in advance-fee fraud.",
    money: "The message asks for money or a transfer. Do not pay before verifying through an independent official channel.",
    sensitive: "Asks for sensitive data (code/password/card). No legitimate party requests it by message or link.",
    urgency: "Artificial time pressure. Scams rely on stopping you from thinking and verifying.",
    impersonation: "The message impersonates a known party. Call them on the official number you already know.",
    link: "The link carries manipulation signs. Do not open it or enter any data.",
    unrealistic: "An unrealistic offer or promise. Fast guaranteed profit is a strong fraud sign.",
    sensational: "Shocking or emotional language built to spread, not to inform.",
    anonymous: "The story relies on unnamed sources. Reliable news attributes information to a party you can check.",
    shareBait: "It urges you to share immediately. Misleading content spreads this way before it is debunked.",
    absolute: "Sweeping claims ('everyone', '100% guaranteed') are rarely true in the real world.",
    conspiracy: "'They hide the truth from you' framing is a common disinformation tactic.",
    noSource: "No named source, no date and no link to check — the story cannot be verified as written.",
    sensitive_paste: "Your input looks like it contains sensitive data ({x}). Delete it now and do not send it to any service — especially a model provider.",
    image_no_vision: "The image was not analyzed because no vision model is enabled. Do not rely on this result alone.",
    name_only: "A bare name: the local client cannot verify who this is. Check official registries, and don't judge a person without evidence.",
    url_only: "The client does not open the link or see its content — the verdict is based on the link's shape only.",
    offline_limit: "Local analysis detects fraud patterns; it does not verify facts.",
    ai_privacy: "When a model is enabled, content is sent to the model provider you chose.",
  },
};

export const SENSITIVE_LABEL = {
  ar: { otp: "رمز تحقق", card: "رقم بطاقة", iban: "رقم حساب/IBAN", seed: "عبارة استرداد محفظة", password: "كلمة مرور" },
  en: { otp: "verification code", card: "card number", iban: "account/IBAN", seed: "wallet recovery phrase", password: "password" },
};
