<div align="center">

<img src="assets/logo.svg" alt="TRUST AI" width="96" height="96" />

# TRUST AI

### تحقق قبل أن تثق · Verify before you trust

منصة سلامة رقمية تساعدك على تقييم الرسائل والروابط ولقطات الشاشة المشبوهة **قبل** أن تضغط أو تدفع أو ترد أو تشارك بياناتك.

*A digital safety platform that helps you assess suspicious messages, links and screenshots before you click, pay, reply or share your data.*



![Version](https://img.shields.io/badge/version-1.2-22d3ee)




![License](https://img.shields.io/badge/license-MIT-22c55e)




![Offline](https://img.shields.io/badge/works-offline-0891b2)




![Languages](https://img.shields.io/badge/lang-AR%20%7C%20EN-eab308)




![No backend](https://img.shields.io/badge/backend-none-64748b)



</div>

---

## 🇸🇦 العربية

### نظرة عامة
**TRUST AI** تطبيق ويب ثابت (HTML / CSS / JavaScript) يعمل بالكامل داخل المتصفح. يحلّل النص أو الرابط أو لقطة الشاشة ويعطيك **درجة خطورة من 0 إلى 100** مع شرح شفاف لكل نقطة فيها، فلا تتلقى حكماً غامضاً بل أسباباً يمكن مراجعتها.

### المزايا الرئيسية

| الميزة | الوصف |
|---|---|
| 🛡️ **طبقتان للتحليل** | الطبقة 1: محرك قواعد محلي يعمل بلا إنترنت ولا مفتاح. الطبقة 2: ذكاء اصطناعي اختياري بمفتاحك الخاص |
| 📊 **درجة شفافة** | 7 فئات بأوزان ثابتة، مع جدول يبيّن النقاط ونسبة كل فئة |
| 🔗 **تحليل الروابط** | لاحقات مشبوهة، انتحال علامات تجارية، عناوين IP، روابط مختصرة، Punycode، رمز @ |
| 📑 **تقرير المصدر التفصيلي** | تشريح الرابط، الجهة المُدّعاة مقابل الفعلية، تسلسل الخطورة جملةً جملة، رسم مسار الخبر، رادار المخاطر |
| 🖼️ **لقطات الشاشة** | رفع أو سحب أو لصق (Ctrl+V)، وتحليل كامل عند ربط نموذج يدعم الرؤية |
| 🎙️ **إدخال صوتي** | إملاء الرسالة بالميكروفون عبر Web Speech API |
| 🚦 **مؤشرات LIVE** | أضواء أخضر / أزرق / برتقالي / أحمر تتفاعل مع مستوى الخطر |
| 🌍 **ثنائي اللغة** | عربية (RTL) وإنجليزية (LTR) مع تبديل فوري |
| 🧪 **أمثلة جاهزة** | 8 سيناريوهات تجريبية خيالية لتجربة التطبيق |
| 📱 **PWA** | قابل للتثبيت على الجوال أو سطح المكتب بأيقونة خاصة |
| 🔒 **خصوصية أولاً** | بلا حسابات، بلا خادم، ولا حفظ دائماً لمحتواك |

### فئات التقييم والأوزان

| الفئة | الحد الأقصى |
|---|---|
| الاستعجال والضغط | 15 |
| انتحال الهوية | 20 |
| طلب أموال | 20 |
| معلومات حساسة | 20 |
| مؤشرات الرابط | 15 |
| عروض غير واقعية | 5 |
| هندسة اجتماعية | 5 |

**المستويات:** 0–24 منخفض 🟢 · 25–49 متوسط 🟡 · 50–74 مرتفع 🟠 · 75–100 شديد 🔴
وعند نقص المعلومات يظهر «يحتاج تحقق إضافي».

### طريقة الاستخدام
1. افتح التطبيق.
2. الصق الرسالة أو الرابط في الحقل، أو اضغط 🎙️ للإملاء، أو ارفع لقطة شاشة.
3. اضغط **تحقق الآن**.
4. اقرأ الدرجة والأسباب والإجراءات الموصى بها.
5. اضغط **📊 تقرير المصدر التفصيلي** لتحليل أعمق مع الرسوم البيانية.
6. جرّب **تجربة مثال** إن أردت رؤية التطبيق على حالات جاهزة.

### تفعيل الذكاء الاصطناعي (اختياري)
من ⚙ الإعدادات اختر المزوّد وأدخل مفتاحك:

- **مجاني:** Groq (Llama) · Google Gemini · OpenRouter
- **مدفوع:** OpenAI (GPT-4o / GPT-4o mini)

المفتاح يبقى في **ذاكرة الجلسة فقط**، ولا يُحفظ ولا يُرسل إلى أي خادم تابع لـ TRUST AI.

### التشغيل محلياً
لا حاجة لأي تثبيت أو بناء. التطبيق يستخدم وحدات ES، فشغّله عبر خادم محلي بدل فتح الملف مباشرة:

```bash
git clone https://github.com/<USERNAME>/TRUST-AI.git
cd TRUST-AI
python3 -m http.server 8080
# ثم افتح http://localhost:8080
```

### النشر على GitHub Pages
المشروع يتضمن Action جاهزاً في `.github/workflows/deploy.yml`:

1. ارفع الملفات إلى فرع `main`.
2. من **Settings ← Pages ← Source** اختر **GitHub Actions**.
3. يُنشر الموقع تلقائياً عند كل `push`.

### هيكل المشروع
```
TRUST-AI/
├── index.html              # الواجهة
├── manifest.json           # إعداد PWA
├── css/styles.css          # التصميم
├── js/
│   ├── app.js              # المتحكم الرئيسي
│   ├── risk-engine.js      # محرك القواعد (بلا إنترنت)
│   ├── ai-provider.js      # عميل الذكاء الاصطناعي
│   ├── source-report.js    # تقرير المصدر والرسوم البيانية
│   ├── i18n.js             # الترجمة AR / EN
│   └── examples.js         # الأمثلة التجريبية
├── assets/                 # الشعار والأيقونات
├── tests/                  # اختبارات المحرك
└── .github/workflows/      # النشر التلقائي
```

### حدود يجب معرفتها
- النتيجة **تقييم مخاطر** وليست حكماً قاطعاً.
- المحرك المحلي لا يعرف عمر النطاق ولا سمعته ولا يتحقق من صحة الخبر من مصدر ثانٍ. تحقق منها بنفسك.
- لا تُدخل كلمات مرور أو رموز OTP أو بيانات بنكية حقيقية داخل أي أداة.

---

## 🇬🇧 English

### Overview
**TRUST AI** is a static web app (HTML / CSS / JavaScript) that runs entirely in your browser. It analyses text, links and screenshots and returns a **0–100 risk score** with a transparent, category-by-category explanation.

### Key features
- **Dual-layer analysis** — Layer 1: offline rule-based Risk Engine (no key, no internet). Layer 2: optional LLM enhancement and vision with your own API key.
- **Transparent scoring** — 7 weighted categories: urgency (15), impersonation (20), money (20), sensitive data (20), link (15), unrealistic offers (5), social engineering (5).
- **Link heuristics** — suspicious TLDs, brand spoofing, raw IPs, shorteners, punycode, `@` tricks, excessive subdomains.
- **Detailed source report** — link anatomy, claimed-vs-actual entity, sentence-by-sentence risk arc, message flow graph, risk radar, and a checklist of what can't be verified offline.
- **Screenshots** — upload, drag-and-drop or paste; full analysis with a vision-capable model.
- **Voice input** via the Web Speech API.
- **LIVE signal lights** — green / blue / orange / red reacting to the risk level.
- **Arabic (RTL) + English (LTR)** with instant switching.
- **8 fictional demo scenarios**, installable **PWA**, and **privacy-first** design (no accounts, no backend, no persistent storage of your content).

### Usage
1. Paste a message or link, dictate it with the mic, or upload a screenshot.
2. Press **Verify now**.
3. Review the score, reasons and recommended actions.
4. Open the **Detailed source report** for charts and deeper source analysis.

### Optional AI setup
Open ⚙ Settings, pick a provider and enter your key. Free: Groq, Google Gemini, OpenRouter. Paid: OpenAI. The key lives **in session memory only** and is never sent to any TRUST AI server.

### Run locally
```bash
git clone https://github.com/<USERNAME>/TRUST-AI.git
cd TRUST-AI
python3 -m http.server 8080   # open http://localhost:8080
```

### Deploy
Push to `main`, then set **Settings → Pages → Source → GitHub Actions**. The included workflow publishes the site automatically.

### Limitations
The score is a risk assessment, not proof. The offline engine cannot know domain age, reputation, or confirm news with an independent source — verify those yourself.

---

## 🤝 المساهمة · Contributing
الاقتراحات وتقارير الأخطاء مرحّب بها عبر Issues أو Pull Requests.
Suggestions and bug reports are welcome via Issues or Pull Requests.

## 👤 المطوّر · Developer
**Nidal Watfa**

| المنصة | الرابط |
|---|---|
| ✉️ البريد | [nidalwatfa99@gmail.com](mailto:nidalwatfa99@gmail.com) |
| 🐙 GitHub | [danial56hd-wq](https://github.com/danial56hd-wq) |
| 🦊 GitLab | [gitlab.com/nidalwatfa](https://gitlab.com/nidalwatfa) |
| 🏔️ Codeberg | [nidalwatfa](https://codeberg.org/nidalwatfa) |
| 💼 LinkedIn | [nidal-watfa](https://www.linkedin.com/in/nidal-watfa-a91720301) |
| 🐦 X | [@NidalWatfa12501](https://x.com/NidalWatfa12501) |
| 🆔 ORCID | [0009-0003-2462-6630](https://orcid.org/0009-0003-2462-6630) |

## 📄 الترخيص · License
مرخّص بموجب رخصة **MIT**. راجع ملف [LICENSE](LICENSE).
Released under the **MIT License**. See [LICENSE](LICENSE).

---

<div align="center">

**TRUST AI** — تحقق قبل أن تثق · Verify before you trust

</div>
