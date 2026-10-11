# 🛡 سياسة الأمان — TRUST AI v3.1 / Security Policy

> **English summary:** TRUST AI is a static, zero-dependency web app. v3.1 continues the layered defence
> (strict CSP, central `security.js`, clickjacking guard, hardened Service Worker, validated storage,
> feed-poisoning protection, prompt-injection defences, CI audit). Real HTTP headers need Cloudflare /
> Netlify (`_headers`, `headers-cloudflare.txt`). Report vulnerabilities privately by e-mail:
> **nidalwatfa99@gmail.com** — please do not disclose publicly before a fix.

## الإصدارات المدعومة

| الإصدار | الدعم الأمني |
|---------|--------------|
| 3.1.x   | ✅ مدعوم |
| 3.0.x   | ✅ مدعوم (ترقية موصى بها) |
| ≤ 2.1   | ❌ حدّث إلى 3.1 |

## الواقع التقني (بصراحة)

**GitHub Pages لا يرسل ترويسات HTTP مخصصة.** لذلك تعمل الحماية على مستويين:

1. **داخل التطبيق (فعّال دائماً):** CSP عبر `<meta>`، حارس الإطارات `js/guard.js`، وحدة `js/security.js`، Service Worker مقيّد.
2. **ترويسات حقيقية (تتطلب Cloudflare أو Netlify):** `frame-ancestors`، `X-Frame-Options`، HSTS، COOP/CORP، Permissions-Policy — الملفات جاهزة: `_headers` و`headers-cloudflare.txt`.

## طبقات الحماية في v3.1

| # | الطبقة | ما الذي تمنعه |
|---|--------|----------------|
| 1 | **CSP مشدد** — `script-src 'self'` + `script-src-attr 'none'` + `form-action 'none'` + `object-src 'none'` | حقن السكربتات والمعالجات المضمّنة، النماذج المخطوفة، الإضافات |
| 2 | **درع الإطارات** (`guard.js` + إخفاء الصفحة افتراضياً) | Clickjacking حتى بدون ترويسات الخادم |
| 3 | **ترميز المخرجات الموحّد** `escapeHtml` (يشمل `' \` =`) في كل الملفات | XSS / حقن HTML، حتى في سمات بلا علامات اقتباس |
| 4 | **فحص الروابط** `isSafeUrl` | `javascript:` و`data:` و`file:` وعناوين داخلية (IPv4/IPv6/عشري/سداسي عشري)، بيانات الدخول داخل الرابط، أسماء LAN |
| 5 | **التحقق من الصور** — بصمة الملف (Magic Bytes) + رفض SVG + حد أبعاد | صور مموّهة (SVG/HTML)، قنابل فك الضغط، وسوم EXIF (تُعاد ترميز الصورة) |
| 6 | **حماية مفاتيح API** — تحقق الصيغة، ذاكرة فقط، **الترويسات لا الروابط**، `redactSecrets` للأخطاء | حقن ترويسات HTTP (CRLF)، تسريب المفتاح في السجلات/الـReferrer |
| 7 | **دفاع حقن التعليمات (Prompt Injection)** — تحييد المحارف الخفية، تسييج المدخلات، قاعدة نظام صريحة، **درجة النموذج لا تخفّض درجة المحرك المحلي** | رسائل احتيال تحاول إقناع النموذج بأنها «آمنة» |
| 8 | **تطبيع مخرجات النموذج** (أنواع، أطوال، نطاقات) | محتوى خبيث أو ضخم قادم من المزوّد |
| 9 | **حماية قاعدة الاحتيال الحيّة** — تحقق صارم من أسماء النطاقات، قائمة نطاقات محمية، حد حجم 3MB، بلا Cookies/Referrer | تسميم المصدر (وسم مواقع شرعية كاحتيال)، تضخيم التخزين |
| 10 | **تخزين محلي مُتحقَّق** `storageGetJSON` — مخطط، حجم، إزالة `__proto__` | التلاعب بـ localStorage، Prototype Pollution |
| 11 | **Service Worker مقيّد** — قائمة بيضاء + استجابات `basic` فقط | تسميم الكاش، تخزين استجابات API |
| 12 | **تحديد المعدل + قفل الطلب الواحد** | الإغراق، الضغط المزدوج، استنزاف حصة المفتاح |
| 13 | **تدقيق آلي في CI** — `npm run check` + CodeQL + Dependabot | رجوع الثغرات عند التطوير مستقبلاً |
| 14 | **نشر الملفات التشغيلية فقط** إلى Pages | تسرّب الاختبارات/الإعدادات |

## خطوات إلزامية على GitHub

1. فعّل **المصادقة الثنائية (2FA)** على حسابك.
2. Settings → Pages → Source = **GitHub Actions**.
3. Settings → Branches → حماية فرع `main` (Require PR + status checks `Tests & security audit`).
4. Settings → Code security → فعّل **Secret scanning** و**Push protection** و**Dependabot alerts**.
5. لا ترفع مفاتيح API أو `.env` حقيقياً أبداً.

## حماية أقوى موصى بها: Cloudflare أمام GitHub Pages

1. أضف نطاقك إلى Cloudflare، وأنشئ سجل `CNAME` → `USERNAME.github.io` (السحابة البرتقالية).
2. SSL/TLS = **Full (strict)**، وفعّل **Always Use HTTPS**.
3. Rules → Transform Rules → *Modify Response Header*: الصق الترويسات من `headers-cloudflare.txt`.
4. Security → فعّل **WAF Managed Rules** و**Bot Fight Mode**، واترك DDoS الافتراضي.
5. أضف قاعدة: المسار `/sw.js` ← `Cache-Control: no-cache`.

> بديل أبسط: انشر على **Netlify** أو **Cloudflare Pages** — ملف `_headers` يُطبَّق تلقائياً.

## ما لا يمكن منعه من جهة التطبيق وحده

- جهاز مخترق أو إضافة متصفح خبيثة (تقرأ كل ما في الصفحة).
- من يعدّل الكود محلياً في أدوات المطور (طبيعي في أي تطبيق مفتوح المصدر).
- لصق المستخدم لمفتاحه في مكان عام، أو حدود/أعطال مزوّدي الذكاء الاصطناعي.
- هجمات DDoS على مستوى البنية (تحتاج Cloudflare أو ما يعادله).
- **لا يوجد نظام آمن 100%.** هذه الطبقات تقلّص سطح الهجوم وتُصعّبه، ولا تعد بالمستحيل.

## للمطوّر

- لا تضف `eval` أو `new Function` أو `innerHTML` بمحتوى غير مُهرَّب — `npm run audit` سيفشل.
- مصدر خارجي جديد؟ حدّث `connect-src` في `index.html` و`headers-cloudflare.txt` و`_headers` (التدقيق يقارنها).
- بعد أي تعديل: `npm run check`.

## الإبلاغ عن ثغرة

راسل **nidalwatfa99@gmail.com** بعنوان `TRUST AI Security` مع الخطوات والأثر المتوقع. نسعى للرد خلال 72 ساعة. من فضلك لا تنشر تفاصيل الاستغلال قبل الإصلاح. انظر أيضاً `/.well-known/security.txt`.
