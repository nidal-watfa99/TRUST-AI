/**
 * TRUST AI — AI Provider layer (optional "with client")
 * Privacy-first: API keys live only in memory / sessionStorage.
 * Never hardcoded. Never sent to any TRUST AI server.
 * Supports free & paid providers via official endpoints.
 * Updated Oct 2026: only currently available free models + ONE paid model.
 * Enhanced with strong pyramid / network marketing detection (QuestNet / QNET style).
 */

const FREE_MODELS = [
  // ── Free (Groq) — current free tier ──────────────────────────
  { id: "groq-gpt-oss-120b", name: "Groq — GPT-OSS 120B (Free)", provider: "groq",
    model: "openai/gpt-oss-120b",
    officialUrl: "https://console.groq.com/keys", docs: "https://console.groq.com/docs/models",
    free: true, vision: false },
  { id: "groq-gpt-oss-20b", name: "Groq — GPT-OSS 20B (Free, أسرع)", provider: "groq",
    model: "openai/gpt-oss-20b",
    officialUrl: "https://console.groq.com/keys", docs: "https://console.groq.com/docs/models",
    free: true, vision: false },
  { id: "groq-qwen", name: "Groq — Qwen3.8 27B (Free)", provider: "groq",
    model: "qwen/qwen3.8-27b",
    officialUrl: "https://console.groq.com/keys", docs: "https://console.groq.com/docs/models",
    free: true, vision: false },

  // ── Free (Google Gemini) ─────────────────────────────────────
  { id: "gemini-flash", name: "Gemini Flash (Free tier)", provider: "gemini",
    model: "gemini-flash-latest",
    officialUrl: "https://aistudio.google.com/apikey", docs: "https://ai.google.dev/gemini-api/docs",
    free: true, vision: true },
  { id: "gemini-flash-lite", name: "Gemini Flash-Lite (Free, أسرع وأخف)", provider: "gemini",
    model: "gemini-flash-lite-latest",
    officialUrl: "https://aistudio.google.com/apikey", docs: "https://ai.google.dev/gemini-api/docs",
    free: true, vision: true },

  // ── Free (OpenRouter) ────────────────────────────────────────
  { id: "openrouter-nemotron", name: "OpenRouter — Nemotron 3 Super (Free)", provider: "openrouter",
    model: "nvidia/nemotron-3-super-120b-a12b:free",
    officialUrl: "https://openrouter.ai/keys", docs: "https://openrouter.ai/docs",
    free: true, vision: false },
  { id: "openrouter-gemma", name: "OpenRouter — Gemma 4 31B (Free + Vision)", provider: "openrouter",
    model: "google/gemma-4-31b-it:free",
    officialUrl: "https://openrouter.ai/keys", docs: "https://openrouter.ai/docs",
    free: true, vision: true },
  { id: "openrouter-free-router", name: "OpenRouter — Auto Free Router", provider: "openrouter",
    model: "openrouter/free",
    officialUrl: "https://openrouter.ai/keys", docs: "https://openrouter.ai/docs",
    free: true, vision: true },

  // ── ONLY ONE PAID MODEL ──────────────────────────────────────
  { id: "openai-gpt4o", name: "OpenAI GPT-4o (Paid + Vision) — الوحيد المدفوع", provider: "openai",
    model: "gpt-4o",
    officialUrl: "https://platform.openai.com/api-keys", docs: "https://platform.openai.com/docs",
    free: false, vision: true },
];

const state = {
  apiKey: null,
  modelId: null,
  provider: null,
  model: null,
  enabled: false,
  visionCapable: false,
};

const SYSTEM_PROMPT = `You are TRUST AI, a highly specialized digital safety and anti-fraud analyst. Your primary mission is to protect people — especially those in difficult economic situations — from scams, phishing, crypto fraud, fake news, and particularly pyramid / multi-level marketing schemes.

You must be extremely sensitive to pyramid scheme patterns. These schemes caused massive harm in Syria and similar countries by exploiting poverty.

Classic pyramid scheme red flags you must detect aggressively:
- Promise of quick extreme wealth or becoming a millionaire in a few months
- Requirement to pay a high registration fee (especially around 1500–2000 USD)
- Obligation to recruit a specific number of people (especially 3 people from family or friends)
- Strict secrecy: forbidding the person from telling even closest family members
- Impossible conditions to withdraw money (must recruit more people endlessly)
- Pressure to sell house, land, gold, or go into debt
- Use of emotional language: "change your life", "this is your only chance", "passive income", "financial freedom"
- Mentions of companies known for pyramid schemes such as QuestNet, QNET, كويست نت, كيونت, QI Group, GoldQuest

Also detect strongly:
- Crypto airdrops, pump-and-dump, seed phrase requests
- Inheritance / bank manager / relative died scams
- Lottery / World Cup / prize claims requiring fees
- Telegram / X investment groups and fake signals
- Fake news designed to create panic

When you detect pyramid or high-risk patterns, give a HIGH or SEVERE score (usually 75–100) and clearly name it.

Respond ONLY with valid JSON (no markdown, no extra text):
{
  "score": <0-100 integer>,
  "level": "low"|"medium"|"high"|"severe",
  "summary": "<1-3 sentence clear summary in the same language as the input. Be direct and protective>",
  "indicators": [
    {"category": "<urgency|impersonation|money|sensitive|link|unrealistic|socialEngineering|pyramid|other>", "detail": "<short clear explanation>", "severity": <1-10>}
  ],
  "actions": ["<short recommended action in the same language>", ...],
  "confidence": <0-100>
}

Rules:
- Prefer higher risk when there is any sign of recruitment + money + secrecy + unrealistic income.
- If the message matches classic QuestNet-style tactics, score should almost always be 85 or higher.
- Never invent facts.
- Be protective and clear in the summary. People need strong warnings.
- Always respond in the same language as the user's input (Arabic or English).`;

function friendlyError(status, body, provider) {
  let msg = "";
  try { const j = JSON.parse(body); msg = j.error?.message || j[0]?.error?.message || ""; } catch (_) {}
  msg = (msg || body || "").toString().slice(0, 160);
  const hint = {
    400: "طلب غير صالح — اسم النموذج غير مدعوم حاليًا. اختر نموذجًا آخر من القائمة.",
    401: "المفتاح مرفوض. تأكد أنه من نفس المزوّد المختار.",
    403: "المفتاح لا يملك صلاحية لهذا النموذج أو المنطقة غير مدعومة.",
    404: "النموذج غير موجود أو أُوقف. اختر نموذجًا آخر من القائمة.",
    429: "تجاوزت حد الاستخدام المجاني. انتظر قليلاً أو بدّل النموذج.",
  }[status] || "خطأ من المزوّد.";
  return `[${provider} ${status}] ${hint} ${msg}`.trim();
}

export function getFreeModels() {
  return FREE_MODELS.map((m) => ({ ...m }));
}

export function initAIProvider(config = {}) {
  if (config.apiKey && typeof config.apiKey === "string" && config.apiKey.length > 8) {
    const modelMeta = FREE_MODELS.find((m) => m.id === config.modelId) || FREE_MODELS[0];
    state.apiKey = config.apiKey;
    state.modelId = modelMeta.id;
    state.provider = modelMeta.provider;
    state.model = (config.customModel || "").trim() || modelMeta.model;
    state.visionCapable = !!modelMeta.vision;
    state.enabled = true;
    try {
      sessionStorage.setItem("trustai_ai", JSON.stringify({
        modelId: state.modelId,
      }));
    } catch (_) {}
    return true;
  }
  clearAIProvider();
  return false;
}

export function clearAIProvider() {
  state.apiKey = null;
  state.modelId = null;
  state.provider = null;
  state.model = null;
  state.enabled = false;
  state.visionCapable = false;
  try {
    sessionStorage.removeItem("trustai_ai");
  } catch (_) {}
}

export function isAIAvailable() {
  return state.enabled === true && !!state.apiKey;
}

export function isVisionAvailable() {
  return isAIAvailable() && state.visionCapable;
}

export function getAIStatus() {
  return {
    available: isAIAvailable(),
    vision: isVisionAvailable(),
    modelId: state.modelId,
    model: state.model,
    provider: state.provider,
  };
}

async function callProvider(messages, options = {}) {
  try { return await callProviderInner(messages, options); }
  catch (e) {
    if (e instanceof TypeError) throw new Error("تعذّر الوصول إلى المزوّد: تحقق من الإنترنت، أو أن مانع الإعلانات/الـVPN لا يحجب الاتصال.");
    throw e;
  }
}

async function callProviderInner(messages, options = {}) {
  const { provider, model, apiKey } = state;
  if (!apiKey) throw new Error("No API key");

  if (provider === "openai" || provider === "openrouter" || provider === "groq") {
    let base = "https://api.openai.com/v1";
    let headers = {
      "Content-Type": "application/json",
      Authorization: `Bearer ${apiKey}`,
    };
    if (provider === "openrouter") {
      base = "https://openrouter.ai/api/v1";
      headers["HTTP-Referer"] = typeof location !== "undefined" ? location.origin : "https://trust-ai.app";
      headers["X-Title"] = "TRUST AI";
    } else if (provider === "groq") {
      base = "https://api.groq.com/openai/v1";
    }

    const body = {
      model,
      messages,
      temperature: 0.1,
      max_tokens: 1200,
      response_format: options.json ? { type: "json_object" } : undefined,
    };

    const res = await fetch(`${base}/chat/completions`, {
      method: "POST",
      headers,
      body: JSON.stringify(body),
    });
    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      throw new Error(friendlyError(res.status, errText, provider));
    }
    const data = await res.json();
    return data.choices?.[0]?.message?.content || "";
  }

  if (provider === "gemini") {
    const url = `https://generativelanguage.googleapis.com/v1beta/models/\( {model}:generateContent?key= \){encodeURIComponent(apiKey)}`;
    const parts = [];
    for (const msg of messages) {
      if (msg.role === "system") continue;
      if (typeof msg.content === "string") {
        parts.push({ text: msg.content });
      } else if (Array.isArray(msg.content)) {
        for (const part of msg.content) {
          if (part.type === "text") parts.push({ text: part.text });
          if (part.type === "image_url" && part.image_url?.url) {
            const b64 = part.image_url.url.replace(/^data:[^;]+;base64,/, "");
            const mime = (part.image_url.url.match(/^data:([^;]+);/) || [])[1] || "image/jpeg";
            parts.push({ inline_data: { mime_type: mime, data: b64 } });
          }
        }
      }
    }
    const sys = messages.find((m) => m.role === "system");
    if (sys) parts.unshift({ text: sys.content });

    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        contents: [{ role: "user", parts }],
        generationConfig: { temperature: 0.1, maxOutputTokens: 1200, responseMimeType: "application/json" },
      }),
    });
    if (!res.ok) {
      const errText = await res.text().catch(() => "");
      throw new Error(friendlyError(res.status, errText, provider));
    }
    const data = await res.json();
    return data.candidates?.[0]?.content?.parts?.[0]?.text || "";
  }

  throw new Error("Unknown provider");
}

function parseAIJson(raw) {
  try {
    const cleaned = raw.replace(/^```json\s*/i, "").replace(/```\s*$/i, "").trim();
    return JSON.parse(cleaned);
  } catch {
    return null;
  }
}

export async function analyzeWithAI(text, engineResult) {
  if (!isAIAvailable()) return null;

  const userContent = `Analyze this message for fraud/phishing risk, with special attention to pyramid and network marketing schemes.

Message:
"""
${text.slice(0, 8000)}
"""

Offline risk engine preliminary score: ${engineResult?.score ?? "n/a"} / 100
Categories triggered: ${(engineResult?.reasons || []).join(", ") || "none"}

Respond with JSON only.`;

  try {
    const raw = await callProvider(
      [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content: userContent },
      ],
      { json: true }
    );
    const parsed = parseAIJson(raw);
    if (!parsed || typeof parsed.score !== "number") return null;
    return {
      score: Math.max(0, Math.min(100, Math.round(parsed.score))),
      level: parsed.level || "medium",
      summary: parsed.summary || "",
      indicators: Array.isArray(parsed.indicators) ? parsed.indicators : [],
      actions: Array.isArray(parsed.actions) ? parsed.actions : [],
      confidence: typeof parsed.confidence === "number" ? parsed.confidence : 70,
      mode: "ai",
      provider: state.provider,
      model: state.model,
    };
  } catch (err) {
    console.warn("AI analysis failed:", err.message);
    return { error: err.message, mode: "ai-error" };
  }
}

export async function analyzeImageWithAI(imageDataUrl, textHint = "") {
  if (!isVisionAvailable()) return null;

  const content = [
    {
      type: "text",
      text: `Analyze this screenshot/image for phishing, scams, or fraud indicators, especially pyramid schemes.
${textHint ? "User note: " + textHint.slice(0, 500) : ""}
Extract any visible text (OCR) and assess risk. Respond with JSON only.`,
    },
    {
      type: "image_url",
      image_url: { url: imageDataUrl },
    },
  ];

  try {
    const raw = await callProvider(
      [
        { role: "system", content: SYSTEM_PROMPT },
        { role: "user", content },
      ],
      { json: true }
    );
    const parsed = parseAIJson(raw);
    if (!parsed || typeof parsed.score !== "number") return null;
    return {
      score: Math.max(0, Math.min(100, Math.round(parsed.score))),
      level: parsed.level || "medium",
      summary: parsed.summary || "",
      indicators: Array.isArray(parsed.indicators) ? parsed.indicators : [],
      actions: Array.isArray(parsed.actions) ? parsed.actions : [],
      confidence: typeof parsed.confidence === "number" ? parsed.confidence : 65,
      mode: "ai-vision",
      provider: state.provider,
      model: state.model,
    };
  } catch (err) {
    console.warn("AI vision failed:", err.message);
    return { error: err.message, mode: "ai-error" };
  }
}

export async function testConnection() {
  if (!isAIAvailable()) return { ok: false, error: "AI not configured" };
  try {
    const raw = await callProvider(
      [
        { role: "system", content: "Reply with JSON: {\"ok\":true}" },
        { role: "user", content: "ping" },
      ],
      { json: true }
    );
    const parsed = parseAIJson(raw);
    return { ok: !!(parsed && (parsed.ok === true || parsed.score !== undefined)), raw: raw.slice(0, 100) };
  } catch (err) {
    return { ok: false, error: err.message };
  }
}
