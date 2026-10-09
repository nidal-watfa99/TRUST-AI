/**
 * TRUST AI — AI Provider layer (optional "with client")
 * Privacy-first: API keys live only in memory / sessionStorage.
 * Never hardcoded. Never sent to any TRUST AI server.
 * Supports free & paid providers via official endpoints.
 */

const FREE_MODELS = [
  { id: "groq-llama", name: "Groq — Llama 3.3 70B (Free tier)", provider: "groq", model: "llama-3.3-70b-versatile",
    officialUrl: "https://console.groq.com/keys", docs: "https://console.groq.com/docs/models", free: true, vision: false },
  { id: "groq-vision", name: "Groq — Llama 4 Scout + Vision (Free tier)", provider: "groq", model: "meta-llama/llama-4-scout-17b-16e-instruct",
    officialUrl: "https://console.groq.com/keys", docs: "https://console.groq.com/docs/models", free: true, vision: true },
  { id: "gemini-flash", name: "Google Gemini Flash — latest (Free tier)", provider: "gemini", model: "gemini-flash-latest",
    officialUrl: "https://aistudio.google.com/apikey", docs: "https://ai.google.dev/gemini-api/docs", free: true, vision: true },
  { id: "gemini-pro", name: "Google Gemini Pro — latest", provider: "gemini", model: "gemini-pro-latest",
    officialUrl: "https://aistudio.google.com/apikey", docs: "https://ai.google.dev/gemini-api/docs", free: true, vision: true },
  { id: "openrouter-free", name: "OpenRouter — Llama 3.3 70B (Free)", provider: "openrouter", model: "meta-llama/llama-3.3-70b-instruct:free",
    officialUrl: "https://openrouter.ai/keys", docs: "https://openrouter.ai/docs", free: true, vision: false },
  { id: "openai-gpt4o-mini", name: "OpenAI GPT-4o mini (Paid)", provider: "openai", model: "gpt-4o-mini",
    officialUrl: "https://platform.openai.com/api-keys", docs: "https://platform.openai.com/docs", free: false, vision: true },
  { id: "openai-gpt4o", name: "OpenAI GPT-4o (Paid + Vision)", provider: "openai", model: "gpt-4o",
    officialUrl: "https://platform.openai.com/api-keys", docs: "https://platform.openai.com/docs", free: false, vision: true },
];

const state = {
  apiKey: null,
  modelId: null,
  provider: null,
  model: null,
  enabled: false,
  visionCapable: false,
};

const SYSTEM_PROMPT = `You are TRUST AI, a digital safety analyst. Analyze the user message or image for phishing, scams, social engineering, and fraud risk.

Respond ONLY with valid JSON (no markdown, no extra text):
{
  "score": <0-100 integer>,
  "level": "low"|"medium"|"high"|"severe",
  "summary": "<1-2 sentence summary in the same language as the input>",
  "indicators": [
    {"category": "<urgency|impersonation|money|sensitive|link|unrealistic|socialEngineering|other>", "detail": "<short explanation>", "severity": <1-10>}
  ],
  "actions": ["<short recommended action>", ...],
  "confidence": <0-100>
}

Be precise. Prefer higher risk when uncertain about financial or credential requests. Never invent facts.`;

function friendlyError(status, body, provider) {
  let msg = "";
  try { const j = JSON.parse(body); msg = j.error?.message || j[0]?.error?.message || ""; } catch (_) {}
  msg = (msg || body || "").toString().slice(0, 160);
  const hint = {
    400: "طلب غير صالح — غالباً اسم النموذج غير مدعوم. جرّب إدخال اسم نموذج آخر في خانة «نموذج مخصص».",
    401: "المفتاح مرفوض. تأكد أنه من نفس المزوّد المختار (مفتاح Groq لا يعمل مع Gemini).",
    403: "المفتاح لا يملك صلاحية لهذا النموذج أو المنطقة غير مدعومة.",
    404: "النموذج غير موجود أو أُوقف. أدخل اسماً حديثاً في «نموذج مخصص».",
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
        // key intentionally NOT persisted to storage for privacy; only memory
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

/**
 * Call the selected provider. Keys never leave the browser except to the official API.
 */
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
    const url = `https://generativelanguage.googleapis.com/v1beta/models/${model}:generateContent?key=${encodeURIComponent(apiKey)}`;
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
    // Prepend system as first text
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
    // strip possible markdown fences
    const cleaned = raw.replace(/^```json\s*/i, "").replace(/```\s*$/i, "").trim();
    return JSON.parse(cleaned);
  } catch {
    return null;
  }
}

/**
 * Analyze text with AI (enhancement layer).
 * Returns null if AI unavailable or fails — Risk Engine remains source of truth.
 */
export async function analyzeWithAI(text, engineResult) {
  if (!isAIAvailable()) return null;

  const userContent = `Analyze this message for fraud/phishing risk.

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

/**
 * Analyze image with vision-capable model.
 */
export async function analyzeImageWithAI(imageDataUrl, textHint = "") {
  if (!isVisionAvailable()) return null;

  const content = [
    {
      type: "text",
      text: `Analyze this screenshot/image for phishing, scams, or fraud indicators.
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

/**
 * Quick connectivity test (does not send user content).
 */
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
