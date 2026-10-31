/**
 * TRUST AI — Image forensics (offline, metadata-based)
 *
 * Reads what the ORIGINAL image file says about itself: PNG text chunks (Stable Diffusion / ComfyUI write their
 * prompt there), EXIF (camera, software, date, GPS presence), XMP (IPTC "trainedAlgorithmicMedia" = declared AI image)
 * and C2PA / Content Credentials markers.
 *
 * HONEST LIMITS — shown to the person with every result:
 *  - Presence of AI metadata is STRONG evidence the image was generated. Absence proves NOTHING: social platforms
 *    strip metadata, and anyone can remove it.
 *  - Camera metadata shows the file came from a camera pipeline, not that the picture is unedited or genuine.
 *  - We do NOT validate C2PA signatures here; we only report that a manifest is present.
 */

// Fixed identifier that starts an XMP packet inside a JPEG APP1 segment (an identifier, never fetched).
const XMP_ID = ["http:", "", "ns.adobe.com", "xap", "1.0", ""].join("/");
const AI_TOOLS = /(stable[\s-]?diffusion|midjourney|dall[·\-\s]?e|firefly|comfyui|automatic1111|a1111|invokeai|novelai|leonardo\.?ai|flux|sdxl|imagen|synthid|bing image creator|ideogram|nano[\s-]?banana|gemini|sora|runway|krea|playground ?ai)/i;
const EDITORS = /(photoshop|lightroom|gimp|canva|snapseed|picsart|facetune|pixlr|affinity|capture one|paint\.net|photoroom|remini|meitu|faceapp)/i;

const T = {
  ar: {
    ai_declared: "البيانات المضمّنة في الملف تصرّح بأن الصورة مولَّدة بالذكاء الاصطناعي ({d}).",
    ai_prompt: "الملف يحمل معلمات توليد صور بالذكاء الاصطناعي (مثل الوصف النصي والعيّنة)، وهذا دليل قوي على أنها مولَّدة ({d}).",
    c2pa_ai: "بيانات «Content Credentials» المضمّنة تذكر أداة توليد ({d}).",
    c2pa: "الملف يحمل بيانات «Content Credentials/C2PA» (سجلّ منشأ). لم نتحقق من توقيعها هنا؛ افحصها بأداة C2PA الرسمية.",
    camera: "بيانات كاميرا موجودة: {d}. هذا يدل على مسار تصوير، لكنه لا يثبت أن الصورة غير معدّلة أو أن الخبر المرافق صادق.",
    taken: "تاريخ الالتقاط المسجَّل في الملف: {d} (قابل للتعديل، لا تعتمد عليه وحده).",
    editor: "الملف مُصدَّر عبر برنامج «{d}» — قد تكون عُدّلت، وهذا وحده ليس دليل تزييف.",
    gps: "الصورة تحمل إحداثيات موقع جغرافي (خصوصية: انتبه عند النشر).",
    none: "لا توجد بيانات وصفية في الملف. هذا شائع جدًا لأن المنصات تحذفها عند الرفع — لا يعني أن الصورة حقيقية ولا أنها مولَّدة.",
    unsupported: "نوع الملف غير مدعوم للفحص (ندعم JPEG وPNG وWebP).",
  },
  en: {
    ai_declared: "The file's embedded metadata declares the image AI-generated ({d}).",
    ai_prompt: "The file carries AI image-generation parameters (prompt, sampler…) — strong evidence it was generated ({d}).",
    c2pa_ai: "Embedded Content Credentials name a generation tool ({d}).",
    c2pa: "The file carries Content Credentials / C2PA provenance data. We did not verify its signature here; check it with an official C2PA verifier.",
    camera: "Camera metadata present: {d}. This shows a photo pipeline, but not that the image is unedited or that the accompanying story is true.",
    taken: "Capture date recorded in the file: {d} (editable — do not rely on it alone).",
    editor: "The file was exported by “{d}” — it may have been edited; that alone is not proof of manipulation.",
    gps: "The image carries GPS coordinates (privacy: be careful when sharing).",
    none: "No metadata in the file. Very common because platforms strip it on upload — it does NOT mean the image is real, nor that it is generated.",
    unsupported: "File type not supported for inspection (JPEG, PNG and WebP are).",
  },
};
const fill = (s, d) => s.replace("{d}", d || "");

const u16 = (dv, o, le) => dv.getUint16(o, le);
const u32 = (dv, o, le) => dv.getUint32(o, le);
const latin1 = (b) => { let t = ""; for (let i = 0; i < b.length; i++) t += String.fromCharCode(b[i]); return t; };
const utf8 = (b) => { try { return new TextDecoder("utf-8", { fatal: false }).decode(b); } catch (_) { return latin1(b); } };
const clean = (t) => String(t || "").replace(/\0/g, "").replace(/[\u0000-\u001f]+/g, " ").trim().slice(0, 300);

/** Minimal TIFF/EXIF reader: ASCII tags only + GPS presence. */
function parseExif(bytes) {
  const out = {};
  try {
    const dv = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
    const le = bytes[0] === 0x49;
    if (!(bytes[0] === 0x49 || bytes[0] === 0x4d) || u16(dv, 2, le) !== 42) return out;
    const names = { 0x010f: "make", 0x0110: "model", 0x0131: "software", 0x0132: "dateTime", 0x013b: "artist", 0x9003: "dateOriginal", 0x9004: "dateDigitized", 0xa430: "owner" };
    const readIfd = (off, depth) => {
      if (depth > 2 || off < 8 || off + 2 > bytes.length) return;
      const n = Math.min(u16(dv, off, le), 200);
      for (let i = 0; i < n; i++) {
        const e = off + 2 + i * 12;
        if (e + 12 > bytes.length) break;
        const tag = u16(dv, e, le), type = u16(dv, e + 2, le), count = u32(dv, e + 4, le);
        if (tag === 0x8769 && type === 4) readIfd(u32(dv, e + 8, le), depth + 1);
        else if (tag === 0x8825) out.gps = true;
        else if (names[tag] && type === 2 && count > 0 && count < 512) {
          const vo = count <= 4 ? e + 8 : u32(dv, e + 8, le);
          if (vo + count <= bytes.length) out[names[tag]] = clean(latin1(bytes.subarray(vo, vo + count)));
        }
      }
    };
    readIfd(u32(dv, 4, le), 0);
  } catch (_) { /* malformed EXIF: ignore */ }
  return out;
}

function scanPng(b, acc) {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let o = 8;
  while (o + 12 <= b.length) {
    const len = dv.getUint32(o);
    const type = latin1(b.subarray(o + 4, o + 8));
    const data = b.subarray(o + 8, Math.min(o + 8 + len, b.length));
    if (type === "tEXt") {
      const z = data.indexOf(0);
      if (z > 0) acc.texts.push({ key: latin1(data.subarray(0, z)), value: latin1(data.subarray(z + 1)) });
    } else if (type === "iTXt") {
      const z = data.indexOf(0);
      if (z > 0) {
        const key = latin1(data.subarray(0, z));
        const compressed = data[z + 1] === 1;
        let p = z + 3; // flag, method
        while (p < data.length && data[p] !== 0) p++; p++; // language
        while (p < data.length && data[p] !== 0) p++; p++; // translated keyword
        if (!compressed) acc.texts.push({ key, value: utf8(data.subarray(p)) });
        else acc.texts.push({ key, value: "" });
      }
    } else if (type === "zTXt") {
      const z = data.indexOf(0);
      if (z > 0) acc.texts.push({ key: latin1(data.subarray(0, z)), value: "" });
    } else if (type === "eXIf") Object.assign(acc.exif, parseExif(data));
    else if (type === "caBX") { acc.c2pa = true; acc.c2paText += latin1(data.subarray(0, 4000)); }
    o += 12 + len;
    if (type === "IEND") break;
  }
}

function scanJpeg(b, acc) {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let o = 2;
  while (o + 4 <= b.length) {
    if (b[o] !== 0xff) { o++; continue; }
    const marker = b[o + 1];
    if (marker === 0xd9 || marker === 0xda) break;
    if (marker === 0x00 || (marker >= 0xd0 && marker <= 0xd7) || marker === 0x01) { o += 2; continue; }
    const len = dv.getUint16(o + 2);
    const seg = b.subarray(o + 4, Math.min(o + 2 + len, b.length));
    if (marker === 0xe1) {
      const head = latin1(seg.subarray(0, 29));
      if (head.startsWith("Exif\0\0")) Object.assign(acc.exif, parseExif(seg.subarray(6)));
      else if (head.startsWith(XMP_ID)) acc.xmp += utf8(seg.subarray(29)) + "\n";
    } else if (marker === 0xeb) { if (latin1(seg.subarray(0, 24)).includes("JP") && latin1(seg).includes("c2pa")) acc.c2pa = true; acc.c2paText += latin1(seg.subarray(0, 4000)); }
    else if (marker === 0xfe) acc.texts.push({ key: "Comment", value: utf8(seg) });
    o += 2 + len;
  }
}

function scanWebp(b, acc) {
  const dv = new DataView(b.buffer, b.byteOffset, b.byteLength);
  let o = 12;
  while (o + 8 <= b.length) {
    const type = latin1(b.subarray(o, o + 4));
    const len = dv.getUint32(o + 4, true);
    const data = b.subarray(o + 8, Math.min(o + 8 + len, b.length));
    if (type === "EXIF") Object.assign(acc.exif, parseExif(data[0] === 0x45 ? data.subarray(6) : data));
    else if (type === "XMP ") acc.xmp += utf8(data) + "\n";
    o += 8 + len + (len % 2);
  }
}

/** @param {Uint8Array} bytes @returns {{format:string, meta:object, findings:Array, hasMetadata:boolean}} */
export function scanImageBytes(bytes, lang = "ar") {
  const s = T[lang] || T.ar;
  const acc = { texts: [], exif: {}, xmp: "", c2pa: false, c2paText: "" };
  let format = "unknown";
  try {
    if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4e && bytes[3] === 0x47) { format = "png"; scanPng(bytes, acc); }
    else if (bytes[0] === 0xff && bytes[1] === 0xd8) { format = "jpeg"; scanJpeg(bytes, acc); }
    else if (latin1(bytes.subarray(0, 4)) === "RIFF" && latin1(bytes.subarray(8, 12)) === "WEBP") { format = "webp"; scanWebp(bytes, acc); }
  } catch (_) { /* truncated/corrupt file: report what we have */ }
  if (format === "unknown") return { format, meta: {}, findings: [{ code: "unsupported", level: "note", text: s.unsupported }], hasMetadata: false };

  const findings = [];
  const add = (code, level, key, d) => findings.push({ code, level, text: fill(s[key], d) });
  const allText = acc.texts.map((t) => `${t.key}=${t.value}`).join("\n") + "\n" + acc.xmp;

  // 1) Declared AI origin (strongest signals)
  const dst = /DigitalSourceType[^>\n]{0,200}?(trainedAlgorithmicMedia|compositeWithTrainedAlgorithmicMedia|algorithmicMedia)/i.exec(acc.xmp) || /digitalsourcetype\/(trainedAlgorithmicMedia|compositeWithTrainedAlgorithmicMedia)/i.exec(acc.xmp);
  if (dst) add("ai_declared", "strong", "ai_declared", "IPTC DigitalSourceType: " + dst[1]);
  const a1111 = acc.texts.find((t) => /^parameters$/i.test(t.key) && /Steps:\s*\d+/i.test(t.value) && /Sampler|CFG scale|Seed/i.test(t.value));
  if (a1111) add("ai_prompt", "strong", "ai_prompt", "Stable Diffusion (parameters)");
  const comfy = acc.texts.find((t) => /^(prompt|workflow)$/i.test(t.key) && /class_type|"nodes"/.test(t.value));
  if (comfy) add("ai_prompt", "strong", "ai_prompt", "ComfyUI workflow");
  const sdmeta = acc.texts.find((t) => /^(sd-metadata|invokeai_metadata|dream|Dream)$/i.test(t.key));
  if (sdmeta) add("ai_prompt", "strong", "ai_prompt", sdmeta.key);
  const tool = acc.texts.filter((t) => /^(software|comment|description|source|title|author|generator|credit)$/i.test(t.key)).map((t) => AI_TOOLS.exec(t.value)).find(Boolean)
    || AI_TOOLS.exec(acc.exif.software || "") || AI_TOOLS.exec(acc.xmp.replace(/<[^>]+>/g, " "));
  if (tool && !findings.some((f) => f.level === "strong")) add("ai_declared", "strong", "ai_declared", tool[1]);

  // 2) Content Credentials
  if (acc.c2pa || /\bc2pa\b|urn:c2pa|contentauth/i.test(acc.xmp)) {
    const t = AI_TOOLS.exec(acc.c2paText) || AI_TOOLS.exec(acc.xmp);
    if (t) add("c2pa_ai", "strong", "c2pa_ai", t[1]); else add("c2pa", "info", "c2pa");
  }

  // 3) Camera / editor / dates / GPS
  const ex = acc.exif;
  const cam = [ex.make, ex.model].filter(Boolean).join(" ");
  if (cam) add("camera", "info", "camera", cam);
  const when = ex.dateOriginal || ex.dateDigitized || ex.dateTime;
  if (when) add("taken", "info", "taken", when);
  if (ex.software && EDITORS.test(ex.software)) add("editor", "note", "editor", ex.software); // camera firmware strings are NOT reported as editors
  if (ex.gps) add("gps", "note", "gps");

  const hasMetadata = acc.texts.length > 0 || !!acc.xmp || acc.c2pa || Object.keys(ex).length > 0;
  if (!findings.length) add("none", "note", "none");
  const meta = { make: ex.make || "", model: ex.model || "", software: ex.software || "", dateOriginal: when || "", gps: !!ex.gps };
  return { format, meta, findings, hasMetadata, aiSignal: findings.some((f) => f.level === "strong") };
}

/** Read the ORIGINAL File (before any resizing strips its metadata). Never throws. */
export async function scanImageFile(file, lang = "ar") {
  try {
    const buf = await file.slice(0, 6 * 1024 * 1024).arrayBuffer();
    return scanImageBytes(new Uint8Array(buf), lang);
  } catch (_) {
    return { format: "unknown", meta: {}, findings: [], hasMetadata: false, aiSignal: false };
  }
}

/** One-line technical facts for the fact-checking model (only things the file actually says). */
export function forensicsFacts(list) {
  return (Array.isArray(list) ? list : []).map((f, i) => {
    if (!f) return "";
    const strong = f.findings.filter((x) => x.level === "strong").map((x) => x.text).join(" ");
    const m = f.meta || {};
    const bits = [];
    if (strong) bits.push("METADATA SAYS AI-GENERATED: " + strong);
    if (m.make || m.model) bits.push(`camera: ${[m.make, m.model].filter(Boolean).join(" ")}`);
    if (m.dateOriginal) bits.push(`capture date: ${m.dateOriginal}`);
    if (m.software) bits.push(`software: ${m.software}`);
    if (!f.hasMetadata) bits.push("no metadata (stripped or absent; proves nothing)");
    return `image ${i + 1} (${f.format}): ${bits.join("; ")}`;
  }).filter(Boolean);
}
