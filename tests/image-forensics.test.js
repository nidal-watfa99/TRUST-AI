/**
 * TRUST AI — image forensics (metadata) on synthetic files
 * Run: node tests/image-forensics.test.js
 */
import { scanImageBytes, forensicsFacts } from "../js/image-forensics.js";

let passed = 0, failed = 0;
const assert = (c, m) => (c ? (passed++, console.log("  ✓", m)) : (failed++, console.error("  ✗", m)));
const enc = (s) => Uint8Array.from([...s].map((c) => c.charCodeAt(0) & 0xff));
const cat = (...a) => { const n = a.reduce((x, y) => x + y.length, 0); const o = new Uint8Array(n); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
const be32 = (n) => Uint8Array.from([(n >>> 24) & 255, (n >>> 16) & 255, (n >>> 8) & 255, n & 255]);

// ── builders ──
const pngChunk = (type, data) => cat(be32(data.length), enc(type), data, new Uint8Array(4));
const PNG_SIG = Uint8Array.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]);
const png = (...chunks) => cat(PNG_SIG, pngChunk("IHDR", new Uint8Array(13)), ...chunks, pngChunk("IEND", new Uint8Array(0)));
const text = (k, v) => pngChunk("tEXt", cat(enc(k), Uint8Array.of(0), enc(v)));
const jseg = (marker, payload) => cat(Uint8Array.of(0xff, marker, ((payload.length + 2) >> 8) & 255, (payload.length + 2) & 255), payload);
const jpeg = (...segs) => cat(Uint8Array.of(0xff, 0xd8), ...segs, Uint8Array.of(0xff, 0xd9));
function makeTiff({ ifd0 = [], exif = [], gps = false }) {
  const buf = new Uint8Array(2048); const dv = new DataView(buf.buffer);
  buf.set([0x49, 0x49, 42, 0]); dv.setUint32(4, 8, true);
  let dp = 1024;
  const ascii = (tag, str) => { const o = dp; for (let i = 0; i < str.length; i++) buf[o + i] = str.charCodeAt(i); buf[o + str.length] = 0; dp += str.length + 1; return { tag, type: 2, count: str.length + 1, value: o }; };
  const write = (off, es) => { dv.setUint16(off, es.length, true); es.forEach((e, i) => { const p = off + 2 + i * 12; dv.setUint16(p, e.tag, true); dv.setUint16(p + 2, e.type, true); dv.setUint32(p + 4, e.count, true); dv.setUint32(p + 8, e.value, true); }); };
  const e0 = ifd0.map(([t, s]) => ascii(t, s));
  if (exif.length) e0.push({ tag: 0x8769, type: 4, count: 1, value: 512 });
  if (gps) e0.push({ tag: 0x8825, type: 4, count: 1, value: 700 });
  write(8, e0);
  if (exif.length) write(512, exif.map(([t, s]) => ascii(t, s)));
  return buf.subarray(0, dp);
}
const exifSeg = (tiff) => jseg(0xe1, cat(enc("Exif\0\0"), tiff));
const xmpSeg = (xml) => jseg(0xe1, cat(enc(["http:", "", "ns.adobe.com", "xap", "1.0", ""].join("/") + "\0"), enc(xml)));
const has = (r, code) => r.findings.some((f) => f.code === code);

console.log("\n=== AI-generation signals (strong evidence when present) ===\n");
let r = scanImageBytes(png(text("parameters", "a cat on a sofa\nSteps: 20, Sampler: Euler a, CFG scale: 7, Seed: 12345, Size: 512x512")));
assert(r.format === "png" && r.aiSignal && has(r, "ai_prompt"), "PNG with Stable Diffusion 'parameters' → flagged as generated");
r = scanImageBytes(png(text("prompt", '{"3":{"class_type":"KSampler","inputs":{}}}')));
assert(r.aiSignal && has(r, "ai_prompt"), "PNG with a ComfyUI workflow → flagged");
r = scanImageBytes(jpeg(xmpSeg('<x:xmpmeta><rdf:Description Iptc4xmpExt:DigitalSourceType="http://cv.iptc.org/newscodes/digitalsourcetype/trainedAlgorithmicMedia"/></x:xmpmeta>')));
assert(r.aiSignal && has(r, "ai_declared"), "JPEG whose XMP declares trainedAlgorithmicMedia → flagged");
r = scanImageBytes(jpeg(exifSeg(makeTiff({ ifd0: [[0x0131, "Midjourney V6 render"]] }))));
assert(r.aiSignal && has(r, "ai_declared"), "EXIF Software naming an image generator → flagged");
r = scanImageBytes(png(pngChunk("caBX", enc("jumb c2pa claim_generator OpenAI DALL-E 3"))));
assert(r.aiSignal && has(r, "c2pa_ai"), "Content Credentials naming a generator → flagged");
r = scanImageBytes(png(pngChunk("caBX", enc("jumb c2pa claim_generator Some Camera"))));
assert(!r.aiSignal && has(r, "c2pa") && /لم نتحقق من توقيعها/.test(r.findings.find((f) => f.code === "c2pa").text), "plain C2PA is reported but its signature is explicitly NOT verified");

console.log("\n=== Camera / editor / GPS (informational — never 'proof') ===\n");
r = scanImageBytes(jpeg(exifSeg(makeTiff({ ifd0: [[0x010f, "Canon Inc"], [0x0110, "Canon EOS R5"], [0x0131, "Adobe Photoshop 25.1"]], exif: [[0x9003, "2024:05:01 10:00:00"]], gps: true }))), "en");
assert(has(r, "camera") && has(r, "taken") && has(r, "editor") && has(r, "gps") && !r.aiSignal, "camera make/model, capture date, editor and GPS are read from EXIF");
assert(/does not prove|not that the image is unedited/i.test(r.findings.find((f) => f.code === "camera").text), "camera metadata is never presented as proof of authenticity");
r = scanImageBytes(jpeg(exifSeg(makeTiff({ ifd0: [[0x0131, "G973FXXU3ASG8"]] }))));
assert(!has(r, "editor") && !r.aiSignal, "an ordinary camera firmware string is NOT called an editor or AI");

console.log("\n=== Absence of metadata ===\n");
r = scanImageBytes(jpeg());
assert(has(r, "none") && !r.hasMetadata && !r.aiSignal, "no metadata → neutral note");
assert(/لا يعني أن الصورة حقيقية ولا أنها مولَّدة/.test(r.findings[0].text), "the note says absence proves nothing either way");

console.log("\n=== Robustness ===\n");
r = scanImageBytes(enc("not an image at all"));
assert(r.format === "unknown" && has(r, "unsupported"), "unsupported file type handled");
let threw = false;
try { scanImageBytes(png(text("parameters", "x")).subarray(0, 60)); scanImageBytes(jpeg(exifSeg(makeTiff({ ifd0: [[0x0110, "Some Model X"]] }))).subarray(0, 40)); } catch (_) { threw = true; }
assert(!threw, "truncated / corrupt files never throw");

console.log("\n=== Facts handed to the fact-checking model ===\n");
const facts = forensicsFacts([scanImageBytes(png(text("parameters", "Steps: 20, Sampler: Euler a, Seed: 1"))), scanImageBytes(jpeg())]);
assert(/METADATA SAYS AI-GENERATED/.test(facts[0]) && /no metadata/.test(facts[1]) && /proves nothing/.test(facts[1]), "facts state only what the file says, and that absence proves nothing");

console.log(`\n${passed} passed, ${failed} failed\n`);
process.exit(failed ? 1 : 0);
