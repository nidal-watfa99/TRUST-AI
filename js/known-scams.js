/**
 * TRUST AI — documented scam domains (small, evidence-based, offline)
 *
 * RULES for adding an entry (so the list can never become a rumour mill or a defamation risk):
 *   1. at least TWO independent public sources, each with a URL and the date it was checked;
 *   2. state what the sources actually say (`says`), not an opinion;
 *   3. only domains — never people.
 * The app also consults (a) the live public-feed list downloaded by fraud-db.js and (b) the person's OWN local reports.
 * Honest limit: this list is tiny. A domain missing from it is NOT safe — it only means nobody here documented it yet.
 */
import { storageGetJSON } from "./security.js";
import { checkDomain } from "./fraud-db.js";

export const KNOWN_SCAM_DOMAINS = Object.freeze([
  {
    domain: "slotcoiner.com",
    type: "crypto_casino_reward_scheme",
    checked: "2026-11-01",
    sources: [
      { name: "Gridinsoft", url: "https://gridinsoft.com/online-virus-scanner/url/slotcoiner-com", date: "2025-05-29", says: "classified as a financial scam; fake \"You got $100\" payout lure with unrealistic returns" },
      { name: "Trustpilot", url: "https://nl-be.trustpilot.com/review/slotcoiner.com", date: "2026-11-01", says: "multiple user reports of withdrawal fees demanded and no payout received" },
    ],
  },
]);

const hostOf = (v) => {
  try { return new URL(/^[a-z][a-z0-9+.-]*:\/\//i.test(String(v)) ? String(v) : "https://" + v).hostname.toLowerCase().replace(/^www\./, ""); } catch (_) { return ""; }
};

/** @returns {null | {origin:"builtin"|"feed"|"local", domain:string, type?:string, sources:Array}} */
export function lookupKnownScam(host) {
  const h = hostOf(host);
  if (!h) return null;
  const b = KNOWN_SCAM_DOMAINS.find((x) => h === x.domain || h.endsWith("." + x.domain));
  if (b) return { origin: "builtin", domain: b.domain, type: b.type, sources: b.sources };
  try {
    const f = checkDomain(h);
    if (f) return { origin: "feed", domain: f.domain || h, type: f.type || f.category || "", sources: [{ name: String(f.source || f.feed || "public feed").slice(0, 60), url: "", date: String(f.date || f.added || "").slice(0, 10), says: "listed in a public malicious-domain feed" }] };
  } catch (_) {}
  try {
    const reports = storageGetJSON("trustai_local_reports", { fallback: [], maxBytes: 400_000 });
    if (Array.isArray(reports)) {
      const r = reports.find((x) => x && x.url && (() => { const rh = hostOf(x.url); return rh && (rh === h || h.endsWith("." + rh)); })());
      if (r) return { origin: "local", domain: hostOf(r.url), type: "", sources: [{ name: "your own report", url: "", date: String(r.createdAt || r.date || "").slice(0, 10), says: "you reported this site on this device" }] };
    }
  } catch (_) {}
  return null;
}
