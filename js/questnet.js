/**
 * TRUST AI v2 — Quest Net / QNet investigation dossier
 * Evidence-based, distinguishes similarly named entities.
 * Does NOT label any company as "fraud" by name alone.
 */

import { deepFreeze } from "./security.js";

/**
 * Structured public-information dossier.
 * Sources should be verifiable by the user; strength of evidence is declared.
 */
export const QUESTNET_DOSSIER = deepFreeze({
  title_ar: "ملف تحقيق: كويست نيت / QNet",
  title_en: "Investigation file: Quest Net / QNet",
  last_reviewed: "2026-01-15",
  methodology_ar:
    "يعتمد هذا الملف على معلومات عامة وتقارير منشورة. يميّز بين الكيانات المتشابهة في الاسم. لا يصدر حكماً قضائياً. التصنيفات مبنية على نوع الدليل (تحذير رسمي، حكم، تقرير صحفي، شكوى عامة).",
  methodology_en:
    "This file relies on public information and published reports. It distinguishes similarly named entities. It does not issue judicial rulings. Classifications are based on evidence type (official warning, court ruling, press report, public complaint).",
  entities: [
    {
      id: "qnet-main",
      legal_name_candidates: ["QNet Ltd", "QNet", "Quest Net", "QuestNet"],
      note_ar: "الأسماء أعلاه قد تشير إلى كيانات أو علامات مرتبطة أو منفصلة حسب البلد والتسجيل. يجب التحقق من السجل التجاري المحلي.",
      note_en: "The names above may refer to related or separate entities depending on country and registration. Verify local commercial registries.",
      activity_ar: "يُشار إليه علناً بنموذج تسويق متعدد المستويات (MLM) / بيع مباشر، مع منتجات وخطط عمولات.",
      activity_en: "Publicly associated with multi-level marketing (MLM) / direct selling models, products, and commission plans.",
      regions_mentioned: ["Asia", "Middle East", "Africa", "Europe", "global"],
      timeline: [
        {
          period: "1990s–2000s",
          ar: "ظهور مبكر لكيانات/علامات مرتبطة بالبيع المباشر في آسيا.",
          en: "Early appearance of related direct-selling entities/brands in Asia.",
          evidence: "public_history",
        },
        {
          period: "2010s–2020s",
          ar: "شكاوى وتقارير إعلامية وتنظيمية في عدة دول حول ممارسات التسويق الهرمي أو الوعود الاستثمارية — تختلف حسب البلد.",
          en: "Complaints and media/regulatory reports in multiple countries regarding pyramid-like marketing practices or investment-style promises — vary by country.",
          evidence: "mixed_public_reports",
        },
      ],
      regulatory_notes: [
        {
          ar: "في بعض الدول وُجدت تحقيقات أو قيود أو تحذيرات تتعلق بممارسات MLM. راجع الجهات الرقابية المحلية لكل بلد على حدة.",
          en: "In some countries there have been investigations, restrictions, or warnings related to MLM practices. Check local regulators per country.",
          strength: "medium",
          kind: "regulatory_attention",
        },
      ],
      middle_east_ar:
        "وردت شكاوى عامة وتداول لاسم كويست نيت / QNet في أوساط مستخدمين في سوريا ولبنان والعراق ودول خليجية. الشكاوى الفردية ليست حكماً قضائياً؛ يُنصح بالتحقق من الترخيص المحلي وعدم دفع مبالغ مقابل وعود أرباح مضمونة.",
      middle_east_en:
        "Public complaints and discussion of the Quest Net / QNet name have appeared among users in Syria, Lebanon, Iraq, and Gulf states. Individual complaints are not court rulings; verify local licensing and avoid paying for guaranteed-profit promises.",
      what_users_should_do_ar: [
        "لا تعتمد على الاسم alone — تحقق من السجل التجاري والترخيص في بلدك.",
        "اطلب عقداً واضحاً واقرأ خطة العمولات بعناية.",
        "احذر من وعود أرباح مضمونة أو ضغط للتجنيد السريع.",
        "احتفظ بكل التحويلات والمراسلات.",
        "إذا تعرضت لخسارة، وثّق الأدلة وأبلغ الجهات المختصة محلياً.",
      ],
      what_users_should_do_en: [
        "Do not rely on the name alone — verify commercial registration and licensing in your country.",
        "Request a clear contract and read the commission plan carefully.",
        "Beware of guaranteed profits or pressure to recruit quickly.",
        "Keep all transfers and correspondence.",
        "If you suffered losses, document evidence and report to local authorities.",
      ],
    },
  ],
  distinctions_ar:
    "قد توجد شركات أخرى بأسماء مشابهة (Quest Network، QuestNet في سياقات تقنية، إلخ). لا تُدمج السجلات دون دليل على الهوية القانونية نفسها.",
  distinctions_en:
    "Other companies may exist with similar names (Quest Network, QuestNet in technical contexts, etc.). Do not merge records without evidence of the same legal identity.",
  sources_for_user: [
    {
      title: "FCA Warning List (UK) — search for unauthorized firms",
      url: "https://www.fca.org.uk/consumers/warning-list-unauthorised-firms",
    },
    {
      title: "IOSCO Investor Alerts",
      url: "https://www.iosco.org/investor_protection/?subsection=investor_alerts_portal",
    },
    {
      title: "Local commercial registries (country-specific)",
      url: null,
    },
  ],
  evidence_legend_ar: {
    high: "تحذير رسمي أو حكم منشور",
    medium: "تقارير متعددة أو اهتمام تنظيمي موثق",
    low: "شكاوى عامة أو تقارير إعلامية منفردة",
    pattern: "نمط سلوكي شائع دون ربط بكيان محدد",
  },
  evidence_legend_en: {
    high: "Official warning or published ruling",
    medium: "Multiple reports or documented regulatory attention",
    low: "Public complaints or isolated press reports",
    pattern: "Common behavioral pattern without binding to a specific entity",
  },
});

export function getQuestnetDossier() {
  return QUESTNET_DOSSIER;
}
