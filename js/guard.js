/* TRUST AI — early guard (classic script, runs before the app).
 * 0) Language boot: sets <html lang/dir> from the person's explicit choice, otherwise
 *    the device language (navigator.languages), so the layout is right before first paint.
 *    Mirrors detectLang() in js/i18n.js (ar / en supported, everything else -> en).
 * 1) Anti-clickjacking: GitHub Pages cannot send frame-ancestors / X-Frame-Options,
 *    so the page stays hidden (see <style id="anti-clickjack"> in index.html) and is
 *    only revealed when it is the top-level document.
 * 2) Marks that the guard ran so the self-check can report it honestly. */
(function () {
  "use strict";
  try {
    var pick = null, saved = null;
    try { saved = localStorage.getItem("trustai_lang_user"); } catch (e) {}
    if (saved === "ar" || saved === "en") pick = saved;
    else {
      var list = (navigator.languages && navigator.languages.length) ? navigator.languages
        : [navigator.language || navigator.userLanguage || "en"];
      for (var i = 0; i < list.length && !pick; i++) {
        var c = String(list[i]).toLowerCase().split(/[-_]/)[0];
        if (c === "ar" || c === "en") pick = c;
      }
    }
    pick = pick || "en";
    document.documentElement.lang = pick;
    document.documentElement.dir = pick === "ar" ? "rtl" : "ltr";
  } catch (e) { /* keep the markup defaults */ }
})();
(function () {
  "use strict";
  var framed = true;
  try { framed = window.top !== window.self; } catch (e) { framed = true; }
  if (!framed) {
    var s = document.getElementById("anti-clickjack");
    if (s && s.parentNode) s.parentNode.removeChild(s);
    window.__TRUST_GUARD__ = { framed: false };
  } else {
    window.__TRUST_GUARD__ = { framed: true };
    try { window.top.location = window.self.location; } catch (e) { /* cross-origin top: stay hidden */ }
  }
})();
