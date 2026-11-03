/* Anonymous visit counter for PhishCheck.
   Sends ONLY: this site's name, the event name (e.g. "visit", "analyze", "share_wa"),
   and coarse buckets: where the visit came from ("google", "whatsapp", "direct"...),
   the campaign tag in the link (utm_source / utm_campaign) and the browser language.
   Never sends anything you type or paste, no cookies, no IDs, no IP is stored.
   Counts are aggregate daily numbers: https://nived-stats.sites.tab.bot/ */
(function () {
  "use strict";
  var SITE = "nived-phishcheck", URL_ = "https://nived-stats.sites.tab.bot/api/hit";
  var SRC = [
    [/(^|\.)google\./, "google"], [/(^|\.)bing\.com$/, "bing"], [/duckduckgo\.com$/, "duckduckgo"], [/(^|\.)yahoo\./, "yahoo"],
    [/whatsapp\.|(^|\.)wa\.me$/, "whatsapp"], [/(^|\.)(facebook\.com|fb\.com|fb\.me)$/, "facebook"], [/instagram\.com$/, "instagram"],
    [/linkedin\.com$|(^|\.)lnkd\.in$/, "linkedin"], [/reddit\.com$|(^|\.)redd\.it$/, "reddit"], [/(^|\.)(t\.co|twitter\.com|x\.com)$/, "twitter"],
    [/youtube\.com$|(^|\.)youtu\.be$/, "youtube"], [/(^|\.)(t\.me|telegram\.org|telegram\.me)$/, "telegram"], [/github\.(com|io)$/, "github"],
    [/\.sites\.tab\.bot$/, "nived-sites"]
  ];
  function send(ev, extra) {
    try {
      if (navigator.webdriver || location.protocol !== "https:") return;
      var body = { s: SITE, e: ev };
      if (extra) for (var k in extra) body[k] = extra[k];
      var data = JSON.stringify(body);
      if (navigator.sendBeacon && navigator.sendBeacon(URL_, new Blob([data], { type: "text/plain" }))) return;
      if (window.fetch) fetch(URL_, { method: "POST", body: data, mode: "no-cors", keepalive: true, credentials: "omit" });
    } catch (e) { /* counting is optional */ }
  }
  function source() {
    var h = "";
    try { h = document.referrer ? new URL(document.referrer).hostname.toLowerCase() : ""; } catch (e) { h = ""; }
    if (!h) return "direct";
    if (h === location.hostname) return "internal";
    for (var i = 0; i < SRC.length; i++) if (SRC[i][0].test(h)) return SRC[i][1];
    return "other";
  }
  var tag = function (v) { return String(v || "").toLowerCase().replace(/[^a-z0-9_.-]/g, "").slice(0, 32); };
  var u = "", c = "";
  try {
    var q = new URLSearchParams(location.search);
    u = tag(q.get("utm_source")); c = tag(q.get("utm_campaign"));
    if (q.has("utm_source") || q.has("utm_campaign") || q.has("utm_medium")) {
      q.delete("utm_source"); q.delete("utm_campaign"); q.delete("utm_medium"); q.delete("utm_content");
      var rest = q.toString();
      history.replaceState(history.state, "", location.pathname + (rest ? "?" + rest : "") + location.hash);
    }
  } catch (e) { /* old browser */ }
  // One visit per browser tab (reloads are not counted twice). sessionStorage, not a cookie; cleared when the tab closes.
  var seen = false;
  try { seen = sessionStorage.getItem("nc-visit") === "1"; sessionStorage.setItem("nc-visit", "1"); } catch (e) { seen = false; }
  if (!seen) send("visit", { r: source(), u: u, c: c, l: String(navigator.language || "").slice(0, 12) });
  // Count an action at most `max` times per page load.
  var used = {};
  window.nivedCount = function (ev, extra, max) {
    used[ev] = (used[ev] || 0) + 1;
    if (used[ev] > (max || 50)) return;
    send(ev, extra);
  };
})();
