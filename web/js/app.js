/* UI wiring for the PhishCheck demo. All rendering uses textContent, so
   content from the analysed email can never inject HTML into the page. */
(function () {
  "use strict";

  // Set this to your GitHub repository URL to show a link in the footer.
  var REPO_URL = "https://github.com/connectnived-lab/phishing-email-analyzer";

  var $ = function (id) { return document.getElementById(id); };
  var input = $("email-input");
  var ARC_LENGTH = Math.PI * 80;
  var VERDICT_NOTES = {
    Safe: "No strong warning signs. Still check anything that asks for money or passwords.",
    Suspicious: "Several warning signs. Do not click links or open attachments until you verify the sender another way.",
    Phishing: "Very likely a phishing or scam email. Do not click, reply or open attachments; report it to IT."
  };
  var VERDICT_CLASS = { Safe: "v-safe", Suspicious: "v-susp", Phishing: "v-phish" };
  var CATEGORY = { headers: "Sender", links: "Links", content: "Wording", attachments: "Attachment" };

  function el(tag, cls, text) {
    var e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text !== undefined) e.textContent = text;
    return e;
  }

  function fact(dl, label, value) {
    if (value === undefined || value === null || value === "") return;
    dl.appendChild(el("dt", null, label));
    var dd = el("dd");
    if (value instanceof Node) dd.appendChild(value); else dd.textContent = value;
    dl.appendChild(dd);
  }

  function authNode(auth) {
    var keys = ["spf", "dkim", "dmarc"];
    if (!Object.keys(auth).length) return "not included";
    var wrap = document.createDocumentFragment();
    keys.forEach(function (k) {
      var v = auth[k] || "n/a";
      var cls = v === "pass" ? "pass" : (v === "fail" || v === "permerror") ? "fail" : v === "softfail" ? "soft" : "";
      wrap.appendChild(el("span", "badge " + cls, k.toUpperCase() + " " + v));
    });
    return wrap;
  }

  function setGauge(score, verdict) {
    var fill = $("gauge-fill");
    fill.style.strokeDasharray = ARC_LENGTH;
    fill.style.strokeDashoffset = ARC_LENGTH * (1 - score / 100);
    fill.style.stroke = getComputedStyle(document.documentElement).getPropertyValue(
      verdict === "Phishing" ? "--phish" : verdict === "Suspicious" ? "--susp" : "--safe");
    $("score").textContent = score;
  }

  function render(report) {
    $("empty-state").hidden = true;
    $("result").hidden = false;
    setGauge(report.score, report.verdict);

    var v = $("verdict");
    v.textContent = report.verdict;
    v.className = "verdict " + VERDICT_CLASS[report.verdict];
    $("verdict-note").textContent = VERDICT_NOTES[report.verdict];

    var s = report.summary, dl = $("facts");
    dl.textContent = "";
    fact(dl, "From", s.from || "not included");
    fact(dl, "Subject", s.subject);
    if (s.reply_to.length) fact(dl, "Reply-To", s.reply_to.join(", "));
    fact(dl, "Authentication", authNode(s.authentication));
    if (s.hops.length) {
      var first = s.hops[0];
      fact(dl, "Route", s.hops.length + " server hop" + (s.hops.length > 1 ? "s" : "") +
        (first.from ? ", first: " + first.from + (first.ip ? " [" + first.ip + "]" : "") : ""));
    }
    fact(dl, "Links", String(s.links));
    fact(dl, "Attachments", s.attachments.length ? s.attachments.join(", ") : "none");

    var list = $("findings");
    list.textContent = "";
    var scored = report.findings.filter(function (f) { return f.points > 0; });
    $("finding-count").textContent = scored.length + " warning" + (scored.length === 1 ? "" : "s");
    if (!scored.length) list.appendChild(el("li", "no-findings", "No warning signs found in this email."));
    report.findings.forEach(function (f) {
      var li = el("li", "finding " + f.severity);
      var top = el("div", "finding-top");
      top.appendChild(el("span", "sev", f.severity === "info" ? "note" : f.severity));
      top.appendChild(el("span", "cat", CATEGORY[f.category] || f.category));
      if (f.points > 0) top.appendChild(el("span", "pts", "+" + f.points));
      li.appendChild(top);
      li.appendChild(el("h4", null, f.title));
      li.appendChild(el("p", null, f.explanation));
      if (f.evidence.length) {
        var ev = el("ul", "evidence");
        f.evidence.forEach(function (x) { ev.appendChild(el("li", null, x)); });
        li.appendChild(ev);
      }
      list.appendChild(li);
    });
  }

  function analyzeText() {
    var text = input.value;
    if (!text.trim()) { input.focus(); return; }
    render(PhishCheck.analyzeText(text));
  }

  function analyzeBinary(binary) {
    render(PhishCheck.analyze(binary));
  }

  function readFile(file) {
    var reader = new FileReader();
    reader.onload = function () {
      var binary = reader.result;
      // show a readable copy in the box, analyse the exact bytes
      try { input.value = new TextDecoder("utf-8").decode(Uint8Array.from(binary, function (c) { return c.charCodeAt(0); })); }
      catch (e) { input.value = binary; }
      clearActive();
      analyzeBinary(binary);
    };
    reader.readAsBinaryString(file);
  }

  function clearActive() {
    Array.prototype.forEach.call(document.querySelectorAll(".chip.active"), function (c) { c.classList.remove("active"); });
  }

  function buildSamples() {
    (window.PHISHCHECK_SAMPLES || []).forEach(function (sample) {
      var chip = el("button", "chip", sample.label);
      chip.type = "button";
      chip.dataset.sample = sample.id;
      chip.addEventListener("click", function () {
        input.value = sample.raw;
        clearActive();
        chip.classList.add("active");
        analyzeText();
        if (window.innerWidth < 900) $("result").scrollIntoView({ behavior: "smooth", block: "start" });
      });
      $(sample.kind === "phishing" ? "samples-phishing" : "samples-legit").appendChild(chip);
    });
  }

  $("analyze-btn").addEventListener("click", function () { clearActive(); analyzeText(); });
  $("clear-btn").addEventListener("click", function () {
    input.value = ""; clearActive();
    $("result").hidden = true; $("empty-state").hidden = false; input.focus();
  });
  $("file-input").addEventListener("change", function (e) { if (e.target.files[0]) readFile(e.target.files[0]); e.target.value = ""; });
  input.addEventListener("keydown", function (e) { if ((e.ctrlKey || e.metaKey) && e.key === "Enter") analyzeText(); });
  ["dragenter", "dragover"].forEach(function (t) {
    input.addEventListener(t, function (e) { e.preventDefault(); input.classList.add("dragging"); });
  });
  ["dragleave", "drop"].forEach(function (t) {
    input.addEventListener(t, function () { input.classList.remove("dragging"); });
  });
  input.addEventListener("drop", function (e) {
    var file = e.dataTransfer && e.dataTransfer.files[0];
    if (file) { e.preventDefault(); readFile(file); }
  });

  if (REPO_URL) {
    var a = el("a", null, "Source code and Python CLI on GitHub");
    a.href = REPO_URL; a.rel = "noopener";
    $("repo-link").appendChild(a);
  } else {
    $("repo-link").textContent = "Python CLI + browser demo, same rules";
  }

  buildSamples();
})();
