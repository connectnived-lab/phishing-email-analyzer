/*
 * PhishCheck browser engine - a JavaScript port of the Python rules in
 * src/phishcheck. Runs entirely in the browser: nothing is uploaded.
 * Rule data (weights, brands, phrases) comes from rules.js, which is
 * generated from src/phishcheck/data/rules.json by scripts/build_web.py.
 */
(function (root) {
  "use strict";

  function R() { return root.PHISHCHECK_RULES; }
  function weight(id) { return R().weights[id]; }

  // ---------------------------------------------------------------- bytes
  function latin1ToBytes(s) {
    var out = new Uint8Array(s.length);
    for (var i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
    return out;
  }
  function bytesToLatin1(b) {
    var s = "";
    for (var i = 0; i < b.length; i += 8192) s += String.fromCharCode.apply(null, b.subarray(i, i + 8192));
    return s;
  }
  function decodeBytes(bytes, charset) {
    charset = (charset || "utf-8").toLowerCase();
    try { return new TextDecoder(charset).decode(bytes); }
    catch (e) { return new TextDecoder("utf-8").decode(bytes); }
  }
  function base64ToBytes(s) {
    s = s.replace(/[^A-Za-z0-9+/=]/g, "");
    try { return latin1ToBytes(atob(s)); } catch (e) { return new Uint8Array(0); }
  }
  function qpToBytes(s) {
    s = s.replace(/=\r?\n/g, "");
    var out = [];
    for (var i = 0; i < s.length; i++) {
      var c = s[i];
      if (c === "=" && /^[0-9A-Fa-f]{2}$/.test(s.substr(i + 1, 2))) { out.push(parseInt(s.substr(i + 1, 2), 16)); i += 2; }
      else out.push(s.charCodeAt(i) & 0xff);
    }
    return new Uint8Array(out);
  }

  // ---------------------------------------------------------------- headers
  function decodeWords(value) {
    // RFC 2047 encoded words, e.g. =?UTF-8?B?...?=
    return value.replace(/=\?([^?]+)\?([bBqQ])\?([^?]*)\?=(\s+(?==\?))?/g, function (_, cs, enc, text) {
      var bytes = enc.toUpperCase() === "B" ? base64ToBytes(text) : qpToBytes(text.replace(/_/g, " "));
      return decodeBytes(bytes, cs);
    });
  }
  function parseHeaderBlock(block) {
    var unfolded = block.replace(/\n[ \t]+/g, " ");
    var list = [];
    unfolded.split("\n").forEach(function (line) {
      var m = /^([!-9;-~]+):\s*(.*)$/.exec(line);
      if (m) list.push([m[1].toLowerCase(), decodeWords(m[2]).trim()]);
    });
    return list;
  }
  function getAll(headers, name) { return headers.filter(function (h) { return h[0] === name; }).map(function (h) { return h[1]; }); }
  function getOne(headers, name) { var a = getAll(headers, name); return a.length ? a[0] : ""; }
  function headerParams(value) {
    var parts = value.split(";"), params = { _: parts[0].trim().toLowerCase() };
    parts.slice(1).forEach(function (p) {
      var m = /^\s*([^=\s]+)\s*=\s*"?([^"]*)"?\s*$/.exec(p);
      if (m) params[m[1].toLowerCase()] = m[2];
    });
    return params;
  }
  function parseAddr(value) {
    value = (value || "").trim();
    var m = /^(.*?)<([^>]*)>/.exec(value);
    if (m) return { name: m[1].trim().replace(/^"|"$/g, "").trim(), addr: m[2].trim().toLowerCase() };
    var bare = /[^\s<>"]+@[^\s<>",]+/.exec(value);
    return { name: "", addr: bare ? bare[0].toLowerCase() : "" };
  }
  function addressList(value) {
    var out = [];
    (value.match(/[^\s<>",;]+@[^\s<>",;]+/g) || []).forEach(function (a) { out.push(a.toLowerCase()); });
    return out;
  }
  function domainOf(addr) {
    addr = (addr || "").trim().replace(/^<|>$/g, "").toLowerCase();
    var i = addr.lastIndexOf("@");
    return i >= 0 ? addr.slice(i + 1) : "";
  }

  // ---------------------------------------------------------------- html
  var ENTITIES = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: "\u00a0" };
  function decodeEntities(s) {
    return s.replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, function (m, e) {
      if (e[0] === "#") return String.fromCodePoint(e[1] === "x" || e[1] === "X" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10));
      return ENTITIES[e.toLowerCase()] !== undefined ? ENTITIES[e.toLowerCase()] : m;
    });
  }
  function stripScripts(html) { return html.replace(/<(script|style)\b[\s\S]*?<\/\1\s*>/gi, ""); }
  function htmlToText(html) {
    if (!html) return "";
    var t = stripScripts(html).replace(/<(br|p|div|tr|li)\b[^>]*>/gi, "\n").replace(/<[^>]*>/g, "");
    return decodeEntities(t).replace(/[ \t]+/g, " ");
  }
  function anchors(html) {
    var out = [], re = /<a\b([^>]*)>([\s\S]*?)<\/a\s*>/gi, m;
    html = stripScripts(html);
    while ((m = re.exec(html))) {
      var h = /\bhref\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+))/i.exec(m[1]);
      if (!h) continue;
      var href = decodeEntities(h[1] !== undefined ? h[1] : h[2] !== undefined ? h[2] : h[3]).trim();
      var text = decodeEntities(m[2].replace(/<[^>]*>/g, "")).split(/\s+/).filter(Boolean).join(" ");
      if (href) out.push({ href: href, text: text, source: "html" });
    }
    return out;
  }
  var URL_RE = /\b((?:https?:\/\/|www\.)[^\s<>"'()\[\]{}]+)/gi;
  function extractLinks(textBody, htmlBody) {
    var links = [], seen = {};
    if (htmlBody) anchors(htmlBody).forEach(function (l) {
      if (/^(https?:\/\/|www\.)/i.test(l.href) && !seen[l.href + "\u0000" + l.text]) { seen[l.href + "\u0000" + l.text] = 1; links.push(l); }
    });
    var m; URL_RE.lastIndex = 0;
    while ((m = URL_RE.exec(textBody || ""))) {
      var url = m[1].replace(/[.,;:!?]+$/, "");
      if (!links.some(function (l) { return l.href === url; })) links.push({ href: url, text: "", source: "text" });
    }
    return links;
  }

  // ---------------------------------------------------------------- MIME
  function splitHead(raw) {
    var i = raw.indexOf("\n\n");
    return i < 0 ? [raw, ""] : [raw.slice(0, i), raw.slice(i + 2)];
  }
  function walk(raw, email) {
    var hb = splitHead(raw), headers = parseHeaderBlock(decodeBytes(latin1ToBytes(hb[0]), "utf-8")), body = hb[1];
    var ct = headerParams(getOne(headers, "content-type") || "text/plain");
    var cd = headerParams(getOne(headers, "content-disposition") || "");
    var cte = (getOne(headers, "content-transfer-encoding") || "7bit").toLowerCase();
    if (ct._.indexOf("multipart/") === 0 && ct.boundary) {
      var sep = "--" + ct.boundary, chunks = body.split(sep);
      chunks.slice(1).forEach(function (chunk) {
        if (chunk.indexOf("--") === 0) return;
        walk(chunk.replace(/^[ \t]*\n/, ""), email);
      });
      return headers;
    }
    var bytes = cte === "base64" ? base64ToBytes(body) : cte === "quoted-printable" ? qpToBytes(body) : latin1ToBytes(body);
    var filename = cd.filename || ct.name;
    if (filename) filename = decodeWords(filename);
    if (filename || cd._ === "attachment") {
      email.attachments.push({ filename: filename || "(unnamed)", contentType: ct._, data: bytes });
    } else if (ct._ === "text/plain") {
      email.textParts.push(decodeBytes(bytes, ct.charset));
    } else if (ct._ === "text/html") {
      email.htmlParts.push(decodeBytes(bytes, ct.charset));
    }
    return headers;
  }

  function textToBinary(text) {
    // JS string -> UTF-8 bytes held one per char, the same shape FileReader.readAsBinaryString gives
    return bytesToLatin1(new TextEncoder().encode(text));
  }

  function parseEmail(binary) {
    // binary: the raw email as a "binary string" (one char per byte)
    var raw = String(binary).replace(/\r\n/g, "\n");
    var firstLine = raw.replace(/^\s+/, "").split("\n")[0] || "";
    var email = { subject: "", fromName: "", fromAddr: "", replyTo: [], returnPath: "", messageId: "",
                  authResults: [], received: [], textBody: "", htmlBody: "", links: [], attachments: [],
                  hasHeaders: true, textParts: [], htmlParts: [] };
    if (!/^[A-Za-z0-9-]{2,}:\s/.test(firstLine)) {
      email.hasHeaders = false;
      var body = decodeBytes(latin1ToBytes(raw), "utf-8");
      if (/<(html|body|a\s|div|p>|table)/i.test(body)) email.htmlBody = body; else email.textBody = body;
      email.links = extractLinks(email.textBody, email.htmlBody);
      return email;
    }
    var headers = walk(raw, email);
    email.subject = getOne(headers, "subject");
    var from = parseAddr(getOne(headers, "from"));
    email.fromName = from.name; email.fromAddr = from.addr;
    getAll(headers, "reply-to").forEach(function (v) { email.replyTo = email.replyTo.concat(addressList(v)); });
    email.returnPath = parseAddr(getOne(headers, "return-path")).addr;
    email.messageId = getOne(headers, "message-id");
    email.authResults = getAll(headers, "authentication-results");
    email.received = getAll(headers, "received").map(function (r) { return r.split(/\s+/).join(" "); });
    email.textBody = email.textParts.join("\n");
    email.htmlBody = email.htmlParts.join("\n");
    email.links = extractLinks(email.textBody, email.htmlBody);
    return email;
  }

  // ---------------------------------------------------------------- domains
  function punycodeDecode(input) {
    var base = 36, tMin = 1, tMax = 26, skew = 38, damp = 700, n = 128, bias = 72, i = 0, output = [];
    var basic = input.lastIndexOf("-");
    for (var j = 0; j < Math.max(basic, 0); j++) output.push(input.charCodeAt(j));
    function adapt(delta, num, first) {
      delta = first ? Math.floor(delta / damp) : delta >> 1; delta += Math.floor(delta / num);
      for (var k = 0; delta > ((base - tMin) * tMax) >> 1; k += base) delta = Math.floor(delta / (base - tMin));
      return Math.floor(k + ((base - tMin + 1) * delta) / (delta + skew));
    }
    for (var idx = basic > 0 ? basic + 1 : 0; idx < input.length;) {
      var oldi = i;
      for (var w = 1, k = base; ; k += base) {
        if (idx >= input.length) throw new Error("bad punycode");
        var c = input.charCodeAt(idx++);
        var digit = c - 48 < 10 ? c - 22 : c - 65 < 26 ? c - 65 : c - 97 < 26 ? c - 97 : base;
        if (digit >= base) throw new Error("bad punycode");
        i += digit * w;
        var t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
        if (digit < t) break;
        w *= base - t;
      }
      var len = output.length + 1;
      bias = adapt(i - oldi, len, oldi === 0);
      n += Math.floor(i / len); i %= len;
      output.splice(i++, 0, n);
    }
    return String.fromCodePoint.apply(null, output);
  }
  function toUnicode(host) {
    return host.split(".").map(function (l) {
      if (l.indexOf("xn--") === 0) { try { return punycodeDecode(l.slice(4)); } catch (e) { return l; } }
      return l;
    }).join(".");
  }
  function hostnameOf(url) {
    url = String(url).trim();
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(url)) url = "http://" + url;
    try {
      var h = new URL(url).hostname.toLowerCase().replace(/^\.+|\.+$/g, "");
      return toUnicode(h.replace(/^\[|\]$/g, ""));
    } catch (e) { return ""; }
  }
  function isIp(host) {
    host = host.replace(/^\[|\]$/g, "");
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(host)) return host.split(".").every(function (p) { return +p <= 255; });
    if (host.indexOf(":") >= 0 && /^[0-9a-f:.]+$/i.test(host)) return true;
    return /^(0x[0-9a-f]{8}|\d{8,10})$/i.test(host);
  }
  function registeredDomain(host) {
    host = host.replace(/^\.+|\.+$/g, "").toLowerCase();
    if (!host || isIp(host)) return host;
    var labels = host.split(".");
    if (labels.length <= 2) return host;
    var lastTwo = labels.slice(-2).join(".");
    return R().multi_part_suffixes.indexOf(lastTwo) >= 0 ? labels.slice(-3).join(".") : lastTwo;
  }
  function subdomainCount(host) {
    var reg = registeredDomain(host);
    if (!reg || reg === host) return 0;
    return host.slice(0, -reg.length).replace(/^\.+|\.+$/g, "").split(".").length;
  }
  function tldOf(host) { var i = host.lastIndexOf("."); return i >= 0 ? host.slice(i + 1) : ""; }
  function normalizeConfusables(text) {
    text = toUnicode(text.toLowerCase());
    var table = R().confusables;
    Object.keys(table).sort(function (a, b) { return b.length - a.length; }).forEach(function (src) {
      text = text.split(src).join(table[src]);
    });
    return text;
  }
  function levenshtein(a, b) {
    if (a === b) return 0;
    var prev = [];
    for (var j = 0; j <= b.length; j++) prev.push(j);
    for (var i = 1; i <= a.length; i++) {
      var cur = [i];
      for (j = 1; j <= b.length; j++) cur.push(Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (a[i - 1] !== b[j - 1] ? 1 : 0)));
      prev = cur;
    }
    return prev[b.length];
  }
  function isOfficial(host, brand) {
    host = host.toLowerCase();
    return brand.domains.some(function (d) { return host === d || host.slice(-(d.length + 1)) === "." + d; });
  }
  function officialBrandFor(host) {
    var b = R().brands;
    for (var name in b) if (isOfficial(host, b[name])) return name;
    return null;
  }
  function splitTokens(s) { return s.split(/[.\-_]/).filter(Boolean); }
  function brandLookalike(host) {
    if (!host || isIp(host) || officialBrandFor(host)) return null;
    var brands = R().brands, uni = toUnicode(host), norm = normalizeConfusables(host), tokens = splitTokens(norm);
    var regLabel = normalizeConfusables(registeredDomain(host)).split(".")[0];
    var rawTokens = splitTokens(uni);
    for (var name in brands) {
      var kws = brands[name].keywords;
      for (var i = 0; i < kws.length; i++) {
        var kw = kws[i];
        if (tokens.indexOf(kw) >= 0 || (kw.length >= 6 && norm.indexOf(kw) >= 0)) {
          if (rawTokens.indexOf(kw) < 0 && !(kw.length >= 6 && uni.indexOf(kw) >= 0))
            return [name, 'uses lookalike characters to spell "' + kw + '"'];
          return [name, 'contains the name "' + kw + '" but is not an official ' + name + " domain"];
        }
      }
      for (i = 0; i < kws.length; i++) {
        kw = kws[i];
        if (kw.length < 5) continue;
        var d = levenshtein(regLabel, kw);
        if (d > 0 && d <= (kw.length < 8 ? 1 : 2)) return [name, 'is one or two letters away from "' + kw + '" (typosquatting)'];
      }
    }
    return null;
  }

  function F(id, category, title, explanation, points, evidence) {
    return { rule_id: id, category: category, title: title, explanation: explanation, points: points, evidence: evidence || [] };
  }

  // ---------------------------------------------------------------- header checks
  function sameOrg(a, b) {
    if (!a || !b) return true;
    if (registeredDomain(a) === registeredDomain(b)) return true;
    var ba = officialBrandFor(a), bb = officialBrandFor(b);
    return ba !== null && ba === bb;
  }
  function authResults(email) {
    var found = {};
    if (!email.authResults.length) return found;
    var re = /\b(spf|dkim|dmarc)\s*=\s*([a-z]+)/gi, m;
    while ((m = re.exec(email.authResults[0]))) { var k = m[1].toLowerCase(); if (!(k in found)) found[k] = m[2].toLowerCase(); }
    return found;
  }
  function headerChecks(email) {
    var out = [];
    if (!email.hasHeaders) {
      out.push(F("H_NO_HEADERS", "headers", "No email headers found",
        "Only the message text was provided, so the sender, the route the email took and the authentication results could not be checked. Paste the full original email (\"Show original\" / \"View source\") for a complete check.", 0));
      return out;
    }
    var rules = R(), fromDomain = domainOf(email.fromAddr), auth = authResults(email), dmarcPass = auth.dmarc === "pass";
    for (var i = 0; i < email.replyTo.length; i++) {
      var rdom = domainOf(email.replyTo[i]);
      if (rdom && !sameOrg(rdom, fromDomain)) {
        out.push(F("H_REPLYTO_MISMATCH", "headers", "Replies go to a different address",
          "The email says it is from " + fromDomain + ", but if you press Reply your answer goes to " + rdom + ". Scammers do this so they receive your reply while the sender name looks genuine.",
          weight("H_REPLYTO_MISMATCH"), ["From: " + email.fromAddr, "Reply-To: " + email.replyTo[i]]));
        break;
      }
    }
    var rp = domainOf(email.returnPath);
    if (rp && !sameOrg(rp, fromDomain) && !dmarcPass)
      out.push(F("H_RETURNPATH_MISMATCH", "headers", "Hidden sending address is different",
        "The technical sending address (Return-Path) is on " + rp + ", not " + fromDomain + ". Mailing services sometimes do this legitimately, but together with other warnings it suggests the email was not sent by who it claims.",
        weight("H_RETURNPATH_MISMATCH"), ["Return-Path: " + email.returnPath]));

    var name = email.fromName, lname = name.toLowerCase();
    var embedded = [], em, ere = /[\w.+-]+@([\w-]+(?:\.[\w-]+)+)/g;
    while ((em = ere.exec(name))) embedded.push(em[1].toLowerCase());
    if (embedded.length && embedded.some(function (d) { return !sameOrg(d, fromDomain); }))
      out.push(F("H_DISPLAY_EMAIL_SPOOF", "headers", "Sender name shows a fake email address",
        "The sender name is written to look like the address \"" + name + "\", but the real address behind it is " + email.fromAddr + ". Many phones only show the name, which hides the trick.",
        weight("H_DISPLAY_EMAIL_SPOOF"), ["From: " + name + " <" + email.fromAddr + ">"]));

    var claimed = null, nameTokens = lname.split(/[^a-z0-9]+/);
    for (var b in rules.brands) {
      var brand = rules.brands[b];
      if (brand.keywords.some(function (kw) { return nameTokens.indexOf(kw) >= 0 || (kw.length >= 6 && lname.indexOf(kw) >= 0); })) {
        if (fromDomain && !isOfficial(fromDomain, brand)) { claimed = b; break; }
      }
    }
    if (claimed) {
      if (rules.free_mail.indexOf(registeredDomain(fromDomain)) >= 0)
        out.push(F("H_FREEMAIL_BRAND", "headers", "\"" + claimed + "\" email sent from a free personal account",
          "The sender calls itself " + claimed + ", but the email came from a free " + fromDomain + " account. Banks and large companies never contact customers from Gmail, Yahoo or similar accounts.",
          weight("H_FREEMAIL_BRAND"), ["From: " + name + " <" + email.fromAddr + ">"]));
      else
        out.push(F("H_DISPLAY_BRAND_SPOOF", "headers", "Sender pretends to be " + claimed,
          "The sender name says " + claimed + ", but the email address is on " + fromDomain + ", which is not a domain " + claimed + " uses.",
          weight("H_DISPLAY_BRAND_SPOOF"), ["From: " + name + " <" + email.fromAddr + ">"]));
    }
    var look = brandLookalike(fromDomain);
    if (look)
      out.push(F("H_SENDER_LOOKALIKE", "headers", "Sender domain imitates " + look[0],
        "The sending domain " + fromDomain + " " + look[1] + ". Look-alike domains are a common way to make a fake email seem official.",
        weight("H_SENDER_LOOKALIKE"), [fromDomain]));

    if (!Object.keys(auth).length) {
      out.push(F("H_NO_AUTH", "headers", "No authentication results",
        "The email carries no SPF/DKIM/DMARC results, so there is no proof it really came from the domain it claims. This may simply mean the headers were not included in what you pasted.", weight("H_NO_AUTH")));
    } else {
      if (auth.spf === "fail" || auth.spf === "permerror")
        out.push(F("H_SPF_FAIL", "headers", "SPF check failed",
          "The server that sent this email is not on the list of servers allowed to send mail for " + (fromDomain || "this domain") + ". This is a strong sign of a forged sender.",
          weight("H_SPF_FAIL"), ["spf=" + auth.spf]));
      else if (auth.spf === "softfail")
        out.push(F("H_SPF_SOFTFAIL", "headers", "SPF check soft-failed",
          "The sending server is probably not authorised to send for this domain.", weight("H_SPF_SOFTFAIL"), ["spf=softfail"]));
      if (auth.dkim === "fail" || auth.dkim === "permerror")
        out.push(F("H_DKIM_FAIL", "headers", "Digital signature (DKIM) is invalid",
          "The email's digital signature does not match. Either it was changed on the way or it was not signed by the real sender.",
          weight("H_DKIM_FAIL"), ["dkim=" + auth.dkim]));
      if (auth.dmarc === "fail" || auth.dmarc === "permerror")
        out.push(F("H_DMARC_FAIL", "headers", "DMARC check failed",
          "The owner of " + (fromDomain || "the sender domain") + " publishes a policy saying how to recognise their real emails. This email does not pass it.",
          weight("H_DMARC_FAIL"), ["dmarc=" + auth.dmarc]));
    }
    var mid = /@([\w.-]+)>?$/.exec(email.messageId);
    if (mid && fromDomain) {
      var md = mid[1].toLowerCase();
      if (!sameOrg(md, fromDomain) && !dmarcPass && md.indexOf(".") >= 0)
        out.push(F("H_MSGID_MISMATCH", "headers", "Message ID created by another domain",
          "The email's internal ID was created on " + md + ", not on " + fromDomain + ". On its own this is minor, but it can show the email was sent through an unrelated server.",
          weight("H_MSGID_MISMATCH"), [email.messageId]));
    }
    if (!email.received.length)
      out.push(F("H_NO_RECEIVED", "headers", "No delivery route (Received headers)",
        "The route the email took between servers is not included, so it cannot be traced.", 0));
    return out;
  }

  // ---------------------------------------------------------------- link checks
  var LINK_TEXT = {
    L_TEXT_HREF_MISMATCH: ["Link text hides the real destination", "A link shows one web address but actually opens a different one. This is one of the most common phishing tricks: you think you are going to a trusted site."],
    L_IP_URL: ["Link goes to a bare IP address", "A link points to a number (an IP address) instead of a normal website name. Genuine companies almost never do this; it is typical of hacked or temporary servers."],
    L_SHORTENER: ["Shortened link hides the destination", "A link uses a URL shortener, so you cannot see where it really leads until you click."],
    L_PUNYCODE: ["Website name uses special look-alike characters", "A link uses an internationalised domain name (it starts with \"xn--\" or contains foreign letters). These can display as a familiar name while being a completely different site."],
    L_LOOKALIKE: ["Link imitates a well-known brand", "A link goes to a website made to look like a real brand's site, but it is not owned by that brand."],
    L_SUSPICIOUS_TLD: ["Link uses a domain ending often abused by scammers", "A link ends in a domain extension that is cheap to register and frequently used for scam sites."],
    L_AT_SIGN: ["Link contains an @ symbol", "Everything before an @ in a web address is ignored by the browser. Scammers use this to put a trusted name at the start of a link that really goes elsewhere."],
    L_MANY_SUBDOMAINS: ["Link has an unusually long chain of sub-domains", "A link stacks many words in front of the real domain (for example login.secure.bank.example.top) so the trusted-looking part is at the start and the real owner is hidden at the end."],
    L_NO_HTTPS: ["Link is not encrypted (http instead of https)", "A link uses plain http. Any page asking for a password or card details over http is unsafe."]
  };
  var DOMAIN_IN_TEXT = /\b((?:https?:\/\/)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/\S*)?)/gi;
  function displayDomain(text) {
    var m; DOMAIN_IN_TEXT.lastIndex = 0;
    while ((m = DOMAIN_IN_TEXT.exec(text || ""))) {
      var host = hostnameOf(m[1]);
      if (!host) continue;
      if (/^(https?:\/\/|www\.)/i.test(m[1]) || R().display_tlds.indexOf(tldOf(host)) >= 0) return host;
    }
    return "";
  }
  function linkChecks(email) {
    var rules = R(), hits = {}, order = [], brandsSeen = [];
    function add(rule, ev) {
      if (!hits[rule]) { hits[rule] = []; order.push(rule); }
      if (hits[rule].indexOf(ev) < 0) hits[rule].push(ev);
    }
    email.links.forEach(function (link) {
      var href = link.href.trim(), host = hostnameOf(href);
      if (!host) return;
      var shown = displayDomain(link.text);
      if (shown && registeredDomain(shown) !== registeredDomain(host))
        add("L_TEXT_HREF_MISMATCH", "shows \"" + link.text.slice(0, 80) + "\" but opens " + host);
      var authority = href.replace(/^[a-z]+:\/\//i, "").split("/")[0];
      if (authority.indexOf("@") >= 0) add("L_AT_SIGN", href.slice(0, 120));
      if (isIp(host)) {
        add("L_IP_URL", href.slice(0, 120));
        if (/^http:\/\//i.test(href)) add("L_NO_HTTPS", host);
        return;
      }
      var reg = registeredDomain(host);
      if (rules.shorteners.indexOf(reg) >= 0 || rules.shorteners.indexOf(host) >= 0) add("L_SHORTENER", href.slice(0, 120));
      var asciiHost = (function () { try { return new URL("http://" + host).hostname; } catch (e) { return host; } })();
      if (asciiHost.indexOf("xn--") >= 0 || /[^\x00-\x7f]/.test(host)) add("L_PUNYCODE", asciiHost + " (displays as " + host + ")");
      var look = brandLookalike(host);
      if (look) { add("L_LOOKALIKE", host + " " + look[1]); brandsSeen.push(look[0]); }
      if (rules.suspicious_tlds.indexOf(tldOf(host)) >= 0) add("L_SUSPICIOUS_TLD", host);
      if (subdomainCount(host) >= 3) add("L_MANY_SUBDOMAINS", host);
      if (/^http:\/\//i.test(href)) add("L_NO_HTTPS", host);
    });
    return order.map(function (rule) {
      var t = LINK_TEXT[rule], title = t[0];
      if (rule === "L_LOOKALIKE" && brandsSeen.length) title = "Link imitates " + brandsSeen[0];
      return F(rule, "links", title, t[1], weight(rule), hits[rule].slice(0, 5));
    });
  }

  // ---------------------------------------------------------------- content checks
  var CONTENT_TEXT = [
    ["C_URGENCY", "Pressure to act quickly", "The email tries to rush you with deadlines or threats (account closure, legal action). Scammers create panic so you act before you think."],
    ["C_CREDENTIALS", "Asks for passwords, OTP or payment details", "The email asks you to log in, confirm a password, or share an OTP, PIN or card details. Genuine banks and IT teams never ask for these by email."],
    ["C_INDIA_SCAM", "Uses wording from common Indian scams", "The email uses phrases seen in widespread scams in India, such as KYC updates, blocked accounts, PAN/Aadhaar linking, tax refunds or electricity disconnection."],
    ["C_PRIZE", "Promises a prize or reward", "The email says you have won something or offers money or gifts. Unexpected prizes are a classic lure, often followed by a request for a \"processing fee\" or your bank details."],
    ["C_ENABLE_CONTENT", "Tells you to enable macros", "The email tells you to click \"Enable Content\" or \"Enable Macros\". That button lets hidden code inside a document run, which is how many ransomware infections start."],
    ["C_GENERIC_GREETING", "Generic greeting instead of your name", "The email starts with \"Dear Customer\" or similar. Companies you have an account with usually address you by name."]
  ];
  function escapeRe(s) { return s.replace(/[.*+?^${}()|[\]\\\/]/g, "\\$&"); }
  function visibleText(email) {
    return [email.subject, email.textBody, htmlToText(email.htmlBody)].filter(Boolean).join("\n");
  }
  function contentChecks(email) {
    var text = visibleText(email).toLowerCase().replace(/\u2019/g, "'").replace(/\s+/g, " ");
    var phrases = R().phrases, out = [];
    CONTENT_TEXT.forEach(function (c) {
      var found = phrases[c[0]].filter(function (p) {
        return new RegExp("(^|[^a-z0-9])" + escapeRe(p) + "(?![a-z0-9])").test(text);
      });
      if (!found.length) return;
      var pts = weight(c[0]);
      if (c[0] !== "C_GENERIC_GREETING" && found.length >= 3) pts += 5;
      out.push(F(c[0], "content", c[1], c[2], pts, found.slice(0, 6).map(function (p) { return "\"" + p + "\""; })));
    });
    return out;
  }

  // ---------------------------------------------------------------- attachment checks
  var MACRO_MARKERS = ["vbaProject.bin", "_VBA_PROJECT", "VBA/", "Attribute VB_"];
  function attachmentChecks(email) {
    var rules = R(), out = [];
    email.attachments.forEach(function (att) {
      var name = att.filename, parts = name.toLowerCase().trim().replace(/^\.+|\.+$/g, "").split(".");
      var exts = parts.length > 1 ? parts.slice(1).map(function (e) { return e.trim(); }) : [];
      var last = exts.length ? exts[exts.length - 1] : "";
      var latin = bytesToLatin1(att.data || new Uint8Array(0));
      var hasMacro = MACRO_MARKERS.some(function (m) { return latin.indexOf(m) >= 0; });
      var isOle = latin.slice(0, 8) === "\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1";
      if (exts.length >= 2 && rules.decoy_extensions.indexOf(exts[exts.length - 2]) >= 0 && rules.decoy_extensions.indexOf(last) < 0)
        out.push(F("A_DOUBLE_EXT", "attachments", "Attachment has a disguised file type",
          "\"" + name + "\" looks like a ." + exts[exts.length - 2] + " file but is really a ." + last + " file. Windows often hides the last extension, so the file appears harmless.",
          weight("A_DOUBLE_EXT"), [name]));
      if (rules.dangerous_extensions.indexOf(last) >= 0)
        out.push(F("A_DANGEROUS_EXT", "attachments", "Attachment can run programs on your computer",
          "\"" + name + "\" is a ." + last + " file, which can install malware as soon as it is opened. Do not open it; report it to IT.",
          weight("A_DANGEROUS_EXT"), [name]));
      else if (rules.macro_extensions.indexOf(last) >= 0 || (rules.legacy_office_extensions.indexOf(last) >= 0 && isOle && hasMacro) ||
               (["docx", "xlsx", "pptx"].indexOf(last) >= 0 && hasMacro))
        out.push(F("A_MACRO", "attachments", "Office document with macros",
          "\"" + name + "\" is an Office file that contains or supports macros. If you click \"Enable Content\", hidden code can run and infect the PC.",
          weight("A_MACRO"), [name]));
      else if (rules.html_extensions.indexOf(last) >= 0)
        out.push(F("A_HTML_ATTACHMENT", "attachments", "Web page sent as an attachment",
          "\"" + name + "\" is a web page file. Opening it usually shows a fake login page that sends your password to the attacker.",
          weight("A_HTML_ATTACHMENT"), [name]));
      else if (rules.archive_extensions.indexOf(last) >= 0)
        out.push(F("A_ARCHIVE", "attachments", "Compressed archive attached",
          "\"" + name + "\" is a compressed archive. Archives are often used to sneak malware past email filters. Only open it if you were expecting it.",
          weight("A_ARCHIVE"), [name]));
    });
    return out;
  }

  // ---------------------------------------------------------------- scoring
  function parseHops(received) {
    return received.slice().reverse().map(function (line) {
      var f = /\bfrom\s+([^\s;()]+)/i.exec(line), b = /\bby\s+([^\s;()]+)/i.exec(line);
      var ip = /\[((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]{3,})\]/i.exec(line);
      return { from: f ? f[1] : "", by: b ? b[1] : "", ip: ip ? ip[1] : "" };
    });
  }
  function severity(points) { return points >= 25 ? "high" : points >= 10 ? "medium" : points > 0 ? "low" : "info"; }

  function analyzeText(text) { return analyze(textToBinary(text)); }

  function analyze(binary) {
    var email = parseEmail(binary);
    var findings = [].concat(headerChecks(email), linkChecks(email), contentChecks(email), attachmentChecks(email));
    findings = findings.map(function (f, i) { f._i = i; return f; })
      .sort(function (a, b) { return b.points - a.points || a._i - b._i; })
      .map(function (f) { delete f._i; f.severity = severity(f.points); return f; });
    var total = findings.reduce(function (s, f) { return s + f.points; }, 0);
    var score = Math.max(0, Math.min(100, total)), t = R().thresholds;
    var verdict = score >= t.phishing ? "Phishing" : score >= t.suspicious ? "Suspicious" : "Safe";
    return {
      score: score, verdict: verdict, findings: findings,
      summary: {
        subject: email.subject,
        from: email.fromAddr ? (email.fromName + " <" + email.fromAddr + ">").trim() : "",
        reply_to: email.replyTo, return_path: email.returnPath,
        authentication: authResults(email), hops: parseHops(email.received),
        links: email.links.length, attachments: email.attachments.map(function (a) { return a.filename; })
      }
    };
  }

  var api = { analyze: analyze, analyzeText: analyzeText, parseEmail: parseEmail, brandLookalike: brandLookalike, registeredDomain: registeredDomain, hostnameOf: hostnameOf };
  root.PhishCheck = api;
  if (typeof module !== "undefined" && module.exports) module.exports = api;
})(typeof globalThis !== "undefined" ? globalThis : this);
