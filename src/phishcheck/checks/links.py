"""Link checks: where each link really goes compared with what it shows."""

from __future__ import annotations

import re

from ..config import load_rules, weight
from ..domains import (
    brand_lookalike,
    hostname_of,
    is_ip,
    registered_domain,
    subdomain_count,
    tld_of,
    to_unicode,
)
from ..models import Finding
from ..parser import ParsedEmail

DOMAIN_IN_TEXT = re.compile(r"(?i)\b((?:https?://)?(?:[a-z0-9-]+\.)+[a-z]{2,}(?:/\S*)?)")

# rule_id -> (title, explanation template); {items} is filled with examples
TEXT = {
    "L_TEXT_HREF_MISMATCH": ("Link text hides the real destination",
        "A link shows one web address but actually opens a different one. This is one of the most "
        "common phishing tricks: you think you are going to a trusted site."),
    "L_IP_URL": ("Link goes to a bare IP address",
        "A link points to a number (an IP address) instead of a normal website name. Genuine companies "
        "almost never do this; it is typical of hacked or temporary servers."),
    "L_SHORTENER": ("Shortened link hides the destination",
        "A link uses a URL shortener, so you cannot see where it really leads until you click."),
    "L_PUNYCODE": ("Website name uses special look-alike characters",
        "A link uses an internationalised domain name (it starts with \"xn--\" or contains foreign "
        "letters). These can display as a familiar name while being a completely different site."),
    "L_LOOKALIKE": ("Link imitates a well-known brand",
        "A link goes to a website made to look like a real brand's site, but it is not owned by that brand."),
    "L_SUSPICIOUS_TLD": ("Link uses a domain ending often abused by scammers",
        "A link ends in a domain extension that is cheap to register and frequently used for scam sites."),
    "L_AT_SIGN": ("Link contains an @ symbol",
        "Everything before an @ in a web address is ignored by the browser. Scammers use this to put a "
        "trusted name at the start of a link that really goes elsewhere."),
    "L_MANY_SUBDOMAINS": ("Link has an unusually long chain of sub-domains",
        "A link stacks many words in front of the real domain (for example login.secure.bank.example.top) "
        "so the trusted-looking part is at the start and the real owner is hidden at the end."),
    "L_NO_HTTPS": ("Link is not encrypted (http instead of https)",
        "A link uses plain http. Any page asking for a password or card details over http is unsafe."),
}


def _display_domain(text: str) -> str:
    """The web address a link's visible text shows, if it shows one.

    "Download Invoice.pdf" is not treated as an address: without http:// or
    www. the last label must be a common domain ending.
    """
    for m in DOMAIN_IN_TEXT.finditer(text or ""):
        candidate = m.group(1)
        host = hostname_of(candidate)
        if not host:
            continue
        if re.match(r"(?i)^(https?://|www\.)", candidate) or tld_of(host) in load_rules()["display_tlds"]:
            return host
    return ""


def run(email: ParsedEmail) -> list[Finding]:
    rules = load_rules()
    hits: dict[str, list[str]] = {}
    lookalike_brands: list[str] = []

    def add(rule: str, evidence: str) -> None:
        bucket = hits.setdefault(rule, [])
        if evidence not in bucket:
            bucket.append(evidence)

    for link in email.links:
        href = link.href.strip()
        host = hostname_of(href)
        if not host:
            continue

        shown = _display_domain(link.text)
        if shown and registered_domain(shown) != registered_domain(host):
            add("L_TEXT_HREF_MISMATCH", f"shows \"{link.text[:80]}\" but opens {host}")

        authority = re.sub(r"(?i)^[a-z]+://", "", href).split("/", 1)[0]
        if "@" in authority:
            add("L_AT_SIGN", href[:120])

        if is_ip(host):
            add("L_IP_URL", href[:120])
            if href.lower().startswith("http://"):
                add("L_NO_HTTPS", host)
            continue

        reg = registered_domain(host)
        if reg in rules["shorteners"] or host in rules["shorteners"]:
            add("L_SHORTENER", href[:120])

        if "xn--" in host or any(ord(c) > 127 for c in host):
            add("L_PUNYCODE", f"{host} (displays as {to_unicode(host)})")

        look = brand_lookalike(host)
        if look:
            add("L_LOOKALIKE", f"{host} {look[1]}")
            lookalike_brands.append(look[0])

        if tld_of(host) in rules["suspicious_tlds"]:
            add("L_SUSPICIOUS_TLD", host)

        if subdomain_count(host) >= 3:
            add("L_MANY_SUBDOMAINS", host)

        if href.lower().startswith("http://"):
            add("L_NO_HTTPS", host)

    findings: list[Finding] = []
    for rule, evidence in hits.items():
        title, explanation = TEXT[rule]
        if rule == "L_LOOKALIKE" and lookalike_brands:
            title = f"Link imitates {lookalike_brands[0]}"
        findings.append(Finding(rule, "links", title, explanation, weight(rule), evidence[:5]))
    return findings
