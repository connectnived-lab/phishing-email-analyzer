"""Domain helpers: hostname parsing, registered domain, lookalike detection."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from .config import load_rules


def hostname_of(url: str) -> str:
    """Return the lower-case hostname of a URL ("" if there is none)."""
    url = url.strip()
    if not re.match(r"(?i)^[a-z][a-z0-9+.-]*://", url):
        url = "http://" + url
    try:
        host = urlsplit(url).hostname or ""
    except ValueError:
        return ""
    return host.strip(".").lower()


def is_ip(host: str) -> bool:
    host = host.strip("[]")
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        pass
    # Decimal / hex encoded IPv4 such as http://3232235777/ or http://0xC0A80001/
    return bool(re.fullmatch(r"(0x[0-9a-f]{8}|\d{8,10})", host))


def to_unicode(host: str) -> str:
    """Decode punycode labels (xn--...) so lookalike characters become visible."""
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return ".".join(labels)


def registered_domain(host: str) -> str:
    """Best-effort "example.co.in" from "mail.login.example.co.in".

    Uses a short list of two-part suffixes instead of the full Public Suffix
    List so the tool needs no downloads.
    """
    host = host.strip(".").lower()
    if not host or is_ip(host):
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    last_two = ".".join(labels[-2:])
    if last_two in load_rules()["multi_part_suffixes"]:
        return ".".join(labels[-3:])
    return last_two


def subdomain_count(host: str) -> int:
    reg = registered_domain(host)
    if not reg or reg == host:
        return 0
    return host[: -len(reg)].strip(".").count(".") + 1


def tld_of(host: str) -> str:
    return host.rsplit(".", 1)[-1] if "." in host else ""


def normalize_confusables(text: str) -> str:
    """Map common lookalike characters to the letter they imitate (0->o, rn->m, Cyrillic a->a)."""
    text = to_unicode(text.lower())
    table = load_rules()["confusables"]
    for src in sorted(table, key=len, reverse=True):
        text = text.replace(src, table[src])
    return text


def levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def is_official(host: str, brand: dict) -> bool:
    host = host.lower()
    return any(host == d or host.endswith("." + d) for d in brand["domains"])


def official_brand_for(host: str) -> str | None:
    for name, brand in load_rules()["brands"].items():
        if is_official(host, brand):
            return name
    return None


def brand_lookalike(host: str) -> tuple[str, str] | None:
    """Return (brand, reason) if host imitates a known brand but is not its real domain."""
    if not host or is_ip(host) or official_brand_for(host):
        return None
    brands = load_rules()["brands"]
    unicode_host = to_unicode(host)
    normalized = normalize_confusables(host)
    tokens = [t for t in re.split(r"[.\-_]", normalized) if t]
    reg_label = normalize_confusables(registered_domain(host)).split(".")[0]

    for name, brand in brands.items():
        for kw in brand["keywords"]:
            if kw in tokens or (len(kw) >= 6 and kw in normalized):
                if kw not in re.split(r"[.\-_]", unicode_host) and not (len(kw) >= 6 and kw in unicode_host):
                    return name, f"uses lookalike characters to spell \"{kw}\""
                return name, f"contains the name \"{kw}\" but is not an official {name} domain"
        for kw in brand["keywords"]:
            if len(kw) < 5:
                continue
            distance = levenshtein(reg_label, kw)
            if 0 < distance <= (1 if len(kw) < 8 else 2):
                return name, f"is one or two letters away from \"{kw}\" (typosquatting)"
    return None
