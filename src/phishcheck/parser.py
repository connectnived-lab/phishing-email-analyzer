"""Turns a raw email (.eml file or pasted text) into a simple structure.

Only the Python standard library is used. Pasted text without headers is
accepted too; it is treated as a message body.
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass, field
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr
from html.parser import HTMLParser

URL_RE = re.compile(r"""(?i)\b((?:https?://|www\.)[^\s<>"'()\[\]{}]+)""")


@dataclass
class Link:
    href: str
    text: str = ""
    source: str = "text"  # html | text


@dataclass
class Attachment:
    filename: str
    content_type: str
    data: bytes = b""

    @property
    def size(self) -> int:
        return len(self.data)


@dataclass
class ParsedEmail:
    subject: str = ""
    from_name: str = ""
    from_addr: str = ""
    reply_to: list[str] = field(default_factory=list)
    return_path: str = ""
    message_id: str = ""
    date: str = ""
    auth_results: list[str] = field(default_factory=list)
    received: list[str] = field(default_factory=list)
    text_body: str = ""
    html_body: str = ""
    links: list[Link] = field(default_factory=list)
    attachments: list[Attachment] = field(default_factory=list)
    has_headers: bool = True

    @property
    def from_domain(self) -> str:
        return domain_of(self.from_addr)

    @property
    def visible_text(self) -> str:
        """Subject + plain text + text extracted from HTML, for phrase checks."""
        parts = [self.subject, self.text_body, html_to_text(self.html_body)]
        return "\n".join(p for p in parts if p)


def domain_of(address: str) -> str:
    address = (address or "").strip().strip("<>").lower()
    return address.rsplit("@", 1)[1] if "@" in address else ""


class _AnchorCollector(HTMLParser):
    """Collects <a href> targets together with the text the reader sees."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[Link] = []
        self._href: str | None = None
        self._text: list[str] = []
        self.text_chunks: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        if tag == "a":
            href = dict(attrs).get("href")
            if href:
                self._href, self._text = href.strip(), []
        if tag in ("br", "p", "div", "tr", "li"):
            self.text_chunks.append("\n")

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1
        if tag == "a" and self._href is not None:
            self.links.append(Link(self._href, " ".join("".join(self._text).split()), "html"))
            self._href = None

    def handle_data(self, data):
        if self._skip:
            return
        self.text_chunks.append(data)
        if self._href is not None:
            self._text.append(data)


def html_to_text(markup: str) -> str:
    if not markup:
        return ""
    collector = _AnchorCollector()
    collector.feed(markup)
    text = html.unescape("".join(collector.text_chunks))
    return re.sub(r"[ \t]+", " ", text)


def extract_links(text_body: str, html_body: str) -> list[Link]:
    links: list[Link] = []
    seen: set[tuple[str, str]] = set()
    if html_body:
        collector = _AnchorCollector()
        collector.feed(html_body)
        for link in collector.links:
            if link.href.lower().startswith(("http://", "https://", "www.")):
                key = (link.href, link.text)
                if key not in seen:
                    seen.add(key)
                    links.append(link)
    for match in URL_RE.finditer(text_body or ""):
        url = match.group(1).rstrip(".,;:!?")
        if not any(l.href == url for l in links):
            links.append(Link(url, "", "text"))
            seen.add((url, ""))
    return links


def _looks_like_headers(raw: bytes) -> bool:
    first = raw.lstrip()[:2000].decode("utf-8", "replace").splitlines()
    return bool(first) and re.match(r"^[A-Za-z0-9-]{2,}:\s", first[0]) is not None


def _decode_part(part: EmailMessage) -> str:
    try:
        return part.get_content()
    except Exception:  # broken charset or encoding; fall back to raw bytes
        payload = part.get_payload(decode=True) or b""
        return payload.decode("utf-8", "replace")


def parse_email(raw: bytes | str) -> ParsedEmail:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    raw = raw.replace(b"\r\n", b"\n")

    if not _looks_like_headers(raw):
        body = raw.decode("utf-8", "replace")
        is_html = bool(re.search(r"(?i)<(html|body|a\s|div|p>|table)", body))
        parsed = ParsedEmail(has_headers=False)
        if is_html:
            parsed.html_body = body
        else:
            parsed.text_body = body
        parsed.links = extract_links(parsed.text_body, parsed.html_body)
        return parsed

    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(raw)
    parsed = ParsedEmail()
    parsed.subject = str(msg.get("Subject", "") or "")
    name, addr = parseaddr(str(msg.get("From", "") or ""))
    parsed.from_name, parsed.from_addr = name.strip(), addr.strip().lower()
    parsed.reply_to = [a.lower() for _, a in getaddresses([str(v) for v in msg.get_all("Reply-To", [])]) if a]
    parsed.return_path = parseaddr(str(msg.get("Return-Path", "") or ""))[1].lower()
    parsed.message_id = str(msg.get("Message-ID", "") or "").strip()
    parsed.date = str(msg.get("Date", "") or "")
    parsed.auth_results = [str(v) for v in msg.get_all("Authentication-Results", [])]
    parsed.received = [" ".join(str(v).split()) for v in msg.get_all("Received", [])]

    text_parts: list[str] = []
    html_parts: list[str] = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        filename = part.get_filename()
        disposition = part.get_content_disposition()
        ctype = part.get_content_type()
        if filename or disposition == "attachment":
            data = part.get_payload(decode=True) or b""
            parsed.attachments.append(Attachment(filename or "(unnamed)", ctype, data))
        elif ctype == "text/plain":
            text_parts.append(_decode_part(part))
        elif ctype == "text/html":
            html_parts.append(_decode_part(part))

    parsed.text_body = "\n".join(text_parts)
    parsed.html_body = "\n".join(html_parts)
    parsed.links = extract_links(parsed.text_body, parsed.html_body)
    return parsed
