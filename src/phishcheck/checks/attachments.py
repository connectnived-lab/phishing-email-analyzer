"""Attachment checks: dangerous file types, disguised extensions, Office macros."""

from __future__ import annotations

from ..config import load_rules, weight
from ..models import Finding
from ..parser import ParsedEmail

OLE_MAGIC = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
MACRO_MARKERS = (b"vbaProject.bin", b"_VBA_PROJECT", b"VBA/", b"Attribute VB_")


def extensions(filename: str) -> list[str]:
    parts = filename.lower().strip().strip(".").split(".")
    return [p.strip() for p in parts[1:]] if len(parts) > 1 else []


def has_macro_bytes(data: bytes) -> bool:
    return any(marker in data for marker in MACRO_MARKERS)


def run(email: ParsedEmail) -> list[Finding]:
    rules = load_rules()
    findings: list[Finding] = []
    for att in email.attachments:
        name = att.filename
        exts = extensions(name)
        last = exts[-1] if exts else ""

        if len(exts) >= 2 and exts[-2] in rules["decoy_extensions"] and last not in rules["decoy_extensions"]:
            findings.append(Finding(
                "A_DOUBLE_EXT", "attachments", "Attachment has a disguised file type",
                f"\"{name}\" looks like a .{exts[-2]} file but is really a .{last} file. Windows often hides "
                "the last extension, so the file appears harmless.",
                weight("A_DOUBLE_EXT"), [name]))

        if last in rules["dangerous_extensions"]:
            findings.append(Finding(
                "A_DANGEROUS_EXT", "attachments", "Attachment can run programs on your computer",
                f"\"{name}\" is a .{last} file, which can install malware as soon as it is opened. "
                "Do not open it; report it to IT.",
                weight("A_DANGEROUS_EXT"), [name]))
        elif last in rules["macro_extensions"] or (
            last in rules["legacy_office_extensions"] and att.data.startswith(OLE_MAGIC) and has_macro_bytes(att.data)
        ) or (last in ("docx", "xlsx", "pptx") and has_macro_bytes(att.data)):
            findings.append(Finding(
                "A_MACRO", "attachments", "Office document with macros",
                f"\"{name}\" is an Office file that contains or supports macros. If you click "
                "\"Enable Content\", hidden code can run and infect the PC.",
                weight("A_MACRO"), [name]))
        elif last in rules["html_extensions"]:
            findings.append(Finding(
                "A_HTML_ATTACHMENT", "attachments", "Web page sent as an attachment",
                f"\"{name}\" is a web page file. Opening it usually shows a fake login page that sends "
                "your password to the attacker.",
                weight("A_HTML_ATTACHMENT"), [name]))
        elif last in rules["archive_extensions"]:
            findings.append(Finding(
                "A_ARCHIVE", "attachments", "Compressed archive attached",
                f"\"{name}\" is a compressed archive. Archives are often used to sneak malware past "
                "email filters. Only open it if you were expecting it.",
                weight("A_ARCHIVE"), [name]))
    return findings
