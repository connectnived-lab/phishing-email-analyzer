"""Runs every check and turns the findings into a 0-100 score and a verdict."""

from __future__ import annotations

import re
from pathlib import Path

from .checks import ALL_CHECKS
from .checks.headers import auth_results
from .config import load_rules
from .models import Finding, Report
from .parser import ParsedEmail, parse_email

RECEIVED_FROM = re.compile(r"\bfrom\s+([^\s;()]+)", re.I)
RECEIVED_BY = re.compile(r"\bby\s+([^\s;()]+)", re.I)
RECEIVED_IP = re.compile(r"\[((?:\d{1,3}\.){3}\d{1,3}|[0-9a-f:]{3,})\]", re.I)


def parse_hops(received: list[str]) -> list[dict[str, str]]:
    """Received headers are added top-down, so the list is reversed to read sender -> recipient."""
    hops = []
    for line in reversed(received):
        frm, by, ip = RECEIVED_FROM.search(line), RECEIVED_BY.search(line), RECEIVED_IP.search(line)
        hops.append({
            "from": frm.group(1) if frm else "",
            "by": by.group(1) if by else "",
            "ip": ip.group(1) if ip else "",
        })
    return hops


def score_findings(findings: list[Finding]) -> tuple[int, str]:
    thresholds = load_rules()["thresholds"]
    score = max(0, min(100, sum(f.points for f in findings)))
    if score >= thresholds["phishing"]:
        verdict = "Phishing"
    elif score >= thresholds["suspicious"]:
        verdict = "Suspicious"
    else:
        verdict = "Safe"
    return score, verdict


def analyze_parsed(email: ParsedEmail) -> Report:
    findings: list[Finding] = []
    for check in ALL_CHECKS:
        findings.extend(check(email))
    findings.sort(key=lambda f: f.points, reverse=True)
    score, verdict = score_findings(findings)
    summary = {
        "subject": email.subject,
        "from": f"{email.from_name} <{email.from_addr}>".strip() if email.from_addr else "",
        "reply_to": email.reply_to,
        "return_path": email.return_path,
        "authentication": auth_results(email),
        "hops": parse_hops(email.received),
        "links": len(email.links),
        "attachments": [a.filename for a in email.attachments],
    }
    return Report(score, verdict, findings, summary)


def analyze_bytes(raw: bytes) -> Report:
    return analyze_parsed(parse_email(raw))


def analyze_text(text: str) -> Report:
    return analyze_parsed(parse_email(text))


def analyze_file(path: str | Path) -> Report:
    return analyze_bytes(Path(path).read_bytes())
