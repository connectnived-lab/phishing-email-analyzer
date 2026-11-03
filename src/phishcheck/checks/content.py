"""Language checks: urgency, requests for passwords/OTP, common Indian scam wording."""

from __future__ import annotations

import re

from ..config import load_rules, weight
from ..models import Finding
from ..parser import ParsedEmail

TEXT = {
    "C_URGENCY": ("Pressure to act quickly",
        "The email tries to rush you with deadlines or threats (account closure, legal action). "
        "Scammers create panic so you act before you think."),
    "C_CREDENTIALS": ("Asks for passwords, OTP or payment details",
        "The email asks you to log in, confirm a password, or share an OTP, PIN or card details. "
        "Genuine banks and IT teams never ask for these by email."),
    "C_INDIA_SCAM": ("Uses wording from common Indian scams",
        "The email uses phrases seen in widespread scams in India, such as KYC updates, blocked "
        "accounts, PAN/Aadhaar linking, tax refunds or electricity disconnection."),
    "C_PRIZE": ("Promises a prize or reward",
        "The email says you have won something or offers money or gifts. Unexpected prizes are a "
        "classic lure, often followed by a request for a \"processing fee\" or your bank details."),
    "C_ENABLE_CONTENT": ("Tells you to enable macros",
        "The email tells you to click \"Enable Content\" or \"Enable Macros\". That button lets hidden "
        "code inside a document run, which is how many ransomware infections start."),
    "C_GENERIC_GREETING": ("Generic greeting instead of your name",
        "The email starts with \"Dear Customer\" or similar. Companies you have an account with "
        "usually address you by name."),
}


def normalize(text: str) -> str:
    text = text.lower().replace("\u2019", "'")
    return re.sub(r"\s+", " ", text)


def matched_phrases(text: str, phrases: list[str]) -> list[str]:
    found = []
    for phrase in phrases:
        if re.search(r"(?<![a-z0-9])" + re.escape(phrase) + r"(?![a-z0-9])", text):
            found.append(phrase)
    return found


def run(email: ParsedEmail) -> list[Finding]:
    text = normalize(email.visible_text)
    phrases = load_rules()["phrases"]
    findings: list[Finding] = []
    for rule, (title, explanation) in TEXT.items():
        found = matched_phrases(text, phrases[rule])
        if not found:
            continue
        points = weight(rule)
        if rule != "C_GENERIC_GREETING" and len(found) >= 3:
            points += 5  # many different pressure phrases: stronger signal
        findings.append(Finding(rule, "content", title, explanation, points,
                                [f"\"{p}\"" for p in found[:6]]))
    return findings
