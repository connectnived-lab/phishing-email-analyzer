"""Header checks: sender identity, authentication results, Message-ID."""

from __future__ import annotations

import re

from ..config import load_rules, weight
from ..domains import brand_lookalike, is_official, official_brand_for, registered_domain
from ..models import Finding
from ..parser import ParsedEmail, domain_of

AUTH_RE = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.I)


def _same_org(a: str, b: str) -> bool:
    """True if two domains belong to the same registered domain or the same brand."""
    if not a or not b:
        return True
    if registered_domain(a) == registered_domain(b):
        return True
    brand_a, brand_b = official_brand_for(a), official_brand_for(b)
    return brand_a is not None and brand_a == brand_b


def auth_results(email: ParsedEmail) -> dict[str, str]:
    """Read SPF/DKIM/DMARC verdicts from the top-most Authentication-Results header.

    The top-most header is the one added by the receiving server; lower ones
    could have been written by the sender and are not trusted.
    """
    if not email.auth_results:
        return {}
    found: dict[str, str] = {}
    for mech, result in AUTH_RE.findall(email.auth_results[0]):
        found.setdefault(mech.lower(), result.lower())
    return found


def run(email: ParsedEmail) -> list[Finding]:
    findings: list[Finding] = []
    if not email.has_headers:
        findings.append(Finding(
            "H_NO_HEADERS", "headers", "No email headers found",
            "Only the message text was provided, so the sender, the route the email took and the "
            "authentication results could not be checked. Paste the full original email "
            "(\"Show original\" / \"View source\") for a complete check.", 0))
        return findings

    rules = load_rules()
    from_domain = email.from_domain
    auth = auth_results(email)
    dmarc_pass = auth.get("dmarc") == "pass"

    # Reply-To pointing somewhere else
    for addr in email.reply_to:
        rdom = domain_of(addr)
        if rdom and not _same_org(rdom, from_domain):
            findings.append(Finding(
                "H_REPLYTO_MISMATCH", "headers", "Replies go to a different address",
                f"The email says it is from {from_domain}, but if you press Reply your answer goes to "
                f"{rdom}. Scammers do this so they receive your reply while the sender name looks genuine.",
                weight("H_REPLYTO_MISMATCH"), [f"From: {email.from_addr}", f"Reply-To: {addr}"]))
            break

    # Return-Path (bounce address) on another domain
    rp_domain = domain_of(email.return_path)
    if rp_domain and not _same_org(rp_domain, from_domain) and not dmarc_pass:
        findings.append(Finding(
            "H_RETURNPATH_MISMATCH", "headers", "Hidden sending address is different",
            f"The technical sending address (Return-Path) is on {rp_domain}, not {from_domain}. "
            "Mailing services sometimes do this legitimately, but together with other warnings it "
            "suggests the email was not sent by who it claims.",
            weight("H_RETURNPATH_MISMATCH"), [f"Return-Path: {email.return_path}"]))

    name = email.from_name
    lowered_name = name.lower()

    # Display name containing a different email address: "support@hdfcbank.com" <x@evil.top>
    embedded = re.findall(r"[\w.+-]+@([\w-]+(?:\.[\w-]+)+)", name)
    if embedded and any(not _same_org(d.lower(), from_domain) for d in embedded):
        findings.append(Finding(
            "H_DISPLAY_EMAIL_SPOOF", "headers", "Sender name shows a fake email address",
            f"The sender name is written to look like the address \"{name}\", but the real "
            f"address behind it is {email.from_addr}. Many phones only show the name, which hides the trick.",
            weight("H_DISPLAY_EMAIL_SPOOF"), [f"From: {name} <{email.from_addr}>"]))

    # Display name claims a brand that the sending domain does not belong to
    claimed = None
    name_tokens = set(re.split(r"[^a-z0-9]+", lowered_name))
    for brand_name, brand in rules["brands"].items():
        if any(kw in name_tokens or (len(kw) >= 6 and kw in lowered_name) for kw in brand["keywords"]):
            if from_domain and not is_official(from_domain, brand):
                claimed = brand_name
                break
    if claimed:
        if registered_domain(from_domain) in rules["free_mail"]:
            findings.append(Finding(
                "H_FREEMAIL_BRAND", "headers", f"\"{claimed}\" email sent from a free personal account",
                f"The sender calls itself {claimed}, but the email came from a free {from_domain} account. "
                "Banks and large companies never contact customers from Gmail, Yahoo or similar accounts.",
                weight("H_FREEMAIL_BRAND"), [f"From: {name} <{email.from_addr}>"]))
        else:
            findings.append(Finding(
                "H_DISPLAY_BRAND_SPOOF", "headers", f"Sender pretends to be {claimed}",
                f"The sender name says {claimed}, but the email address is on {from_domain}, which is "
                f"not a domain {claimed} uses.",
                weight("H_DISPLAY_BRAND_SPOOF"), [f"From: {name} <{email.from_addr}>"]))

    # Sender domain itself imitates a brand
    look = brand_lookalike(from_domain)
    if look:
        brand_name, reason = look
        findings.append(Finding(
            "H_SENDER_LOOKALIKE", "headers", f"Sender domain imitates {brand_name}",
            f"The sending domain {from_domain} {reason}. Look-alike domains are a common way to make "
            "a fake email seem official.",
            weight("H_SENDER_LOOKALIKE"), [from_domain]))

    # SPF / DKIM / DMARC
    if not auth:
        findings.append(Finding(
            "H_NO_AUTH", "headers", "No authentication results",
            "The email carries no SPF/DKIM/DMARC results, so there is no proof it really came from the "
            "domain it claims. This may simply mean the headers were not included in what you pasted.",
            weight("H_NO_AUTH")))
    else:
        spf = auth.get("spf")
        if spf in ("fail", "permerror"):
            findings.append(Finding(
                "H_SPF_FAIL", "headers", "SPF check failed",
                f"The server that sent this email is not on the list of servers allowed to send mail "
                f"for {from_domain or 'this domain'}. This is a strong sign of a forged sender.",
                weight("H_SPF_FAIL"), [f"spf={spf}"]))
        elif spf == "softfail":
            findings.append(Finding(
                "H_SPF_SOFTFAIL", "headers", "SPF check soft-failed",
                "The sending server is probably not authorised to send for this domain.",
                weight("H_SPF_SOFTFAIL"), ["spf=softfail"]))
        if auth.get("dkim") in ("fail", "permerror"):
            findings.append(Finding(
                "H_DKIM_FAIL", "headers", "Digital signature (DKIM) is invalid",
                "The email's digital signature does not match. Either it was changed on the way or it "
                "was not signed by the real sender.",
                weight("H_DKIM_FAIL"), [f"dkim={auth['dkim']}"]))
        if auth.get("dmarc") in ("fail", "permerror"):
            findings.append(Finding(
                "H_DMARC_FAIL", "headers", "DMARC check failed",
                f"The owner of {from_domain or 'the sender domain'} publishes a policy saying how to "
                "recognise their real emails. This email does not pass it.",
                weight("H_DMARC_FAIL"), [f"dmarc={auth['dmarc']}"]))

    # Message-ID from an unrelated domain
    mid = re.search(r"@([\w.-]+)>?$", email.message_id)
    if mid and from_domain:
        mid_domain = mid.group(1).lower()
        if not _same_org(mid_domain, from_domain) and not dmarc_pass and "." in mid_domain:
            findings.append(Finding(
                "H_MSGID_MISMATCH", "headers", "Message ID created by another domain",
                f"The email's internal ID was created on {mid_domain}, not on {from_domain}. On its own "
                "this is minor, but it can show the email was sent through an unrelated server.",
                weight("H_MSGID_MISMATCH"), [email.message_id]))

    if not email.received:
        findings.append(Finding(
            "H_NO_RECEIVED", "headers", "No delivery route (Received headers)",
            "The route the email took between servers is not included, so it cannot be traced.", 0))
    return findings
