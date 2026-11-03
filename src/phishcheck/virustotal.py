"""Optional VirusTotal lookups (off by default).

Only runs when the user passes --virustotal AND the environment variable
VT_API_KEY is set. Lookups use hashes / URL ids, so attachment contents are
never uploaded.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import urllib.error
import urllib.request

from .models import Finding
from .parser import ParsedEmail

API = "https://www.virustotal.com/api/v3"


def api_key() -> str | None:
    return os.environ.get("VT_API_KEY") or None


def _get(path: str, key: str, opener=urllib.request.urlopen) -> dict | None:
    req = urllib.request.Request(API + path, headers={"x-apikey": key})
    try:
        with opener(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None  # VirusTotal has never seen this item
        raise


def _malicious(data: dict | None) -> int:
    if not data:
        return 0
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return int(stats.get("malicious", 0))


def lookup(email: ParsedEmail, key: str, opener=urllib.request.urlopen, max_urls: int = 4) -> list[Finding]:
    findings: list[Finding] = []
    for att in email.attachments:
        sha = hashlib.sha256(att.data).hexdigest()
        hits = _malicious(_get(f"/files/{sha}", key, opener))
        if hits:
            findings.append(Finding(
                "VT_FILE", "attachments", "Attachment is known malware (VirusTotal)",
                f"{hits} antivirus engines on VirusTotal flag \"{att.filename}\" as malicious.",
                50, [sha]))
    for link in email.links[:max_urls]:
        url_id = base64.urlsafe_b64encode(link.href.encode()).decode().strip("=")
        hits = _malicious(_get(f"/urls/{url_id}", key, opener))
        if hits:
            findings.append(Finding(
                "VT_URL", "links", "Link is flagged by VirusTotal",
                f"{hits} security vendors on VirusTotal list this link as malicious or phishing.",
                40, [link.href[:120]]))
    return findings
