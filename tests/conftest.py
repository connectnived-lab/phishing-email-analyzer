from __future__ import annotations

from pathlib import Path

import pytest

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


@pytest.fixture
def samples_dir() -> Path:
    return SAMPLES


def make_email(headers: dict[str, str] | None = None, body: str = "Hello", html: str | None = None) -> str:
    """Build a small raw email for unit tests."""
    base = {
        "From": "Alice <alice@example.com>",
        "To": "bob@example.org",
        "Subject": "Test",
        "Authentication-Results": "mx.example.org; spf=pass; dkim=pass; dmarc=pass",
        "Received": "from mail.example.com (mail.example.com [192.0.2.1]) by mx.example.org",
        "Message-ID": "<1@example.com>",
    }
    base.update(headers or {})
    lines = [f"{k}: {v}" for k, v in base.items() if v is not None]
    if html is not None:
        lines.append("Content-Type: text/html; charset=utf-8")
        return "\n".join(lines) + "\n\n" + html
    lines.append("Content-Type: text/plain; charset=utf-8")
    return "\n".join(lines) + "\n\n" + body
