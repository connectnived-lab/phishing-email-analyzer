import base64

import pytest

from phishcheck import analyze_text

from conftest import make_email


def ids(raw):
    return {f.rule_id for f in analyze_text(raw).findings}


@pytest.mark.parametrize("text,rule", [
    ("Your account will be suspended within 24 hours.", "C_URGENCY"),
    ("Please verify your account by entering your password.", "C_CREDENTIALS"),
    ("Complete your KYC or your account will be blocked.", "C_INDIA_SCAM"),
    ("Link your PAN with Aadhaar today.", "C_INDIA_SCAM"),
    ("Congratulations, you have won the lucky draw!", "C_PRIZE"),
    ("Dear Customer, thank you.", "C_GENERIC_GREETING"),
    ("Open the file and click Enable Content.", "C_ENABLE_CONTENT"),
])
def test_phrases(text, rule):
    assert rule in ids(make_email(body=text))


def test_safety_advice_is_not_a_credential_request():
    body = "HDFC Bank will never ask for your password or OTP. Do not share them with anyone."
    assert "C_CREDENTIALS" not in ids(make_email(body=body))


def test_word_boundaries():
    # "winners" is not "winner"; "pancard" alone is not "pan card"
    assert "C_PRIZE" not in ids(make_email(body="Our team members are all winners of hearts."))


def with_attachment(name, data=b"x", ctype="application/octet-stream"):
    b64 = base64.b64encode(data).decode()
    return (
        "From: a@example.com\nTo: b@example.org\nSubject: file\n"
        "Authentication-Results: mx; spf=pass; dkim=pass; dmarc=pass\n"
        "MIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=XX\n\n"
        "--XX\nContent-Type: text/plain\n\nsee attached\n"
        f"--XX\nContent-Type: {ctype}; name=\"{name}\"\nContent-Disposition: attachment; filename=\"{name}\"\n"
        f"Content-Transfer-Encoding: base64\n\n{b64}\n--XX--\n"
    )


@pytest.mark.parametrize("name", ["setup.exe", "invoice.js", "photo.scr", "update.iso", "doc.lnk", "run.ps1"])
def test_dangerous_extensions(name):
    assert "A_DANGEROUS_EXT" in ids(with_attachment(name))


def test_double_extension():
    found = ids(with_attachment("Invoice.pdf.exe"))
    assert {"A_DOUBLE_EXT", "A_DANGEROUS_EXT"} <= found


def test_macro_extension():
    assert "A_MACRO" in ids(with_attachment("report.xlsm"))


def test_legacy_doc_with_vba_stream():
    data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100 + b"_VBA_PROJECT" + b"\x00" * 10
    assert "A_MACRO" in ids(with_attachment("old.doc", data))


def test_plain_doc_without_macros_is_fine():
    data = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1" + b"\x00" * 100
    assert not ids(with_attachment("old.doc", data)) & {"A_MACRO", "A_DANGEROUS_EXT"}


def test_html_and_archive():
    assert "A_HTML_ATTACHMENT" in ids(with_attachment("Payment_Advice.html"))
    assert "A_ARCHIVE" in ids(with_attachment("docs.zip"))


def test_pdf_is_fine():
    assert not any(r.startswith("A_") for r in ids(with_attachment("quote.pdf", b"%PDF-1.4")))
