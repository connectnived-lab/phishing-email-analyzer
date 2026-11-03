from phishcheck import analyze_text

from conftest import make_email


def ids(raw):
    return {f.rule_id for f in analyze_text(raw).findings}


def test_reply_to_mismatch():
    assert "H_REPLYTO_MISMATCH" in ids(make_email({"Reply-To": "scammer@gmail.com"}))


def test_reply_to_same_org_is_fine():
    assert "H_REPLYTO_MISMATCH" not in ids(make_email({"Reply-To": "support@help.example.com"}))


def test_return_path_mismatch_only_without_dmarc_pass():
    raw = make_email({"Return-Path": "<b@bulk-sender.net>",
                      "Authentication-Results": "mx; spf=pass; dkim=none; dmarc=none"})
    assert "H_RETURNPATH_MISMATCH" in ids(raw)
    assert "H_RETURNPATH_MISMATCH" not in ids(make_email({"Return-Path": "<b@bulk-sender.net>"}))


def test_display_name_with_fake_address():
    raw = make_email({"From": '"support@hdfcbank.com" <x@evil.top>'})
    assert "H_DISPLAY_EMAIL_SPOOF" in ids(raw)


def test_brand_display_name_on_free_mail():
    raw = make_email({"From": "SBI Customer Care <sbicare123@gmail.com>"})
    found = ids(raw)
    assert "H_FREEMAIL_BRAND" in found
    assert "H_DISPLAY_BRAND_SPOOF" not in found


def test_brand_display_name_on_official_domain_is_fine():
    raw = make_email({"From": "HDFC Bank InstaAlerts <alerts@hdfcbank.net>"})
    assert not ids(raw) & {"H_DISPLAY_BRAND_SPOOF", "H_FREEMAIL_BRAND", "H_SENDER_LOOKALIKE"}


def test_brand_name_on_unrelated_domain():
    assert "H_DISPLAY_BRAND_SPOOF" in ids(make_email({"From": "Paytm Rewards <win@rewards-centre.in>"}))


def test_sender_lookalike_domain():
    assert "H_SENDER_LOOKALIKE" in ids(make_email({"From": "Support <help@paypa1.com>"}))


def test_auth_failures():
    raw = make_email({"Authentication-Results": "mx; spf=fail; dkim=fail; dmarc=fail"})
    assert {"H_SPF_FAIL", "H_DKIM_FAIL", "H_DMARC_FAIL"} <= ids(raw)


def test_softfail():
    assert "H_SPF_SOFTFAIL" in ids(make_email({"Authentication-Results": "mx; spf=softfail; dmarc=pass"}))


def test_only_topmost_auth_header_is_trusted():
    raw = make_email({"Authentication-Results": "mx.real; spf=fail; dmarc=fail"}).replace(
        "Message-ID: <1@example.com>",
        "Message-ID: <1@example.com>\nAuthentication-Results: forged-by-sender; spf=pass; dkim=pass; dmarc=pass")
    assert {"H_SPF_FAIL", "H_DMARC_FAIL"} <= ids(raw)


def test_missing_auth_results():
    assert "H_NO_AUTH" in ids(make_email({"Authentication-Results": None}))


def test_pasted_body_without_headers():
    report = analyze_text("Dear customer, your account has been blocked. Update your KYC now.")
    found = {f.rule_id for f in report.findings}
    assert "H_NO_HEADERS" in found and "C_INDIA_SCAM" in found
