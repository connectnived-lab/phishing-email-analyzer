import pytest

from phishcheck import analyze_text
from phishcheck.domains import brand_lookalike, registered_domain, subdomain_count

from conftest import make_email


def link_ids(href, text=None):
    html = f'<html><body><a href="{href}">{text or "click here"}</a></body></html>'
    return {f.rule_id for f in analyze_text(make_email(html=html)).findings}


def test_text_vs_href_mismatch():
    assert "L_TEXT_HREF_MISMATCH" in link_ids("https://evil.example.net/x", "https://www.hdfcbank.com")


def test_bare_domain_in_text_is_compared():
    assert "L_TEXT_HREF_MISMATCH" in link_ids("https://evil.example.net/x", "hdfcbank.com")


def test_file_name_in_link_text_is_not_an_address():
    assert "L_TEXT_HREF_MISMATCH" not in link_ids("https://files.example.com/a", "Download Invoice.pdf")


def test_matching_text_and_href_is_fine():
    assert "L_TEXT_HREF_MISMATCH" not in link_ids("https://www.hdfcbank.com/login", "www.hdfcbank.com")


@pytest.mark.parametrize("href", ["http://185.10.20.30/login", "http://3232235777/x", "http://[2001:db8::1]/a"])
def test_ip_urls(href):
    assert "L_IP_URL" in link_ids(href)


def test_shortener():
    assert "L_SHORTENER" in link_ids("https://bit.ly/abc123")


def test_punycode():
    found = link_ids("https://xn--pypal-4ve.com/signin")
    assert "L_PUNYCODE" in found and "L_LOOKALIKE" in found


def test_at_sign():
    assert "L_AT_SIGN" in link_ids("https://www.sbi.co.in@login-check.top/")


def test_suspicious_tld():
    assert "L_SUSPICIOUS_TLD" in link_ids("https://parcel-status.xyz/track")


def test_many_subdomains():
    assert "L_MANY_SUBDOMAINS" in link_ids("https://login.secure.account.update.example.top/")


def test_plain_http():
    assert "L_NO_HTTPS" in link_ids("http://example.org/")


def test_links_in_plain_text_are_checked():
    raw = make_email(body="Pay here: http://203.0.113.5/pay now")
    assert "L_IP_URL" in {f.rule_id for f in analyze_text(raw).findings}


@pytest.mark.parametrize("host,brand", [
    ("hdfcbank-secure.com", "HDFC Bank"),
    ("onlinesbi-kyc.top", "SBI"),
    ("sbi-rewards.in", "SBI"),
    ("paytrn.com", None),          # rn->m makes "paytm"
    ("arnazon.in", "Amazon"),      # rn->m
    ("amaz0n-orders.com", "Amazon"),
    ("rnicrosoft-support.com", "Microsoft"),
    ("micros0ft.com", "Microsoft"),
    ("icicibank.co", "ICICI Bank"),
])
def test_brand_lookalikes(host, brand):
    result = brand_lookalike(host)
    assert result is not None
    if brand:
        assert result[0] == brand


@pytest.mark.parametrize("host", [
    "www.onlinesbi.sbi", "netbanking.hdfcbank.com", "www.amazon.in", "login.microsoftonline.com",
    "paytm.com", "github.com", "example.org", "pineapple.com", "lesbianrights.org",
])
def test_official_and_unrelated_domains_not_flagged(host):
    assert brand_lookalike(host) is None


def test_registered_domain():
    assert registered_domain("a.b.example.co.in") == "example.co.in"
    assert registered_domain("mail.google.com") == "google.com"
    assert subdomain_count("a.b.c.example.com") == 3
