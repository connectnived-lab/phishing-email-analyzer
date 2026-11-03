"""The browser demo (web/js/analyzer.js) must score exactly like the Python package.

Runs the JavaScript engine under Node. Skipped when Node is not installed.
"""

import json
import shutil
import subprocess
from pathlib import Path

import pytest

from phishcheck import analyze_file

from conftest import SAMPLES, make_email
from test_content_attachments import with_attachment

ROOT = Path(__file__).resolve().parent.parent
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="node is not installed")

EXTRA = {
    "punycode.eml": make_email(html='<a href="https://xn--pypal-4ve.com/signin">PayPal</a>'),
    "decimal_ip.eml": make_email(body="Go to http://3232235777/login now"),
    "at_sign.eml": make_email(html='<a href="https://www.sbi.co.in@login-check.top/">www.sbi.co.in</a>'),
    "subdomains.eml": make_email(html='<a href="https://login.secure.account.update.example.top/">Login</a>'),
    "spoof_name.eml": make_email({"From": '"support@hdfcbank.com" <x@evil.top>', "Reply-To": "a@gmail.com",
                                  "Authentication-Results": "mx; spf=softfail; dkim=fail; dmarc=fail"}),
    "freemail_brand.eml": make_email({"From": "SBI Customer Care <sbicare123@gmail.com>"},
                                     body="Dear customer, complete your KYC or your account will be blocked."),
    "no_headers.txt": "Dear user, you have won a lucky draw! Claim now at https://bit.ly/x1 and enter your OTP.",
    "double_ext.eml": with_attachment("Invoice.pdf.exe"),
    "html_attach.eml": with_attachment("Payment_Advice.html"),
    "macro.eml": with_attachment("report.xlsm"),
    "unicode_body.eml": make_email(body="₹ 5000 refund amount pending. Visit https://аmazon.in/refund"),
}


def run_node(paths):
    out = subprocess.run([NODE, str(ROOT / "scripts" / "web_analyze.js"), *map(str, paths)],
                         capture_output=True, text=True, timeout=60, check=True)
    return json.loads(out.stdout)


def test_web_engine_matches_python(tmp_path):
    paths = sorted(SAMPLES.glob("*/*.eml"))
    for name, raw in EXTRA.items():
        p = tmp_path / name
        p.write_text(raw, encoding="utf-8")
        paths.append(p)
    for js in run_node(paths):
        py = analyze_file(js["file"]).to_dict()
        assert [f["rule_id"] for f in js["findings"]] == [f["rule_id"] for f in py["findings"]], js["file"]
        assert js["score"] == py["score"] and js["verdict"] == py["verdict"], js["file"]
        assert js["summary"]["authentication"] == py["summary"]["authentication"]
        assert js["summary"]["hops"] == py["summary"]["hops"]


def test_generated_web_files_are_up_to_date():
    rules_js = (ROOT / "web" / "js" / "rules.js").read_text(encoding="utf-8")
    rules = json.loads((ROOT / "src" / "phishcheck" / "data" / "rules.json").read_text(encoding="utf-8"))
    assert json.dumps(rules, ensure_ascii=False) in rules_js, "run: python scripts/build_web.py"
