import io
import json

from phishcheck import cli
from phishcheck import virustotal
from phishcheck.parser import parse_email

from conftest import SAMPLES


def test_cli_text_output_and_exit_code(capsys):
    code = cli.main(["analyze", "--no-color", str(SAMPLES / "phishing" / "03_paytm_lottery.eml")])
    out = capsys.readouterr().out
    assert code == 2
    assert "PHISHING" in out and "risk score" in out


def test_cli_json(capsys):
    code = cli.main(["analyze", "--json", str(SAMPLES / "legit" / "01_github_security_alert.eml")])
    data = json.loads(capsys.readouterr().out)
    assert code == 0
    assert data["verdict"] == "Safe" and data["score"] < 30
    assert data["summary"]["authentication"]["dmarc"] == "pass"
    assert len(data["summary"]["hops"]) == 2


def test_cli_multiple_files_json(capsys):
    files = [str(p) for p in sorted((SAMPLES / "legit").glob("*.eml"))[:2]]
    cli.main(["analyze", "--json", *files])
    assert len(json.loads(capsys.readouterr().out)) == 2


def test_cli_missing_file(capsys):
    assert cli.main(["analyze", "does-not-exist.eml"]) == 3


def test_virustotal_flag_without_key(monkeypatch, capsys):
    monkeypatch.delenv("VT_API_KEY", raising=False)
    cli.main(["analyze", "--virustotal", str(SAMPLES / "legit" / "01_github_security_alert.eml")])
    assert "VT_API_KEY" in capsys.readouterr().err


class FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False


def test_virustotal_lookup_with_mocked_api():
    email = parse_email((SAMPLES / "phishing" / "04_amazon_invoice_attachment.eml").read_bytes())
    calls = []

    def opener(request, timeout=0):
        calls.append(request.full_url)
        assert request.headers["X-apikey"] == "test-key"
        body = {"data": {"attributes": {"last_analysis_stats": {"malicious": 12}}}}
        return FakeResponse(json.dumps(body).encode())

    findings = virustotal.lookup(email, "test-key", opener=opener)
    assert calls and calls[0].startswith("https://www.virustotal.com/api/v3/files/")
    assert findings[0].rule_id == "VT_FILE" and "12" in findings[0].explanation
