"""End-to-end: every sample email gets the expected verdict."""

import pytest

from phishcheck import analyze_file

from conftest import SAMPLES

PHISHING = sorted((SAMPLES / "phishing").glob("*.eml"))
LEGIT = sorted((SAMPLES / "legit").glob("*.eml"))


def test_samples_exist():
    assert len(PHISHING) >= 5
    assert len(LEGIT) >= 4


@pytest.mark.parametrize("path", PHISHING, ids=lambda p: p.name)
def test_phishing_samples_flagged(path):
    report = analyze_file(path)
    assert report.verdict == "Phishing", [f.rule_id for f in report.findings]
    assert report.score >= 60


@pytest.mark.parametrize("path", LEGIT, ids=lambda p: p.name)
def test_legit_samples_safe(path):
    report = analyze_file(path)
    assert report.verdict == "Safe", [(f.rule_id, f.evidence) for f in report.findings]
    assert report.score < 30


def test_every_finding_is_explained():
    for path in PHISHING + LEGIT:
        for finding in analyze_file(path).findings:
            assert finding.title and len(finding.explanation) > 40
            assert finding.category in {"headers", "links", "content", "attachments"}


def test_expected_signals_in_sbi_sample():
    ids = {f.rule_id for f in analyze_file(SAMPLES / "phishing" / "01_sbi_kyc_update.eml").findings}
    assert {"H_REPLYTO_MISMATCH", "H_SPF_FAIL", "H_DMARC_FAIL", "L_TEXT_HREF_MISMATCH",
            "L_LOOKALIKE", "C_INDIA_SCAM"} <= ids
