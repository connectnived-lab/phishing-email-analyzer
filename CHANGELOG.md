# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [1.0.0] - 2026-11-03

### Added
- Python package `phishcheck` with a `phishcheck analyze` command (text and `--json` output, stdin, several files, exit codes per verdict).
- Header checks: Reply-To / Return-Path mismatch, display-name spoofing, brand names on free-mail and unrelated domains, look-alike sender domains, SPF / DKIM / DMARC from the top-most `Authentication-Results`, Message-ID domain, `Received` hop parsing.
- Link checks: text vs. real destination, IP-address URLs, shorteners, punycode and homoglyph domains, look-alike brand domains (Indian banks, Paytm, PhonePe, Amazon, Microsoft and others), suspicious TLDs, `@` in URLs, long sub-domain chains, plain http.
- Wording checks: urgency, credential/OTP requests, Indian scam phrases (KYC, blocked account, PAN/Aadhaar, refunds), prize lures, "Enable Content" instructions, generic greetings.
- Attachment checks: executable/script types, double extensions, macro-enabled and VBA-containing Office files, HTML attachments, archives.
- Weighted 0-100 score with Safe / Suspicious / Phishing verdicts and a plain-English explanation for every finding.
- Optional VirusTotal lookups (`--virustotal`, needs `VT_API_KEY`), off by default.
- Browser-only web demo with the same rules ported to JavaScript, sample buttons, .eml upload / drag-and-drop and a score gauge.
- 12 sample emails (6 phishing, 6 legitimate) and a pytest suite, including a Python/JavaScript parity test.
