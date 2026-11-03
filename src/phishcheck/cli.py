"""Command line interface: ``phishcheck analyze email.eml``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analyzer import analyze_parsed, score_findings
from .parser import parse_email
from .report import render

EXIT_CODES = {"Safe": 0, "Suspicious": 1, "Phishing": 2}


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="phishcheck", description="Offline phishing email analyzer.")
    parser.add_argument("--version", action="version", version=f"phishcheck {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)
    analyze = sub.add_parser("analyze", help="analyze one or more .eml files ('-' reads stdin)")
    analyze.add_argument("files", nargs="+", help="path to .eml / .txt file, or - for stdin")
    analyze.add_argument("--json", action="store_true", help="print machine-readable JSON")
    analyze.add_argument("--no-color", action="store_true", help="disable coloured output")
    analyze.add_argument("--virustotal", action="store_true",
                         help="also look up attachment hashes and links on VirusTotal (needs VT_API_KEY)")
    return parser


def _read(path: str) -> bytes:
    return sys.stdin.buffer.read() if path == "-" else Path(path).read_bytes()


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    results = []
    worst = 0
    for path in args.files:
        try:
            email = parse_email(_read(path))
        except OSError as exc:
            print(f"phishcheck: cannot read {path}: {exc.strerror}", file=sys.stderr)
            return 3
        report = analyze_parsed(email)
        if args.virustotal:
            from . import virustotal
            key = virustotal.api_key()
            if not key:
                print("phishcheck: --virustotal needs the VT_API_KEY environment variable", file=sys.stderr)
            else:
                try:
                    report.findings.extend(virustotal.lookup(email, key))
                    report.score, report.verdict = score_findings(report.findings)
                except Exception as exc:  # network problems must not hide the offline result
                    print(f"phishcheck: VirusTotal lookup failed: {exc}", file=sys.stderr)
        worst = max(worst, EXIT_CODES[report.verdict])
        results.append((path, report))

    if args.json:
        payload = [dict(file=p, **r.to_dict()) for p, r in results]
        print(json.dumps(payload[0] if len(payload) == 1 else payload, indent=2, ensure_ascii=False))
    else:
        for path, report in results:
            if len(results) > 1:
                print(f"== {path}")
            print(render(report, color=False if args.no_color else None))
    return worst


if __name__ == "__main__":
    sys.exit(main())
