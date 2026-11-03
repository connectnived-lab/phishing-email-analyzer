"""Human-readable console output."""

from __future__ import annotations

import os
import sys
import textwrap

from .models import Report

COLORS = {"Safe": "32", "Suspicious": "33", "Phishing": "31",
          "high": "31", "medium": "33", "low": "36", "info": "90"}


def _use_color(stream) -> bool:
    return hasattr(stream, "isatty") and stream.isatty() and not os.environ.get("NO_COLOR")


def render(report: Report, color: bool | None = None, stream=sys.stdout) -> str:
    color = _use_color(stream) if color is None else color

    def paint(text: str, key: str) -> str:
        return f"\033[{COLORS[key]}m{text}\033[0m" if color else text

    s = report.summary
    lines = [
        "",
        f"  Verdict : {paint(report.verdict.upper(), report.verdict)}   (risk score {report.score}/100)",
        f"  Subject : {s.get('subject') or '-'}",
        f"  From    : {s.get('from') or '-'}",
    ]
    auth = s.get("authentication") or {}
    if auth:
        lines.append("  Auth    : " + "  ".join(f"{k.upper()}={v}" for k, v in auth.items()))
    hops = s.get("hops") or []
    if hops:
        origin = hops[0]
        lines.append(f"  Route   : {len(hops)} hop(s), first server {origin['from'] or '?'} {origin['ip'] and '[' + origin['ip'] + ']'}")
    lines.append(f"  Links   : {s.get('links', 0)}    Attachments: {', '.join(s.get('attachments') or []) or 'none'}")
    lines.append("")

    scored = [f for f in report.findings if f.points > 0]
    info = [f for f in report.findings if f.points == 0]
    if not scored:
        lines.append("  No warning signs found.")
    for f in scored:
        tag = paint(f"[{f.severity.upper():6}]", f.severity)
        lines.append(f"  {tag} +{f.points:<3} {f.title}")
        for chunk in textwrap.wrap(f.explanation, 74):
            lines.append(f"                 {chunk}")
        for ev in f.evidence[:3]:
            lines.append(f"                 > {ev}")
        lines.append("")
    for f in info:
        lines.append(f"  {paint('[INFO  ]', 'info')}      {f.title}")
    lines.append("")
    return "\n".join(lines)
