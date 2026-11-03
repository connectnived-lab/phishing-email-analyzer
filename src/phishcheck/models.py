"""Data classes shared by every check."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any


@dataclass
class Finding:
    """One thing the analyzer noticed about the email."""

    rule_id: str
    category: str  # headers | links | content | attachments
    title: str
    explanation: str  # written for a non-technical reader
    points: int
    evidence: list[str] = field(default_factory=list)

    @property
    def severity(self) -> str:
        if self.points >= 25:
            return "high"
        if self.points >= 10:
            return "medium"
        if self.points > 0:
            return "low"
        return "info"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["severity"] = self.severity
        return data


@dataclass
class Report:
    """Final result of analysing one email."""

    score: int
    verdict: str  # Safe | Suspicious | Phishing
    findings: list[Finding]
    summary: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "summary": self.summary,
            "findings": [f.to_dict() for f in self.findings],
        }
