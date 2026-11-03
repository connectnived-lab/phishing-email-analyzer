"""phishcheck - offline phishing email analyzer."""

from .analyzer import analyze_bytes, analyze_file, analyze_text
from .models import Finding, Report

__all__ = ["analyze_bytes", "analyze_file", "analyze_text", "Finding", "Report"]
__version__ = "1.0.0"
