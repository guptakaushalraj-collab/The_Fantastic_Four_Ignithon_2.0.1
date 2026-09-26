"""Module 6 — Incident Report Generation.

Combines the timeline (Module 3), the redacted evidence (Module 5) and the
flags (Module 4) into a structured incident report: executive summary,
timeline of events, evidence table, flags for missing or contradictory
information, and the final fraud attempt log. Rendered as JSON, Markdown or text.
"""

from .builder import REPORT_VERSION, IncidentReportBuilder, build_report
from .render import render_markdown, render_text

__all__ = ["REPORT_VERSION", "IncidentReportBuilder", "build_report", "render_markdown", "render_text"]
