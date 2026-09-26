"""Module 3 — Chronological Timeline.

Takes extracted evidence records from Module 2, sorts them by timestamp and
builds the chain of fraud events (suspicious message → malicious URL →
transaction → fraud), returned as an ordered list of timestamped events
with descriptions plus a case summary.
"""

from .builder import DEFAULT_TZ, TimelineBuilder, TimelineEvent, build_timeline
from .indicators import find_indicators, is_suspicious
from .render import render_markdown, render_text

__all__ = [
    "DEFAULT_TZ",
    "TimelineBuilder",
    "TimelineEvent",
    "build_timeline",
    "find_indicators",
    "is_suspicious",
    "render_markdown",
    "render_text",
]
