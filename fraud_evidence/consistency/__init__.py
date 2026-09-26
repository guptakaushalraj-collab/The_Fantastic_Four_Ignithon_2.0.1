"""Module 4 — Gap & Contradiction Detection.

Takes a Module 3 timeline and returns a list of flagged issues: gaps
(missing timestamps, amounts, UTRs, payee or sender identifiers) and
contradictions (the same transaction reported with different amounts or
payees, a payment that differs from the amount requested, one sender name
behind several identifiers, a payment dated before the contact that caused it).
"""

from .detector import ConsistencyChecker, Issue, check_timeline
from .render import render_markdown, render_text

__all__ = [
    "ConsistencyChecker",
    "Issue",
    "check_timeline",
    "render_markdown",
    "render_text",
]
