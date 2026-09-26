"""Human-readable renderings of a consistency report."""

from __future__ import annotations

from typing import Any

_MARKERS = {"low": "·", "medium": "!", "high": "!!"}


def _events(issue: dict[str, Any]) -> str:
    return ", ".join(f"#{n}" for n in issue["events"]) or "case"


def render_text(report: dict[str, Any]) -> str:
    s = report["summary"]
    lines = [
        f"Gaps & contradictions{' — case ' + report['case_id'] if report.get('case_id') else ''}",
        f"{s['issue_count']} issue(s) in {s['events_checked']} event(s): "
        + ", ".join(f"{n} {c}" for c, n in s["by_category"].items() if n)
        if s["issue_count"] else f"No issues found in {s['events_checked']} event(s).",
        "",
    ]
    for i in report["issues"]:
        lines.append(f"{i['issue_id']} {_MARKERS[i['severity']]:<2} [{i['category']}] "
                     f"{i['title']}  (events {_events(i)})")
        lines.append(f"     {i['description']}")
        if i.get("suggestion"):
            lines.append(f"     → {i['suggestion']}")
    return "\n".join(lines).rstrip()


def render_markdown(report: dict[str, Any]) -> str:
    s = report["summary"]
    out = [
        f"# Gaps & contradictions{' — ' + report['case_id'] if report.get('case_id') else ''}",
        "",
        f"**Issues:** {s['issue_count']} "
        f"({', '.join(f'{n} {c}' for c, n in s['by_category'].items() if n) or 'none'})  ",
        f"**Highest severity:** {s['highest_severity'] or '—'}",
        "",
        "| ID | Severity | Category | Issue | Events | Details | Next step |",
        "|---|---|---|---|---|---|---|",
    ]
    for i in report["issues"]:
        cells = [i["issue_id"], i["severity"], i["category"], i["title"], _events(i),
                 i["description"], i.get("suggestion") or ""]
        out.append("| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |")
    return "\n".join(out)
