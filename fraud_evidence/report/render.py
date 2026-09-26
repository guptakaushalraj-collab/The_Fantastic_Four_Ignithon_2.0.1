"""Human-readable renderings of an incident report."""

from __future__ import annotations

import json
import textwrap
from datetime import datetime
from pathlib import Path
from typing import Any

from ..timeline.builder import format_money

WIDTH = 100


def _when(ts: str | None, precision: str | None = None) -> str:
    if not ts:
        return "(no timestamp)"
    if precision == "date" or len(ts) == 10:
        return f"{ts} (date only)"
    try:
        return datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M:%S")
    except ValueError:
        return ts


def _money(amount, currency) -> str:
    return format_money(amount, currency) if amount is not None else "—"


def _loss(loss: dict[str, float]) -> str:
    return ", ".join(format_money(v, c) for c, v in loss.items()) or "none recorded"


def _cell(value: Any) -> str:
    if value in (None, "", []):
        return "—"
    if isinstance(value, list):
        value = ", ".join(map(str, value))
    return str(value).replace("|", "\\|").replace("\n", " ")


def _table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    out = ["| " + " | ".join(headers) + " |", "|" + "---|" * len(headers)]
    out += ["| " + " | ".join(_cell(c) for c in row) + " |" for row in rows]
    return out


def render_markdown(report: dict[str, Any]) -> str:
    es, facts = report["executive_summary"], report["executive_summary"]["key_facts"]
    out = [
        f"# Incident report{' — ' + report['case_id'] if report.get('case_id') else ''}",
        "",
        f"Generated {report['generated_at']} · times in {report.get('timezone') or 'source time'}"
        + (" · personal and financial identifiers are redacted" if report.get("redacted") else ""),
        "",
        "## 1. Executive summary",
        "",
        f"**Assessment:** {es['assessment']}",
        "",
        es["text"],
        "",
        *_table(["Fact", "Value"], [
            ["First contact", facts["first_contact_at"]],
            ["First loss", facts["first_loss_at"]],
            ["Attack chain", facts["attack_chain"]],
            ["Fraudulent payments", facts["fraudulent_payment_count"]],
            ["Failed attempts", facts["failed_attempt_count"]],
            ["Total loss", _loss(facts["total_loss"])],
            ["Suspect identifiers", facts["suspect_identifier_count"]],
            ["Flags (high severity)", f"{facts['flag_count']} ({facts['high_severity_flag_count']})"],
        ]),
        "",
        "## 2. Timeline of events",
        "",
        *_table(["#", "Time", "Stage", "Severity", "Event", "Details"], [
            [e["sequence"], _when(e["timestamp"], e["time_precision"]), e["stage"], e["severity"],
             e["title"], e["description"]] for e in report["timeline"]]),
        "",
        "## 3. Evidence",
        "",
        *_table(["Evidence", "Type", "Time", "From", "To", "Content", "Events", "Flags"], [
            [(r["evidence_id"] or "")[:12], r["evidence_type"], _when(r["timestamp"]), r["sender"],
             r["receiver"], r["summary"], [f"#{n}" for n in r["events"]], r["flags"]]
            for r in report["evidence"]]),
        "",
        "## 4. Flags: missing and contradictory information",
        "",
    ]
    issues = report["flags"]["issues"]
    if issues:
        out += _table(["ID", "Severity", "Category", "Issue", "Events", "Next step"], [
            [i["issue_id"], i["severity"], i["category"], f"{i['title']}. {i['description']}",
             [f"#{n}" for n in i["events"]], i["suggestion"]] for i in issues])
    else:
        out.append("No gaps or contradictions found.")
    out += ["", "## 5. Fraud attempt log", ""]
    if report["fraud_attempt_log"]:
        out += _table(["#", "Time", "Action", "Channel", "Counterparty", "Amount", "Reference", "Outcome"], [
            [a["entry"], _when(a["timestamp"]), a["action"], a["channel"], a["counterparty"],
             _money(a["amount"], a["currency"]), a["transaction_id"] or a["url"], a["outcome"]]
            for a in report["fraud_attempt_log"]])
    else:
        out.append("No fraud attempts recorded.")
    return "\n".join(out)


def _wrap(text: str, indent: str = "    ", width: int = WIDTH) -> list[str]:
    return textwrap.wrap(text or "", width=width, initial_indent=indent, subsequent_indent=indent) or [indent]


def _heading(title: str) -> list[str]:
    return ["", title, "-" * len(title)]


def render_text(report: dict[str, Any]) -> str:
    """A plain-text report with every section in full, for reading, printing or email."""
    es, facts = report["executive_summary"], report["executive_summary"]["key_facts"]
    title = f"INCIDENT REPORT{' — ' + report['case_id'] if report.get('case_id') else ''}"
    lines = [
        "=" * WIDTH, title, "=" * WIDTH,
        f"Generated: {report['generated_at']}",
        f"Times in:  {report.get('timezone') or 'source time'}",
    ]
    if report.get("redacted"):
        lines.append("Personal and financial identifiers are shown as [REDACTED].")

    lines += _heading("1. EXECUTIVE SUMMARY")
    lines += [f"Assessment: {es['assessment']}", ""]
    lines += _wrap(es["text"], indent="")
    lines.append("")
    for label, value in (
        ("First contact", _when(facts["first_contact_at"]) if facts["first_contact_at"] else "—"),
        ("First loss", _when(facts["first_loss_at"]) if facts["first_loss_at"] else "—"),
        ("Attack chain", facts["attack_chain"] or "—"),
        ("Contact channels", ", ".join(facts["contact_channels"]) or "—"),
        ("Fraudulent payments", facts["fraudulent_payment_count"]),
        ("Failed attempts", facts["failed_attempt_count"]),
        ("Total loss", _loss(facts["total_loss"])),
        ("Suspect identifiers", facts["suspect_identifier_count"]),
        ("Flags", f"{facts['flag_count']} ({facts['high_severity_flag_count']} high severity)"),
    ):
        lines += textwrap.wrap(f"{label + ':':<21}{value}", width=WIDTH, initial_indent="  ",
                               subsequent_indent=" " * 23)

    lines += _heading("2. TIMELINE OF EVENTS")
    for e in report["timeline"]:
        delta = f"  (+{e['since_previous']})" if e.get("since_previous") else ""
        lines.append(f"{e['sequence']:>3}. {_when(e['timestamp'], e['time_precision'])}{delta}"
                     f"  [{e['stage']}, {e['severity']}]")
        lines += _wrap(e["title"], indent="     ")
        lines += _wrap(e["description"], indent="       ")
    if not report["timeline"]:
        lines.append("No events.")

    lines += _heading("3. EVIDENCE")
    for n, r in enumerate(report["evidence"], start=1):
        lines.append(f"{n:>3}. {r['evidence_type']} {r['evidence_id'] or ''}".rstrip())
        for label, value in (
            ("Time", _when(r["timestamp"]) if r["timestamp"] else None),
            ("Source", r.get("source")),
            ("From", r["sender"]), ("To", r["receiver"]),
            ("Events", ", ".join(f"#{x}" for x in r["events"])),
            ("Flags", ", ".join(r["flags"])),
            ("Hash", r.get("content_hash")),
        ):
            if value:
                lines.append(f"     {label + ':':<8}{value}")
        lines += _wrap(r["summary"], indent="     ")
        for warning in r.get("warnings") or []:
            lines += _wrap(f"Warning: {warning}", indent="     ")
    if not report["evidence"]:
        lines.append("No evidence.")

    lines += _heading("4. FLAGS: MISSING AND CONTRADICTORY INFORMATION")
    for i in report["flags"]["issues"]:
        events = ", ".join(f"#{x}" for x in i["events"]) or "whole case"
        lines.append(f"{i['issue_id']}  [{i['severity']}, {i['category']}]  events {events}")
        lines += _wrap(i["title"], indent="    ")
        lines += _wrap(i["description"], indent="    ")
        if i.get("suggestion"):
            lines += _wrap(f"Next step: {i['suggestion']}", indent="    ")
    if not report["flags"]["issues"]:
        lines.append("No gaps or contradictions found.")

    lines += _heading("5. FRAUD ATTEMPT LOG")
    for a in report["fraud_attempt_log"]:
        lines.append(f"{a['entry']:>3}. {_when(a['timestamp'])}  {a['action']}  -> {a['outcome']}")
        details = [
            f"channel {a['channel']}" if a["channel"] else None,
            f"counterparty {a['counterparty']}" if a["counterparty"] else None,
            f"amount {_money(a['amount'], a['currency'])}" if a["amount"] is not None else None,
            f"ref {a['transaction_id']}" if a["transaction_id"] else None,
            a["url"],
        ]
        lines += _wrap(", ".join(d for d in details if d), indent="     ")
    if not report["fraud_attempt_log"]:
        lines.append("No fraud attempts recorded.")

    lines += ["", "=" * WIDTH, "End of report", "=" * WIDTH]
    return "\n".join(line.rstrip() for line in lines)


_RENDERERS = {"json": ("json", lambda r: json.dumps(r, ensure_ascii=False, indent=2, default=str)),
              "text": ("txt", render_text),
              "markdown": ("md", render_markdown)}


def save_report(report: dict[str, Any], path: str | Path,
                formats: tuple[str, ...] = ("json", "text")) -> dict[str, Path]:
    """Write the report in each format next to each other: ``path`` plus .json/.txt/.md.

    Returns the written paths by format, e.g. ``{"json": ..report.json, "text": ..report.txt}``.
    """
    base = Path(path)
    if base.suffix in (".json", ".txt", ".md"):
        base = base.with_suffix("")
    base.parent.mkdir(parents=True, exist_ok=True)
    written = {}
    for fmt in formats:
        suffix, render = _RENDERERS[fmt]
        target = base.with_name(f"{base.name}.{suffix}")
        target.write_text(render(report) + "\n", encoding="utf-8")
        written[fmt] = target
    return written
