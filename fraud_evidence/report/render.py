"""Human-readable renderings of an incident report."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from ..timeline.builder import format_money


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


def render_text(report: dict[str, Any]) -> str:
    es, facts = report["executive_summary"], report["executive_summary"]["key_facts"]
    lines = [
        f"INCIDENT REPORT{' — ' + report['case_id'] if report.get('case_id') else ''}",
        f"Assessment: {es['assessment']}   Total loss: {_loss(facts['total_loss'])}",
        "",
        "EXECUTIVE SUMMARY",
        es["text"],
        "",
        "TIMELINE",
        *(f"{e['sequence']:>3}. {_when(e['timestamp'], e['time_precision'])}  [{e['stage']}] {e['title']}"
          for e in report["timeline"]),
        "",
        "EVIDENCE",
        *(f"  {(r['evidence_id'] or '')[:12]}  {r['evidence_type']:<11} {r['summary']}"
          for r in report["evidence"]),
        "",
        "FLAGS",
        *(f"  {i['issue_id']} [{i['severity']}] {i['title']}" for i in report["flags"]["issues"]),
        *([] if report["flags"]["issues"] else ["  none"]),
        "",
        "FRAUD ATTEMPT LOG",
        *(f"{a['entry']:>3}. {_when(a['timestamp'])}  {a['action']}"
          + (f" — {_money(a['amount'], a['currency'])}" if a["amount"] is not None else "")
          + f"  → {a['outcome']}" for a in report["fraud_attempt_log"]),
        *([] if report["fraud_attempt_log"] else ["  none"]),
    ]
    return "\n".join(lines)
