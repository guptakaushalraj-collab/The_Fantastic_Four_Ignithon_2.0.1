"""Human-readable renderings of a timeline document."""

from __future__ import annotations

from datetime import datetime
from typing import Any

_MARKERS = {"info": " ", "low": "·", "medium": "!", "high": "!!", "critical": "!!!"}


def _when(event: dict[str, Any]) -> str:
    ts = event["timestamp"]
    if ts is None:
        return "(no timestamp)"
    if event["time_precision"] == "date":
        return f"{ts} (date only)"
    return datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M:%S")


def render_text(timeline: dict[str, Any]) -> str:
    s = timeline["summary"]
    lines = [
        f"Fraud timeline{' — case ' + timeline['case_id'] if timeline.get('case_id') else ''}"
        f" (times in {timeline['timezone']})",
        f"Attack chain: {s['attack_chain'] or 'no suspicious activity found'}",
    ]
    if s["total_loss"]:
        lines.append("Total loss: " + ", ".join(f"{c} {v:,.2f}" for c, v in s["total_loss"].items())
                     + (f" (first loss {s['time_to_first_loss']} after first contact)"
                        if s["time_to_first_loss"] else ""))
    if s["suspect_identifiers"]:
        lines.append("Suspect identifiers: " + ", ".join(s["suspect_identifiers"]))
    lines.append("")

    for e in timeline["events"]:
        delta = f"  (+{e['since_previous']})" if e.get("since_previous") else ""
        lines.append(f"{e['sequence']:>3}. {_when(e)}{delta}  [{e['stage']}] "
                     f"{_MARKERS[e['severity']]} {e['title']}".rstrip())
        lines.append(f"     {e['description']}")
    return "\n".join(lines)


def render_markdown(timeline: dict[str, Any]) -> str:
    s = timeline["summary"]
    out = [
        f"# Fraud timeline{' — ' + timeline['case_id'] if timeline.get('case_id') else ''}",
        "",
        f"**Attack chain:** {s['attack_chain'] or 'no suspicious activity found'}  ",
        f"**Period:** {s['first_event_at'] or '—'} → {s['last_event_at'] or '—'}"
        + (f" ({s['duration']})" if s["duration"] else "") + "  ",
        f"**Total loss:** " + (", ".join(f"{c} {v:,.2f}" for c, v in s["total_loss"].items())
                               or "none recorded"),
        "",
        f"| # | Time ({timeline['timezone']}) | Stage | Severity | Event | Details |",
        "|---|---|---|---|---|---|",
    ]
    for e in timeline["events"]:
        cells = [str(e["sequence"]), _when(e), e["stage"], e["severity"], e["title"], e["description"]]
        out.append("| " + " | ".join(c.replace("|", "\\|") for c in cells) + " |")
    return "\n".join(out)
