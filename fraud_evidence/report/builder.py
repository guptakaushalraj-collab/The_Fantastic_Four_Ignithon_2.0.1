"""Module 6 core: assemble the incident report.

Combines the Module 3 timeline, the Module 5 redacted evidence records and the
Module 4 flags into one structured report with five sections: executive
summary, timeline of events, evidence table, flags, and fraud attempt log.
The finished report is passed through the redactor once more, so no
identifier from the timeline or the flags reaches the report unredacted.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Iterable

from ..consistency import check_timeline
from ..redaction import Redactor
from ..timeline.builder import DEFAULT_TZ, TimelineBuilder, format_money, party_label

REPORT_VERSION = "1.0"

# Event types that belong in the fraud attempt log, with what each one means.
_ATTEMPT_ACTIONS = {
    "suspicious_message": ("Scam contact", "contacted"),
    "malicious_url": ("Phishing link sent", "link sent"),
    "suspicious_url": ("Suspicious link sent", "link sent"),
    "scammer_credit": ("Credit from suspect account", "received"),
    "fraud_attempt": ("Payment to suspect attempted", "failed"),
    "fraudulent_payment": ("Payment to suspect", "money lost"),
    "follow_up_message": ("Follow-up demand after loss", "contacted"),
}
_CHANNELS = {"sms": "SMS", "email": "email", "chat": "chat"}


def _snippet(text: str | None, limit: int = 100) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _fmt(ts: str | None) -> str | None:
    """"2024-03-12T10:15:00+05:30" -> "2024-03-12 10:15"; date-only values unchanged."""
    if not ts or len(ts) == 10:
        return ts
    try:
        return datetime.fromisoformat(ts).strftime("%Y-%m-%d %H:%M")
    except ValueError:
        return ts


def _ref_key(ref: Any) -> str | None:
    return re.sub(r"\s+", "", str(ref)).upper() if ref else None


class IncidentReportBuilder:
    """Build an incident report.

    ``redact`` (default on) runs a final redaction pass over the whole report.
    Turn it off only for a report that stays inside the investigating team.
    """

    def __init__(self, redactor: Redactor | None = None, redact: bool = True):
        self.redactor = redactor or Redactor()
        self.redact = redact

    def build(self, timeline: dict[str, Any], evidence: Iterable[dict[str, Any]] | None = None,
              flags: dict[str, Any] | None = None, case_id: str | None = None) -> dict[str, Any]:
        """``evidence`` should be the redacted Module 2 records; ``flags`` the Module 4 report.

        Missing flags are computed from the timeline. Without evidence records the
        evidence table is built from the timeline's events.
        """
        flags = flags if flags is not None else check_timeline(timeline)
        events = timeline.get("events", [])
        issues = flags.get("issues", [])
        evidence_rows = (self._evidence_from_records(list(evidence), events, issues)
                         if evidence is not None else self._evidence_from_events(events, issues))
        attempts = self._attempt_log(events)

        report = {
            "report_version": REPORT_VERSION,
            "case_id": case_id or timeline.get("case_id") or flags.get("case_id"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "timezone": timeline.get("timezone"),
            "redacted": self.redact,
            "executive_summary": self._executive_summary(timeline, flags, attempts, len(evidence_rows)),
            "timeline": [self._timeline_row(e) for e in events],
            "evidence": evidence_rows,
            "flags": {"summary": flags.get("summary", {}), "issues": [self._flag_row(i) for i in issues]},
            "fraud_attempt_log": attempts,
        }
        if not self.redact:
            return report
        # The timeline's parties tell the redactor which identifiers to look for in the text.
        context = [e.get("actors") for e in events]
        return self.redactor.redact({"report": report, "context": context}).document["report"]

    def build_from_records(self, records: Iterable[dict[str, Any]], case_id: str | None = None,
                           tz: str = DEFAULT_TZ) -> dict[str, Any]:
        """Run Modules 3-5 on Module 2 records, then build the report."""
        records = list(records)
        timeline = TimelineBuilder(tz).build(records, case_id=case_id)
        return self.build(timeline, self.redactor.redact(records).document, check_timeline(timeline),
                          case_id)

    # ------------------------------------------------------ executive summary

    def _executive_summary(self, timeline, flags, attempts, evidence_count) -> dict[str, Any]:
        s = timeline.get("summary", {})
        events = timeline.get("events", [])
        payments = [a for a in attempts if a["event_type"] == "fraudulent_payment"]
        failed = [a for a in attempts if a["event_type"] == "fraud_attempt"]
        contacts = [e for e in events if e["stage"] in ("contact", "lure", "follow_up")]
        messages = [e for e in contacts if e["event_type"] in ("suspicious_message", "follow_up_message")]
        links = [e for e in contacts if e.get("url")]
        loss, unique_payments = self._loss(payments)
        channels = sorted({_CHANNELS[p] for e in contacts
                           if (p := (e.get("details") or {}).get("platform")) in _CHANNELS})
        fsum = flags.get("summary", {})
        by_cat = fsum.get("by_category", {})
        high_flags = (fsum.get("by_severity") or {}).get("high", 0)

        if payments:
            assessment = "Fraud with financial loss"
        elif failed:
            assessment = "Attempted fraud, no confirmed loss"
        elif contacts:
            assessment = "Suspicious contact, no payment found"
        else:
            assessment = "No fraud indicators found"

        sentences = []
        if s.get("first_event_at"):
            first, last = _fmt(s["first_event_at"]), _fmt(s.get("last_event_at"))
            period = f"between {first} and {last}" if last != first else f"on {first}"
            sentences.append(f"The evidence ({evidence_count} item{'s' if evidence_count != 1 else ''}) "
                             f"covers events {period}.")
        if messages or links:
            parts = []
            if messages:
                parts.append(f"{len(messages)} suspicious message{'s' if len(messages) != 1 else ''}"
                             + (f" by {' and '.join(channels)}" if channels else ""))
            if links:
                parts.append(f"{len(links)} malicious or suspicious link{'s' if len(links) != 1 else ''}")
            sentences.append(f"The victim received {' and '.join(parts)}.")
        if s.get("attack_chain") and (contacts or payments or failed):
            sentences.append(f"The attack followed this sequence: {s['attack_chain']}.")
        if payments:
            total = ", ".join(format_money(v, c) for c, v in loss.items()) or "an unknown amount"
            sentences.append(
                (f"1 fraudulent payment of {total} was made" if unique_payments == 1 else
                 f"{unique_payments} fraudulent payments totalling {total} were made")
                + (f" (recorded in {len(payments)} documents)" if len(payments) > unique_payments else "")
                + (f", the first {s['time_to_first_loss']} after first contact" if s.get("time_to_first_loss")
                   else "") + ".")
        if failed:
            sentences.append(f"{len(failed)} further payment attempt{'s' if len(failed) != 1 else ''} "
                             "to the suspects failed.")
        if s.get("suspect_identifiers"):
            n = len(s["suspect_identifiers"])
            sentences.append(f"{n} suspect identifier{'s were' if n != 1 else ' was'} found "
                             "(redacted in this report)." if self.redact else
                             f"Suspect identifiers: {', '.join(s['suspect_identifiers'])}.")
        if fsum.get("issue_count"):
            sentences.append(
                f"Review found {by_cat.get('gap', 0)} gap(s) and {by_cat.get('contradiction', 0)} "
                f"contradiction(s) in the evidence"
                + (f", {high_flags} of them high severity" if high_flags else "")
                + "; see the flags section before filing.")
        elif events:
            sentences.append("No gaps or contradictions were found in the evidence.")

        return {
            "assessment": assessment,
            "text": " ".join(sentences) or "No evidence was provided.",
            "key_facts": {
                "evidence_count": evidence_count,
                "event_count": len(events),
                "first_event_at": s.get("first_event_at"),
                "last_event_at": s.get("last_event_at"),
                "first_contact_at": next((e["timestamp"] for e in contacts if e.get("timestamp")), None),
                "first_loss_at": next((a["timestamp"] for a in payments if a.get("timestamp")), None),
                "attack_chain": s.get("attack_chain"),
                "contact_channels": channels,
                "fraudulent_payment_count": unique_payments,
                "failed_attempt_count": len(failed),
                "total_loss": loss,
                "suspect_identifier_count": len(s.get("suspect_identifiers", [])),
                "highest_severity": s.get("highest_severity"),
                "flag_count": fsum.get("issue_count", 0),
                "high_severity_flag_count": high_flags,
            },
        }

    @staticmethod
    def _loss(payments: list[dict]) -> tuple[dict[str, float], int]:
        """Total per currency and payment count, counting a payment seen in several documents once."""
        seen: set[str] = set()
        loss: dict[str, float] = {}
        count = 0
        for p in payments:
            key = _ref_key(p.get("transaction_id"))
            if key and key in seen:
                continue
            if key:
                seen.add(key)
            count += 1
            if p.get("amount") is not None:
                cur = p.get("currency") or "INR"
                loss[cur] = round(loss.get(cur, 0) + p["amount"], 2)
        return loss, count

    # --------------------------------------------------------------- sections

    @staticmethod
    def _timeline_row(e: dict) -> dict[str, Any]:
        return {
            "sequence": e["sequence"],
            "timestamp": e.get("timestamp"),
            "time_precision": e.get("time_precision"),
            "since_previous": e.get("since_previous"),
            "stage": e["stage"],
            "event_type": e["event_type"],
            "severity": e["severity"],
            "title": e["title"],
            "description": e["description"],
            "evidence_id": e.get("evidence_id"),
        }

    @staticmethod
    def _flag_row(issue: dict) -> dict[str, Any]:
        return {k: issue.get(k) for k in ("issue_id", "category", "issue_type", "severity", "title",
                                          "description", "events", "evidence_ids", "suggestion")}

    @staticmethod
    def _cross_refs(evidence_id, events, issues) -> dict[str, list]:
        return {
            "events": [e["sequence"] for e in events if e.get("evidence_id") == evidence_id],
            "flags": [i["issue_id"] for i in issues if evidence_id in (i.get("evidence_ids") or [])],
        }

    def _evidence_from_records(self, records, events, issues) -> list[dict[str, Any]]:
        rows = []
        for r in records:
            message = r.get("message") or {}
            txn = r.get("transaction") or {}
            if r.get("transactions"):
                n = len(r["transactions"])
                summary = (f"{n} transaction{'s' if n != 1 else ''}" if n > 1 else
                           f"{(txn.get('direction') or 'debit').capitalize()} of "
                           f"{format_money(txn.get('amount'), txn.get('currency'))}"
                           + (f", ref {txn['transaction_id']}" if txn.get("transaction_id") else ""))
            elif message:
                summary = ((f"Subject: {message['subject']}. " if message.get("subject") else "")
                           + f'"{_snippet(message.get("content"))}"')
            elif r.get("urls"):
                summary = "; ".join(f"{u['url']} ({u['verdict']}, score {u['score']})" for u in r["urls"])
            else:
                summary = ""
            # The timeline's time is zone-normalized and knows date-only values.
            first = next((e for e in events if e.get("evidence_id") == r.get("evidence_id")
                          and e.get("timestamp")), None)
            rows.append({
                "evidence_id": r.get("evidence_id"),
                "evidence_type": r.get("evidence_type"),
                "source": r.get("source"),
                "timestamp": first["timestamp"] if first else r.get("timestamp"),
                "sender": party_label(r.get("sender")),
                "receiver": party_label(r.get("receiver")),
                "summary": summary,
                "content_hash": r.get("content_hash"),
                "warnings": r.get("warnings", []),
                **self._cross_refs(r.get("evidence_id"), events, issues),
            })
        return rows

    def _evidence_from_events(self, events, issues) -> list[dict[str, Any]]:
        rows: dict[str, dict] = {}
        for e in events:
            ev_id = e.get("evidence_id")
            if ev_id in rows:
                continue
            actors = e.get("actors") or {}
            rows[ev_id] = {
                "evidence_id": ev_id,
                "evidence_type": e.get("evidence_type"),
                "source": None,
                "timestamp": e.get("timestamp"),
                "sender": party_label(actors.get("from")),
                "receiver": party_label(actors.get("to")),
                "summary": e["description"],
                "content_hash": None,
                "warnings": [],
                **self._cross_refs(ev_id, events, issues),
            }
        return list(rows.values())

    @staticmethod
    def _attempt_log(events: list[dict]) -> list[dict[str, Any]]:
        log = []
        for e in events:
            if e["event_type"] not in _ATTEMPT_ACTIONS:
                continue
            action, outcome = _ATTEMPT_ACTIONS[e["event_type"]]
            amount = e.get("amount") or {}
            details = e.get("details") or {}
            actors = e.get("actors") or {}
            counterparty = actors.get("from") if amount.get("direction") != "debit" else actors.get("to")
            log.append({
                "entry": len(log) + 1,
                "sequence": e["sequence"],
                "timestamp": e.get("timestamp"),
                "event_type": e["event_type"],
                "action": action,
                "channel": _CHANNELS.get(details.get("platform")) or (
                    details.get("payment_method") or ("URL" if e.get("url") else None)),
                "counterparty": party_label(counterparty),
                "amount": amount.get("value"),
                "currency": amount.get("currency") or ("INR" if amount.get("value") is not None else None),
                "transaction_id": details.get("transaction_id"),
                "url": e.get("url"),
                "outcome": outcome,
                "severity": e["severity"],
                "evidence_id": e.get("evidence_id"),
                "linked_evidence": e.get("linked_evidence", []),
            })
        return log


def build_report(timeline: dict[str, Any], evidence: Iterable[dict[str, Any]] | None = None,
                 flags: dict[str, Any] | None = None, case_id: str | None = None,
                 redact: bool = True) -> dict[str, Any]:
    return IncidentReportBuilder(redact=redact).build(timeline, evidence, flags, case_id)
