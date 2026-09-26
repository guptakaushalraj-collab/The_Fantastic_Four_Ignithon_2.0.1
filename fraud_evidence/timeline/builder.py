"""Module 3 core: turn extracted evidence records into an ordered fraud timeline.

Each Module 2 record becomes one or more events (a message that carries a
phishing link yields a *suspicious message* event and a *malicious URL*
event; a bank statement yields one event per transaction). Events are then
linked, so a payment to a UPI ID that a scammer sent earlier is marked as
a fraudulent payment. Finally they are sorted into the attack chain, for
example: suspicious message → malicious URL → transaction → fraud.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, time, timedelta, timezone, tzinfo
from typing import Any, Iterable
from zoneinfo import ZoneInfo

from .indicators import find_indicators, is_suspicious

DEFAULT_TZ = "Asia/Kolkata"

# Order of the fraud kill chain; also breaks ties between same-time events.
STAGE_ORDER = {
    "communication": 0, "contact": 1, "lure": 2, "transaction": 3, "fraud": 4, "follow_up": 5,
}
EVENT_LABELS = {
    "message": "message",
    "suspicious_message": "suspicious message",
    "follow_up_message": "follow-up message",
    "malicious_url": "malicious URL",
    "suspicious_url": "suspicious URL",
    "url": "URL",
    "transaction": "transaction",
    "failed_transaction": "failed transaction",
    "scammer_credit": "credit from suspect",
    "fraudulent_payment": "fraudulent payment",
    "fraud_attempt": "fraud attempt",
}
_SEVERITY = {
    "message": "info", "url": "info", "transaction": "low", "failed_transaction": "low",
    "suspicious_message": "medium", "suspicious_url": "medium", "scammer_credit": "medium",
    "malicious_url": "high", "follow_up_message": "high", "fraud_attempt": "high",
    "fraudulent_payment": "critical",
}
# Timestamps from these sources carry a real time of day; others at exactly
# midnight were most likely date-only values (bank statements, "on 12-03-24").
_PRECISE_SOURCES = {"header", "chat_export", "metadata"}
_BAD_VERDICTS = {"malicious", "suspicious"}


@dataclass
class TimelineEvent:
    event_type: str
    stage: str
    title: str
    description: str
    evidence_id: str | None
    evidence_type: str
    timestamp: str | None = None
    time_precision: str = "unknown"  # "datetime" | "date" | "unknown"
    severity: str = "info"
    actors: dict[str, Any] = field(default_factory=dict)
    amount: dict[str, Any] | None = None
    url: str | None = None
    indicators: list[str] = field(default_factory=list)
    linked_evidence: list[str] = field(default_factory=list)
    details: dict[str, Any] = field(default_factory=dict)
    sequence: int = 0
    since_previous: str | None = None
    # Sorting helpers, not serialized.
    _dt: datetime | None = field(default=None, repr=False)
    _order: int = field(default=0, repr=False)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.pop("_dt")
        data.pop("_order")
        return data


# --------------------------------------------------------------- formatting

def format_money(amount: float | None, currency: str | None) -> str:
    if amount is None:
        return "an unknown amount"
    if (currency or "INR") == "INR":
        return f"₹{amount:,.2f}"
    return f"{currency} {amount:,.2f}"


def party_label(party: dict | None) -> str | None:
    if not party:
        return None
    name, ident = party.get("name"), party.get("identifier")
    if name and ident:
        return f"{name} <{ident}>"
    return name or ident or party.get("raw")


def humanize_delta(delta: timedelta) -> str:
    seconds = int(delta.total_seconds())
    if seconds < 0:
        return "-" + humanize_delta(-delta)
    days, rem = divmod(seconds, 86400)
    hours, rem = divmod(rem, 3600)
    minutes, secs = divmod(rem, 60)
    parts = [f"{v}{u}" for v, u in ((days, "d"), (hours, "h"), (minutes, "m")) if v]
    return " ".join(parts) or f"{secs}s"


def _cap(text: str) -> str:
    """Uppercase the first letter only (``str.capitalize`` would lowercase 'UPI', 'XX1234')."""
    return text[:1].upper() + text[1:]


def _snippet(text: str, limit: int = 80) -> str:
    text = " ".join((text or "").split())
    return text if len(text) <= limit else text[: limit - 1].rstrip() + "…"


def _identifiers(party: dict | None) -> set[str]:
    if not party or not party.get("identifier"):
        return set()
    return {party["identifier"].lower()}


# ------------------------------------------------------------------ builder

class TimelineBuilder:
    """Build a chronological fraud timeline from Module 2 extracted records.

    ``tz`` is the zone assumed for timestamps without an offset (chat exports
    and bank statements are in local time) and the zone used for display.
    """

    def __init__(self, tz: str | tzinfo = DEFAULT_TZ):
        self.tz = ZoneInfo(tz) if isinstance(tz, str) else tz

    def build(self, records: Iterable[dict[str, Any]], case_id: str | None = None) -> dict[str, Any]:
        records = list(records)
        events: list[TimelineEvent] = []
        for record in records:
            events.extend(self._events_for(record))
        for i, event in enumerate(events):
            event._order = i

        self._link_transactions(events)
        events = self._sort(events)
        self._mark_follow_ups(events)

        # Gaps are only meaningful between events with a real time of day.
        previous = None
        for seq, event in enumerate(events, start=1):
            event.sequence = seq
            if event.time_precision == "datetime":
                if previous is not None:
                    event.since_previous = humanize_delta(event._dt - previous)
                previous = event._dt

        return {
            "case_id": case_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "timezone": str(self.tz),
            "summary": self._summary(events, len(records)),
            "events": [e.to_dict() for e in events],
        }

    # ------------------------------------------------------- event creation

    def _resolve_time(self, value: str | None, source: str | None):
        """Return (aware datetime, precision) for an ISO timestamp string."""
        if not value:
            return None, "unknown"
        try:
            dt = datetime.fromisoformat(value)
        except ValueError:
            return None, "unknown"
        precision = "datetime"
        if dt.tzinfo is None:
            if dt.time() == time(0) and source not in _PRECISE_SOURCES:
                precision = "date"
            dt = dt.replace(tzinfo=self.tz)
        return dt.astimezone(self.tz), precision

    def _new_event(self, record, ts_value, ts_source, **kwargs) -> TimelineEvent:
        dt, precision = self._resolve_time(ts_value, ts_source)
        event = TimelineEvent(
            evidence_id=record.get("evidence_id"),
            evidence_type=record.get("evidence_type", "message"),
            timestamp=(dt.date().isoformat() if precision == "date" else dt.isoformat())
            if dt else None,
            time_precision=precision,
            **kwargs,
        )
        event.severity = _SEVERITY.get(event.event_type, "info")
        event._dt = dt
        return event

    def _events_for(self, record: dict[str, Any]) -> list[TimelineEvent]:
        kind = record.get("evidence_type")
        ts_source = (record.get("field_sources") or {}).get("timestamp")
        if record.get("transactions"):
            return self._transaction_events(record, ts_source)
        if kind == "url":
            return [self._url_event(record, url, record.get("timestamp"), ts_source, None)
                    for url in record.get("urls", [])]
        if record.get("message") is not None:
            return self._message_events(record, ts_source)
        return []

    def _message_events(self, record, ts_source) -> list[TimelineEvent]:
        message = record["message"]
        content = message.get("content", "")
        indicators = find_indicators(f"{message.get('subject') or ''}\n{content}")
        bad_urls = [u for u in record.get("urls", []) if u.get("verdict") in _BAD_VERDICTS]
        suspicious = is_suspicious(indicators, has_bad_url=bool(bad_urls))

        sender, receiver = record.get("sender"), record.get("receiver")
        channel = {"sms": "SMS", "email": "Email", "chat": "Chat message"}.get(
            message.get("platform"),
            "Screenshot" if record.get("evidence_type") == "screenshot" else "Message",
        )
        who = party_label(sender)
        lowered = channel if channel.isupper() else channel.lower()
        title = f"{'Suspicious ' + lowered if suspicious else channel}" + (
            f" from {who}" if who else " received"
        )
        description = f'"{_snippet(content)}"'
        if message.get("subject"):
            description = f"Subject: {message['subject']}. " + description
        if indicators:
            description += " — indicators: " + ", ".join(i.replace("_", " ") for i in indicators)

        events = [self._new_event(
            record, record.get("timestamp"), ts_source,
            event_type="suspicious_message" if suspicious else "message",
            stage="contact" if suspicious else "communication",
            title=title,
            description=description,
            actors={"from": sender, "to": receiver},
            indicators=indicators,
            details={
                "platform": message.get("platform"),
                "contacts": record.get("contacts", {}),
                "amounts_mentioned": message.get("amounts_mentioned", []),
            },
        )]
        for url in bad_urls:
            events.append(self._url_event(record, url, record.get("timestamp"), ts_source, sender))
        return events

    def _url_event(self, record, url: dict, ts, ts_source, sender) -> TimelineEvent:
        verdict = url.get("verdict", "benign")
        event_type = {"malicious": "malicious_url", "suspicious": "suspicious_url"}.get(verdict, "url")
        reasons = [s["name"].replace("_", " ") for s in url.get("signals", []) if s["weight"] > 0]
        shared = f" shared by {party_label(sender)}" if party_label(sender) else ""
        return self._new_event(
            record, ts, ts_source,
            event_type=event_type,
            stage="lure" if event_type != "url" else "communication",
            title=f"{_cap(EVENT_LABELS[event_type])}{shared}: {url['domain']}",
            description=f"{url['url']} (reputation score {url['score']}/100"
                        + (f": {', '.join(reasons[:4])}" if reasons else "") + ")",
            actors={"from": sender},
            url=url["url"],
            details={"score": url["score"], "verdict": verdict, "domain": url["domain"]},
        )

    def _transaction_events(self, record, ts_source) -> list[TimelineEvent]:
        events = []
        for txn in record["transactions"]:
            status = (txn.get("status") or "").lower()
            failed = status in {"failed", "declined", "rejected", "reversed", "cancelled"}
            direction = txn.get("direction") or "debit"
            money = format_money(txn.get("amount"), txn.get("currency"))
            sender, receiver = party_label(txn.get("sender")), party_label(txn.get("receiver"))

            if direction == "credit":
                title = f"Credit of {money}" + (f" from {sender}" if sender else "")
            else:
                title = f"Debit of {money}" + (f" to {receiver}" if receiver else "")
            parts = []
            if sender and direction != "credit":
                parts.append(f"from {sender}")
            if receiver and direction == "credit":
                parts.append(f"to {receiver}")
            if txn.get("payment_method"):
                parts.append(f"via {txn['payment_method']}")
            if txn.get("transaction_id"):
                parts.append(f"ref {txn['transaction_id']}")
            if status:
                parts.append(f"status {status}")

            events.append(self._new_event(
                record, txn.get("timestamp"), ts_source,
                event_type="failed_transaction" if failed else "transaction",
                stage="transaction",
                title=title,
                description=_cap(" ".join(parts) or "transaction"),
                actors={"from": txn.get("sender"), "to": txn.get("receiver")},
                amount={"value": txn.get("amount"), "currency": txn.get("currency"),
                        "direction": direction},
                details={k: txn.get(k) for k in ("transaction_id", "payment_method", "status")},
            ))
        return events

    # ------------------------------------------------------------- linking

    def _link_transactions(self, events: list[TimelineEvent]) -> None:
        """Mark payments whose counterparty was named by suspicious contact as fraud."""
        suspects: dict[str, set[str]] = {}
        for event in events:
            if event.stage not in ("contact", "lure"):
                continue
            ids = _identifiers(event.actors.get("from"))
            contacts = event.details.get("contacts") or {}
            for key in ("upi_ids", "phone_numbers", "emails"):
                ids.update(v.lower() for v in contacts.get(key, []))
            if event.details.get("domain"):
                ids.add(event.details["domain"].lower())
            for ident in ids:
                suspects.setdefault(ident, set()).add(event.evidence_id)

        suspicious_contact_times = [
            e._dt for e in events if e.stage in ("contact", "lure") and e._dt is not None
        ]
        for event in events:
            if event.stage != "transaction":
                continue
            direction = (event.amount or {}).get("direction")
            counterparty = event.actors.get("from" if direction == "credit" else "to")
            matches = set().union(*(suspects.get(i, set()) for i in _identifiers(counterparty)))
            matches.discard(event.evidence_id)
            if matches:
                event.linked_evidence = sorted(m for m in matches if m)
                if direction == "credit":
                    event.event_type = "scammer_credit"
                    event.title += " (suspect account)"
                else:
                    event.event_type = ("fraud_attempt" if event.event_type == "failed_transaction"
                                        else "fraudulent_payment")
                    event.stage = "fraud"
                    event.title = f"{_cap(EVENT_LABELS[event.event_type])}: {event.title}"
                event.description += (f" — counterparty {party_label(counterparty)} "
                                      "appears in suspicious evidence")
                event.severity = _SEVERITY[event.event_type]
            elif direction != "credit" and event._dt is not None and any(
                t <= event._dt for t in suspicious_contact_times
            ):
                event.details["follows_suspicious_contact"] = True
                event.severity = "medium"

    @staticmethod
    def _mark_follow_ups(events: list[TimelineEvent]) -> None:
        """Suspicious contact after money was lost is a follow-up (e.g. 'pay tax to release')."""
        seen_fraud = False
        for event in events:
            if event.stage == "fraud":
                seen_fraud = True
            elif seen_fraud and event.event_type == "suspicious_message":
                event.event_type, event.stage = "follow_up_message", "follow_up"
                event.severity = _SEVERITY["follow_up_message"]
                event.title = event.title.replace("Suspicious", "Follow-up", 1)

    # ------------------------------------------------------------- sorting

    def _sort(self, events: list[TimelineEvent]) -> list[TimelineEvent]:
        def key(e: TimelineEvent):
            if e._dt is None:
                return (1, datetime.max.replace(tzinfo=timezone.utc), STAGE_ORDER[e.stage], e._order)
            # A date-only event could have happened any time that day; placing it
            # at the end of the day keeps a timed message before a same-day debit.
            dt = e._dt + timedelta(days=1, microseconds=-1) if e.time_precision == "date" else e._dt
            return (0, dt, STAGE_ORDER[e.stage], e._order)

        return sorted(events, key=key)

    # ------------------------------------------------------------- summary

    def _summary(self, events: list[TimelineEvent], record_count: int) -> dict[str, Any]:
        dated = [e for e in events if e._dt is not None]
        chain: list[str] = []
        for e in dated:
            label = EVENT_LABELS[e.event_type]
            if e.event_type not in ("message", "url") and label not in chain:
                chain.append(label)

        losses: dict[str, float] = {}
        for e in events:
            if e.event_type == "fraudulent_payment" and e.amount and e.amount["value"]:
                cur = e.amount.get("currency") or "INR"
                losses[cur] = round(losses.get(cur, 0) + e.amount["value"], 2)

        first_contact = next((e for e in dated if e.stage in ("contact", "lure")), None)
        first_loss = next((e for e in dated if e.event_type == "fraudulent_payment"), None)
        # The sender of a suspicious contact and the payee of a fraudulent
        # payment are suspects; the payer of that payment is the victim.
        suspect_parties = [
            e.actors.get("to") if e.stage == "fraud" else e.actors.get("from")
            for e in events if e.stage in ("contact", "lure", "fraud", "follow_up")
        ]
        suspects = sorted({p["identifier"] for p in suspect_parties if p and p.get("identifier")})

        return {
            "evidence_count": record_count,
            "event_count": len(events),
            "undated_event_count": len(events) - len(dated),
            "first_event_at": dated[0].timestamp if dated else None,
            "last_event_at": dated[-1].timestamp if dated else None,
            "duration": humanize_delta(dated[-1]._dt - dated[0]._dt) if len(dated) > 1 else None,
            "attack_chain": " → ".join(chain) or None,
            "stages_observed": sorted({e.stage for e in events}, key=STAGE_ORDER.get),
            "fraudulent_payment_count": sum(e.event_type == "fraudulent_payment" for e in events),
            "total_loss": losses,
            "time_to_first_loss": humanize_delta(first_loss._dt - first_contact._dt)
            if first_contact and first_loss and first_loss._dt >= first_contact._dt else None,
            "suspect_identifiers": suspects,
            "highest_severity": max(
                (e.severity for e in events),
                key=["info", "low", "medium", "high", "critical"].index,
                default=None,
            ),
        }


def build_timeline(records: Iterable[dict[str, Any]], case_id: str | None = None,
                   tz: str = DEFAULT_TZ) -> dict[str, Any]:
    return TimelineBuilder(tz).build(records, case_id)
