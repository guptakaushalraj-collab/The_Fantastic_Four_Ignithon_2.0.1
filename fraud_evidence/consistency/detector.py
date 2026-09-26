"""Module 4 core: flag gaps and contradictions in a fraud timeline.

Gaps are details an investigator still needs (an undated payment, a debit
with no UTR, a scam message whose sender is only a display name).
Contradictions are pieces of evidence that disagree with each other: the
same transaction reference with different amounts or payees, a payment that
does not match the amount the scammer asked for, one sender name behind
several phone numbers, or a payment dated before the message that caused it.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass, field as dc_field
from datetime import date, datetime, timedelta, timezone
from typing import Any, Iterable

from ..timeline.builder import format_money, party_label

SEVERITY_ORDER = ["low", "medium", "high"]
CATEGORY_ORDER = ["contradiction", "gap", "duplicate"]

_MONEY_STAGES = {"transaction", "fraud"}
_SUSPICIOUS_MESSAGES = {"suspicious_message", "follow_up_message"}
_FAILED = {"failed", "declined", "rejected", "reversed", "cancelled"}
_SUCCEEDED = {"success", "successful", "completed", "processed", "paid", "debited", "credited"}
# Receipts and statements for one payment often differ by a few minutes.
TIME_TOLERANCE = timedelta(hours=1)


@dataclass
class Issue:
    category: str  # "gap" | "contradiction" | "duplicate"
    issue_type: str
    severity: str
    title: str
    description: str
    field: str | None = None
    events: list[int] = dc_field(default_factory=list)
    evidence_ids: list[str] = dc_field(default_factory=list)
    values: list[dict[str, Any]] = dc_field(default_factory=list)
    suggestion: str | None = None
    issue_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return {"issue_id": data.pop("issue_id"), **data}


# ---------------------------------------------------------------- helpers

def _ids(events: Iterable[dict]) -> list[str]:
    return sorted({e["evidence_id"] for e in events if e.get("evidence_id")})


def _seqs(events: Iterable[dict]) -> list[int]:
    return sorted(e["sequence"] for e in events)


def _when(event: dict) -> datetime | date | None:
    ts = event.get("timestamp")
    if not ts:
        return None
    if event.get("time_precision") == "date":
        return date.fromisoformat(ts)
    return datetime.fromisoformat(ts)


def _day(value: datetime | date) -> date:
    return value.date() if isinstance(value, datetime) else value


def _is_money(event: dict) -> bool:
    return event.get("stage") in _MONEY_STAGES and event.get("amount") is not None


def _normalize_identifier(party: dict | None) -> str | None:
    """Comparable form of an identifier: masked accounts by last 4 digits, phones by last 10."""
    if not party or not party.get("identifier"):
        return None
    ident = re.sub(r"\s+", "", str(party["identifier"])).lower()
    kind = party.get("identifier_type")
    digits = re.sub(r"\D", "", ident)
    if kind == "account" and len(digits) >= 4:
        return "acct:" + digits[-4:]
    if kind == "phone" and len(digits) >= 10:
        return "phone:" + digits[-10:]
    return ident


def _normalize_name(party: dict | None) -> str | None:
    if not party or not party.get("name"):
        return None
    return " ".join(party["name"].lower().split())


def _status_class(event: dict) -> str | None:
    status = ((event.get("details") or {}).get("status") or "").lower()
    if status in _FAILED:
        return "failed"
    if status in _SUCCEEDED:
        return "succeeded"
    return None


def _money(event: dict) -> str:
    amount = event.get("amount") or {}
    return format_money(amount.get("value"), amount.get("currency"))


def _value(event: dict, value: Any) -> dict[str, Any]:
    return {"sequence": event["sequence"], "evidence_id": event.get("evidence_id"), "value": value}


# --------------------------------------------------------------- detector

class ConsistencyChecker:
    """Check a Module 3 timeline for missing details and conflicting evidence."""

    def check(self, timeline: dict[str, Any]) -> dict[str, Any]:
        events = timeline.get("events", [])
        issues: list[Issue] = []
        for check in (
            self._missing_timestamps, self._date_only_payments, self._incomplete_transactions,
            self._unidentified_senders, self._unlinked_debits, self._no_transaction_evidence,
            self._transaction_conflicts, self._requested_vs_paid, self._sender_id_conflicts,
            self._payment_before_contact,
        ):
            issues.extend(check(events))

        issues.sort(key=lambda i: (-SEVERITY_ORDER.index(i.severity),
                                   CATEGORY_ORDER.index(i.category),
                                   i.events[0] if i.events else 0, i.issue_type))
        for n, issue in enumerate(issues, start=1):
            issue.issue_id = f"ISSUE-{n:03d}"

        return {
            "case_id": timeline.get("case_id"),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "timezone": timeline.get("timezone"),
            "summary": self._summary(issues, len(events)),
            "issues": [i.to_dict() for i in issues],
        }

    # ------------------------------------------------------------- gaps

    @staticmethod
    def _missing_timestamps(events: list[dict]) -> list[Issue]:
        # A message and the URL it carries share one evidence item: report it once.
        by_evidence: dict[Any, list[dict]] = {}
        for e in events:
            if e.get("timestamp") is None:
                by_evidence.setdefault(e.get("evidence_id") or id(e), []).append(e)

        issues = []
        for group in by_evidence.values():
            money = any(e["stage"] in _MONEY_STAGES for e in group)
            first = group[0]
            issues.append(Issue(
                "gap", "missing_timestamp", "high" if money else "medium",
                f"No timestamp: {first['title']}",
                "This evidence has no date or time, so its place in the attack chain is unknown"
                + (" and the payment cannot be matched to a bank statement." if money else "."),
                field="timestamp", events=_seqs(group), evidence_ids=_ids(group),
                suggestion="Get the original with its date (full screenshot, message info, "
                           "email headers or bank statement entry).",
            ))
        return issues

    @staticmethod
    def _date_only_payments(events: list[dict]) -> list[Issue]:
        issues = []
        for e in events:
            if _is_money(e) and e.get("time_precision") == "date":
                issues.append(Issue(
                    "gap", "date_only_timestamp", "low",
                    f"Time of day unknown: {e['title']}",
                    f"Only the date ({e['timestamp']}) is known, so its order relative to "
                    "messages the same day is inferred, not proven.",
                    field="timestamp", events=[e["sequence"]], evidence_ids=_ids([e]),
                    suggestion="Get the payment receipt or UPI app history, which shows the exact time.",
                ))
        return issues

    @staticmethod
    def _incomplete_transactions(events: list[dict]) -> list[Issue]:
        issues = []
        for e in events:
            if not _is_money(e):
                continue
            fraud = e["stage"] == "fraud"
            direction = e["amount"].get("direction") or "debit"
            where = dict(events=[e["sequence"]], evidence_ids=_ids([e]))
            if e["amount"].get("value") is None:
                issues.append(Issue(
                    "gap", "missing_amount", "high" if fraud else "medium",
                    f"Amount missing: {e['title']}",
                    "The transaction amount could not be read, so the loss cannot be quantified.",
                    field="amount.value", suggestion="Get a clearer receipt or the bank statement entry.",
                    **where,
                ))
            counterparty = "to" if direction == "debit" else "from"
            if _normalize_identifier(e["actors"].get(counterparty)) is None:
                role = "payee" if direction == "debit" else "payer"
                issues.append(Issue(
                    "gap", "missing_counterparty", "medium",
                    f"No {role} account: {e['title']}",
                    f"The {role}'s UPI ID, account or phone number is missing, so this transaction "
                    "cannot be linked to a suspect.",
                    field=f"actors.{counterparty}.identifier",
                    suggestion=f"Find the {role} VPA/account in the receipt or the UPI app history.",
                    **where,
                ))
            if not (e.get("details") or {}).get("transaction_id"):
                issues.append(Issue(
                    "gap", "missing_transaction_id", "medium" if fraud else "low",
                    f"No UTR/reference: {e['title']}",
                    "Without a UTR or transaction reference the bank cannot trace or freeze this payment.",
                    field="details.transaction_id",
                    suggestion="Get the UTR number from the receipt, SMS alert or bank statement.",
                    **where,
                ))
        return issues

    @staticmethod
    def _unidentified_senders(events: list[dict]) -> list[Issue]:
        issues = []
        for e in events:
            if e["event_type"] not in _SUSPICIOUS_MESSAGES:
                continue
            sender = e["actors"].get("from")
            if sender and sender.get("identifier"):
                continue
            name = (sender or {}).get("name")
            issues.append(Issue(
                "gap", "missing_sender_id", "medium",
                f"Sender not identified: {e['title']}",
                (f'The sender is known only by the display name "{name}"' if name
                 else "The sender of this suspicious message is unknown")
                + ", so it cannot be traced or matched with other evidence.",
                field="actors.from.identifier", events=[e["sequence"]], evidence_ids=_ids([e]),
                suggestion="Get the sender's phone number, email address or SMS header "
                           "(e.g. from the chat's contact info).",
            ))
        return issues

    @staticmethod
    def _unlinked_debits(events: list[dict]) -> list[Issue]:
        issues = []
        for e in events:
            if (e.get("details") or {}).get("follows_suspicious_contact"):
                issues.append(Issue(
                    "gap", "unlinked_debit", "medium",
                    f"Possible loss not linked to the scam: {e['title']}",
                    "This debit happened after suspicious contact, but its payee does not appear in "
                    "any suspicious evidence, so it may or may not be part of the fraud.",
                    field="actors.to", events=[e["sequence"]], evidence_ids=_ids([e]),
                    suggestion="Ask the victim whether they made this payment and why; collect the "
                               "message that gave them the payee details.",
                ))
        return issues

    @staticmethod
    def _no_transaction_evidence(events: list[dict]) -> list[Issue]:
        contact = [e for e in events if e["stage"] in ("contact", "lure", "follow_up")]
        if not contact or any(_is_money(e) for e in events):
            return []
        return [Issue(
            "gap", "no_transaction_evidence", "medium",
            "No transaction evidence",
            "The case has suspicious contact but no payment records, so any loss is unproven.",
            events=[], evidence_ids=[],
            suggestion="Collect bank statements, UPI history or payment receipts for the period "
                       "after the first contact (or confirm no money was lost).",
        )]

    # --------------------------------------------------- contradictions

    def _transaction_conflicts(self, events: list[dict]) -> list[Issue]:
        """Evidence items describing the same transaction reference must agree."""
        groups: dict[str, list[dict]] = {}
        for e in events:
            ref = (e.get("details") or {}).get("transaction_id")
            if _is_money(e) and ref:
                groups.setdefault(re.sub(r"\s+", "", str(ref)).upper(), []).append(e)

        issues = []
        for ref, group in groups.items():
            if len(group) < 2:
                continue
            found = self._compare_transactions(ref, group)
            issues.extend(found)
            if not found:
                counted = sum(e["event_type"] == "fraudulent_payment" for e in group)
                issues.append(Issue(
                    "duplicate", "duplicate_transaction", "medium" if counted > 1 else "low",
                    f"Same transaction in {len(group)} pieces of evidence (ref {ref})",
                    "These records agree and describe one payment"
                    + (f"; the timeline's total loss counts it {counted} times." if counted > 1
                       else "."),
                    field="details.transaction_id", events=_seqs(group), evidence_ids=_ids(group),
                    values=[_value(e, _money(e)) for e in group],
                    suggestion="Count this payment once when reporting the loss.",
                ))
        return issues

    @staticmethod
    def _compare_transactions(ref: str, group: list[dict]) -> list[Issue]:
        issues = []
        where = dict(events=_seqs(group), evidence_ids=_ids(group))

        def conflict(issue_type, severity, what, field_name, values, description):
            issues.append(Issue(
                "contradiction", issue_type, severity, f"Conflicting {what} for transaction {ref}",
                description, field=field_name, values=values,
                suggestion="Check which record is authentic against the bank's own statement.",
                **where,
            ))

        amounts = {round(e["amount"]["value"], 2) for e in group if e["amount"].get("value") is not None}
        if len(amounts) > 1:
            conflict("amount_mismatch", "high", "amounts", "amount.value",
                     [_value(e, e["amount"]["value"]) for e in group],
                     "The same reference appears with different amounts: "
                     + ", ".join(sorted({_money(e) for e in group})) + ".")

        currencies = {e["amount"]["currency"] for e in group if e["amount"].get("currency")}
        if len(currencies) > 1:
            conflict("currency_mismatch", "medium", "currencies", "amount.currency",
                     [_value(e, e["amount"].get("currency")) for e in group],
                     "The same reference appears in different currencies: "
                     + ", ".join(sorted(currencies)) + ".")

        directions = {e["amount"].get("direction") for e in group if e["amount"].get("direction")}
        if len(directions) > 1:
            conflict("direction_mismatch", "high", "directions", "amount.direction",
                     [_value(e, e["amount"].get("direction")) for e in group],
                     "One record shows this reference as a debit and another as a credit.")

        for role, label, severity in (("to", "payee", "high"), ("from", "payer", "medium")):
            parties = {}
            for e in group:
                key = _normalize_identifier(e["actors"].get(role))
                if key:
                    parties.setdefault(key, party_label(e["actors"][role]))
            if len(parties) > 1:
                conflict(f"{label}_mismatch", severity, f"{label}s", f"actors.{role}.identifier",
                         [_value(e, party_label(e["actors"].get(role))) for e in group],
                         f"The same reference names different {label}s: "
                         + ", ".join(sorted(parties.values())) + ".")

        statuses = {_status_class(e) for e in group} - {None}
        if len(statuses) > 1:
            conflict("status_mismatch", "high", "statuses", "details.status",
                     [_value(e, (e.get("details") or {}).get("status")) for e in group],
                     "One record shows this payment as failed and another as successful, "
                     "which changes whether money was lost.")

        timed = [(e, _when(e)) for e in group if _when(e) is not None]
        days = {_day(w) for _, w in timed}
        precise = [w for e, w in timed if e.get("time_precision") == "datetime"]
        if len(days) > 1 or (len(precise) > 1 and max(precise) - min(precise) > TIME_TOLERANCE):
            conflict("timestamp_mismatch", "medium", "timestamps", "timestamp",
                     [_value(e, e.get("timestamp")) for e in group],
                     "The records disagree on when this payment happened: "
                     + ", ".join(sorted({e["timestamp"] for e, _ in timed})) + ".")
        return issues

    @staticmethod
    def _requested_vs_paid(events: list[dict]) -> list[Issue]:
        """A fraudulent payment should match an amount the linked messages asked for."""
        messages: dict[str, list[dict]] = {}
        for e in events:
            if (e.get("details") or {}).get("amounts_mentioned") and e.get("evidence_id"):
                messages.setdefault(e["evidence_id"], []).append(e)

        issues = []
        for e in events:
            if e["event_type"] not in ("fraudulent_payment", "fraud_attempt"):
                continue
            paid = e["amount"].get("value")
            currency = e["amount"].get("currency") or "INR"
            linked = [m for ev_id in e.get("linked_evidence", []) for m in messages.get(ev_id, [])]
            asked = [a for m in linked for a in m["details"]["amounts_mentioned"]
                     if (a.get("currency") or "INR") == currency and a.get("value") is not None]
            if paid is None or not asked or any(abs(a["value"] - paid) < 0.01 for a in asked):
                continue
            requested = sorted({format_money(a["value"], a.get("currency")) for a in asked})
            issues.append(Issue(
                "contradiction", "requested_amount_mismatch", "medium",
                f"Paid amount differs from the amount requested: {e['title']}",
                f"The linked message{'s' if len(linked) > 1 else ''} asked for "
                f"{' / '.join(requested)}, but the payment was {_money(e)}.",
                field="amount.value", events=_seqs([e, *linked]), evidence_ids=_ids([e, *linked]),
                values=[_value(e, paid)] + [_value(m, [a["value"] for a in m["details"]["amounts_mentioned"]])
                                            for m in linked],
                suggestion="Check for further payments (split instalments, fees) or a misread amount.",
            ))
        return issues

    @staticmethod
    def _sender_id_conflicts(events: list[dict]) -> list[Issue]:
        """One name behind several identifiers, or one identifier using several names."""
        by_name: dict[str, dict[str, list[tuple[dict, dict]]]] = {}
        by_ident: dict[str, dict[str, list[tuple[dict, dict]]]] = {}
        for e in events:
            for role in ("from", "to"):
                party = e["actors"].get(role)
                name, ident = _normalize_name(party), _normalize_identifier(party)
                if name and ident:
                    by_name.setdefault(name, {}).setdefault(ident, []).append((e, party))
                    by_ident.setdefault(ident, {}).setdefault(name, []).append((e, party))

        issues = []
        for name, idents in by_name.items():
            if len(idents) < 2:
                continue
            hits = [h for hs in idents.values() for h in hs]
            shown = sorted({hs[0][1]["identifier"] for hs in idents.values()})
            issues.append(Issue(
                "contradiction", "sender_id_conflict", "medium",
                f'"{hits[0][1]["name"]}" appears with {len(idents)} different identifiers',
                f"The same name is linked to {', '.join(shown)}. Either the suspect uses several "
                "accounts, or the evidence is attributed to the wrong party.",
                field="actors.identifier", events=_seqs({id(e): e for e, _ in hits}.values()),
                evidence_ids=_ids(e for e, _ in hits),
                values=[_value(e, p["identifier"]) for e, p in hits],
                suggestion="Record every identifier as a suspect account and confirm with the victim "
                           "which contact they dealt with.",
            ))
        for ident, names in by_ident.items():
            if len(names) < 2:
                continue
            hits = [h for hs in names.values() for h in hs]
            shown = sorted({hs[0][1]["name"] for hs in names.values()})
            issues.append(Issue(
                "contradiction", "identifier_name_conflict", "low",
                f"{hits[0][1]['identifier']} appears under {len(names)} different names",
                f"The same identifier uses the names {', '.join(shown)}, a common impersonation "
                "pattern (or a contact saved under different names).",
                field="actors.name", events=_seqs({id(e): e for e, _ in hits}.values()),
                evidence_ids=_ids(e for e, _ in hits),
                values=[_value(e, p["name"]) for e, p in hits],
            ))
        return issues

    @staticmethod
    def _payment_before_contact(events: list[dict]) -> list[Issue]:
        """A fraudulent payment cannot precede every message that gave the victim the payee."""
        by_evidence: dict[str, list[dict]] = {}
        for e in events:
            if e.get("evidence_id"):
                by_evidence.setdefault(e["evidence_id"], []).append(e)

        issues = []
        for e in events:
            paid_at = _when(e)
            if e["event_type"] not in ("fraudulent_payment", "fraud_attempt") or paid_at is None:
                continue
            linked = [m for ev_id in e.get("linked_evidence", []) for m in by_evidence.get(ev_id, [])
                      if m["stage"] in ("contact", "lure", "follow_up") and _when(m) is not None]
            if not linked:
                continue

            def before(contact: dict) -> bool:
                at = _when(contact)
                if isinstance(paid_at, datetime) and isinstance(at, datetime):
                    return paid_at < at
                return _day(paid_at) < _day(at)

            if all(before(m) for m in linked):
                issues.append(Issue(
                    "contradiction", "payment_before_contact", "medium",
                    f"Payment dated before the contact that led to it: {e['title']}",
                    f"The payment ({e['timestamp']}) is earlier than every linked message "
                    f"({', '.join(sorted({m['timestamp'] for m in linked}))}). A timestamp may be "
                    "wrong (e.g. a timezone or day/month mix-up), or earlier contact is missing.",
                    field="timestamp", events=_seqs([e, *linked]), evidence_ids=_ids([e, *linked]),
                    values=[_value(x, x["timestamp"]) for x in (e, *linked)],
                    suggestion="Verify both timestamps and ask for any earlier messages from this contact.",
                ))
        return issues

    # ------------------------------------------------------------ summary

    @staticmethod
    def _summary(issues: list[Issue], event_count: int) -> dict[str, Any]:
        return {
            "events_checked": event_count,
            "issue_count": len(issues),
            "by_category": {c: sum(i.category == c for i in issues) for c in CATEGORY_ORDER},
            "by_severity": {s: sum(i.severity == s for i in issues) for s in reversed(SEVERITY_ORDER)},
            "highest_severity": issues[0].severity if issues else None,
        }


def check_timeline(timeline: dict[str, Any]) -> dict[str, Any]:
    return ConsistencyChecker().check(timeline)
