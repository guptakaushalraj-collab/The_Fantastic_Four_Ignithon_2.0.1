"""Parsing of transaction evidence into a canonical record shape.

Transactions arrive as JSON objects, lists of objects, CSV exports, or the
free text of bank/UPI alert SMS. Every form is mapped onto the same field
names so downstream modules never deal with bank-specific column headers.
"""

from __future__ import annotations

import csv
import io
import json
import re
from datetime import datetime
from typing import Any

from .text import extract_entities, normalize_text, parse_amount

CANONICAL_FIELDS = (
    "transaction_id", "timestamp", "amount", "currency", "direction",
    "sender", "receiver", "payment_method", "status", "description",
)

_ALIASES = {
    "transaction_id": {"transaction_id", "txn_id", "txnid", "id", "utr", "rrn",
                       "reference", "reference_number", "ref_no", "ref"},
    "timestamp": {"timestamp", "date", "datetime", "time", "txn_date",
                  "transaction_date", "value_date", "created_at"},
    "amount": {"amount", "amt", "value", "txn_amount", "transaction_amount",
               "debit", "credit", "withdrawal", "deposit"},
    "currency": {"currency", "cur", "ccy"},
    "direction": {"direction", "type", "dr_cr", "cr_dr", "txn_type"},
    "sender": {"sender", "from", "payer", "from_account", "remitter", "source"},
    "receiver": {"receiver", "to", "payee", "beneficiary", "to_account", "vpa",
                 "merchant", "destination"},
    "payment_method": {"payment_method", "method", "mode", "channel", "payment_mode"},
    "status": {"status", "state", "result"},
    "description": {"description", "narration", "remarks", "note", "memo",
                    "particulars", "details"},
}
_ALIAS_LOOKUP = {alias: canon for canon, aliases in _ALIASES.items() for alias in aliases}

_DATE_FORMATS = (
    "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S", "%Y-%m-%d", "%d-%m-%Y %H:%M:%S",
    "%d-%m-%Y", "%d/%m/%Y %H:%M:%S", "%d/%m/%Y", "%d-%m-%y", "%d/%m/%y",
    "%d-%b-%Y", "%d-%b-%y", "%d %b %Y", "%d%b%y", "%d %b %Y %H:%M",
)

_TXN_KEYWORDS = re.compile(
    r"(?i)\b(debited|credited|debit|credit|withdrawn|deposited|sent|received|paid|"
    r"a/c|acct|account|upi|imps|neft|rtgs|utr|txn|transaction)\b"
)
_DIRECTION_RE = re.compile(r"(?i)\b(debited|withdrawn|sent|paid|dr)\b|\b(credited|deposited|received|cr)\b")
_METHOD_RE = re.compile(r"(?i)\b(upi|imps|neft|rtgs|card|atm|net ?banking|wallet)\b")
_ACCOUNT_RE = re.compile(r"(?i)\ba/?c\.?\s*(?:no\.?)?\s*([x*]*\d{3,6})")
_TEXT_DATE_RE = re.compile(
    r"\b(\d{1,2}[-/]\d{1,2}[-/]\d{2,4}|\d{4}-\d{2}-\d{2}|\d{1,2}[- ]?[A-Za-z]{3}[- ]?\d{2,4})\b"
)


def _normalize_key(key: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", str(key).strip().lower()).strip("_")


def parse_timestamp(value: Any) -> str | None:
    if value in (None, ""):
        return None
    if isinstance(value, (int, float)):
        return datetime.fromtimestamp(value / 1000 if value > 1e11 else value).isoformat()
    text = str(value).strip()
    try:
        return datetime.fromisoformat(text.replace("Z", "+00:00")).isoformat()
    except ValueError:
        pass
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt).isoformat()
        except ValueError:
            continue
    return None


def _normalize_direction(value: Any) -> str | None:
    text = str(value or "").strip().lower()
    if text in {"dr", "debit", "debited", "withdrawal", "sent", "out", "outgoing", "paid"}:
        return "debit"
    if text in {"cr", "credit", "credited", "deposit", "received", "in", "incoming"}:
        return "credit"
    return None


def normalize_record(record: dict[str, Any]) -> tuple[dict[str, Any], list[str]]:
    """Map an arbitrary transaction dict onto :data:`CANONICAL_FIELDS`."""
    out: dict[str, Any] = dict.fromkeys(CANONICAL_FIELDS)
    extra: dict[str, Any] = {}
    warnings: list[str] = []

    for key, value in record.items():
        norm = _normalize_key(key)
        canon = _ALIAS_LOOKUP.get(norm)
        if canon is None or value in (None, ""):
            extra[key] = value
            continue
        # Bank statements split amounts into debit/credit columns; the column
        # name tells us the direction.
        if canon == "amount" and norm in {"debit", "withdrawal", "credit", "deposit"}:
            out["direction"] = out["direction"] or _normalize_direction(norm)
        if out[canon] is None:
            out[canon] = value
        else:
            extra[key] = value

    if out["amount"] is not None:
        raw_amount = out["amount"]
        amount = raw_amount if isinstance(raw_amount, (int, float)) else parse_amount(
            re.sub(r"[^\d.,-]", "", str(raw_amount))
        )
        if amount is None:
            warnings.append(f"unparseable amount: {raw_amount!r}")
        else:
            if amount < 0:
                out["direction"] = out["direction"] or "debit"
            out["amount"] = abs(float(amount))
            if out["currency"] is None and re.search(r"₹|rs|inr", str(raw_amount), re.I):
                out["currency"] = "INR"

    if out["timestamp"] is not None:
        parsed = parse_timestamp(out["timestamp"])
        if parsed is None:
            warnings.append(f"unparseable timestamp: {out['timestamp']!r}")
        else:
            out["timestamp"] = parsed

    if out["direction"] is not None:
        out["direction"] = _normalize_direction(out["direction"]) or out["direction"]
    if out["currency"] is not None:
        out["currency"] = str(out["currency"]).upper()
    if out["payment_method"] is not None:
        out["payment_method"] = str(out["payment_method"]).upper()
    if out["transaction_id"] is not None:
        out["transaction_id"] = str(out["transaction_id"]).strip()

    if extra:
        out["extra"] = extra
    return out, warnings


def parse_transaction_text(text: str) -> dict[str, Any]:
    """Best-effort parse of a bank/UPI alert such as
    ``Rs.5,000 debited from A/c XX1234 on 12-03-24 to VPA abc@ybl UPI Ref 412345678901``.
    """
    text = normalize_text(text)
    entities = extract_entities(text)
    record: dict[str, Any] = dict.fromkeys(CANONICAL_FIELDS)

    if entities.amounts:
        record["amount"] = entities.amounts[0]["value"]
        record["currency"] = entities.amounts[0]["currency"]
    if entities.reference_numbers:
        record["transaction_id"] = entities.reference_numbers[0]
    if m := _DIRECTION_RE.search(text):
        record["direction"] = "debit" if m.group(1) else "credit"
    if m := _METHOD_RE.search(text):
        record["payment_method"] = m.group(1).upper().replace(" ", "")
    if m := _TEXT_DATE_RE.search(text):
        record["timestamp"] = parse_timestamp(m.group(1).replace(" ", "-")) or m.group(1)

    account = _ACCOUNT_RE.search(text)
    counterparty = entities.upi_ids[0] if entities.upi_ids else None
    if record["direction"] == "credit":
        record["receiver"] = account.group(1) if account else None
        record["sender"] = counterparty
    else:
        record["sender"] = account.group(1) if account else None
        record["receiver"] = counterparty

    record["description"] = text
    return record


def looks_like_transaction_text(text: str) -> bool:
    """Heuristic: an amount plus at least two banking keywords."""
    return bool(extract_entities(text).amounts) and len(set(
        m.lower() for m in _TXN_KEYWORDS.findall(text)
    )) >= 2


def parse_structured(payload: Any) -> list[dict[str, Any]] | None:
    """Return raw transaction dicts from a dict/list payload or JSON/CSV text, else ``None``."""
    if isinstance(payload, dict):
        return [payload]
    if isinstance(payload, list) and payload and all(isinstance(r, dict) for r in payload):
        return payload
    if not isinstance(payload, str):
        return None

    stripped = payload.strip()
    if stripped[:1] in "[{":
        try:
            return parse_structured(json.loads(stripped))
        except json.JSONDecodeError:
            return None

    lines = stripped.splitlines()
    if len(lines) >= 2 and ("," in lines[0] or "\t" in lines[0] or ";" in lines[0]):
        try:
            dialect = csv.Sniffer().sniff(lines[0], delimiters=",;\t")
        except csv.Error:
            return None
        rows = list(csv.DictReader(io.StringIO(stripped), dialect=dialect))
        header = {_normalize_key(h) for h in rows[0].keys()} if rows else set()
        if header & _ALIASES["amount"]:
            return rows
    return None
