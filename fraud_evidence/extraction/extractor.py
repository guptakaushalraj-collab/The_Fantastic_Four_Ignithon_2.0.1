"""Module 2 core: pull key fields out of normalized evidence.

Every evidence type is reduced to the same record shape (see ``schema.json``)
so later modules can correlate a chat, a payment screenshot and a bank
statement without caring which form the evidence arrived in.
"""

from __future__ import annotations

import re
from datetime import datetime
from email.utils import parsedate_to_datetime
from typing import Any

from ..ingestion.models import Evidence
from ..ingestion.text import extract_entities
from ..ingestion.transactions import parse_timestamp
from .reputation import URLReputationScorer

SCHEMA_VERSION = "1.0"
_TXN_FIELDS = ("transaction_id", "amount", "currency", "direction", "payment_method", "status")

_HEADER_RE = re.compile(r"(?im)^(from|to|date|subject|sent|received)\s*:\s*(.+)$")
_NAME_ADDR_RE = re.compile(r"^\s*\"?([^\"<]*?)\"?\s*<([^>]+)>\s*$")
# WhatsApp exports: "[12/03/24, 10:15:02 AM] Name: text" or "12/03/2024, 10:15 - Name: text"
_CHAT_LINE_RE = re.compile(
    r"^\[?(?P<date>\d{1,2}/\d{1,2}/\d{2,4}),?\s+(?P<time>\d{1,2}:\d{2}(?::\d{2})?(?:\s?[AaPp]\.?[Mm]\.?)?)\]?"
    r"\s*(?:-\s*)?(?P<name>[^:\n]{1,60}?):\s(?P<text>.*)$"
)
# DLT-registered SMS headers such as "VM-SBIINB" or "AD-HDFCBK".
_SMS_HEADER_RE = re.compile(r"^(?:from\s*:\s*)?(?P<id>[A-Z]{2}-[A-Z0-9]{5,8})(?:-[A-Z])?\b[:\s]*", re.M)
_TEXT_DATETIME_RE = re.compile(
    r"\b(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}(?::\d{2})?"
    r"|\d{1,2}[-/]\d{1,2}[-/]\d{2,4}(?:,?\s+\d{1,2}:\d{2}(?::\d{2})?(?:\s?[AaPp][Mm])?)?"
    r"|\d{1,2}[- ][A-Za-z]{3}[- ]\d{2,4})\b"
)
_EXTRA_DATETIME_FORMATS = (
    "%d/%m/%y %I:%M:%S %p", "%d/%m/%y %I:%M %p", "%d/%m/%Y %I:%M:%S %p", "%d/%m/%Y %I:%M %p",
    "%d/%m/%y %H:%M:%S", "%d/%m/%y %H:%M", "%d/%m/%Y %H:%M", "%d-%m-%Y %H:%M", "%d-%m-%y %H:%M",
    "%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M",
)
_ACCOUNT_RE = re.compile(r"^[xX*]*\d{3,18}$")
# "A/c 7210933889": marked as an account, so a 10-digit number is not taken for a phone.
_ACCOUNT_PREFIX_RE = re.compile(r"(?i)^(?:a/?c|acct|account)(?:\s*no)?\.?\s*[:#]?\s*([xX*]*\d{3,18})$")
_PHONE_RE = re.compile(r"^\+?\d[\d\s-]{8,14}\d$")


def parse_datetime(value: Any) -> str | None:
    """Parse the date formats seen in chats, SMS, emails and bank exports to ISO-8601."""
    if value in (None, ""):
        return None
    parsed = parse_timestamp(value)
    if parsed:
        return parsed
    text = re.sub(r"\s+", " ", str(value).replace(",", " ")).strip()
    text = re.sub(r"(?i)([ap])\.?m\.?$", lambda m: m.group(1).upper() + "M", text)
    for fmt in _EXTRA_DATETIME_FORMATS:
        try:
            return datetime.strptime(text, fmt).isoformat()
        except ValueError:
            continue
    try:
        return parsedate_to_datetime(str(value)).isoformat()
    except (TypeError, ValueError, IndexError):
        return None


def make_party(raw: Any, name: str | None = None) -> dict[str, Any] | None:
    """Describe a sender/receiver, classifying its identifier (UPI, email, phone, ...)."""
    if raw in (None, "") and not name:
        return None
    raw_text = str(raw).strip() if raw not in (None, "") else ""
    identifier = raw_text or None
    id_type = None

    if raw_text:
        m = _NAME_ADDR_RE.match(raw_text)
        if m:
            name = name or m.group(1).strip() or None
            identifier = m.group(2).strip()
        ident = identifier or ""
        account = _ACCOUNT_PREFIX_RE.match(ident)
        digits = re.sub(r"\D", "", ident)
        # Indian mobile: 10 digits from 6-9, optionally written with 0 or 91 in front.
        mobile = (len(digits) == 10 and digits[0] in "6789"
                  or len(digits) == 11 and digits[0] == "0" and digits[1] in "6789"
                  or len(digits) == 12 and digits[:2] == "91" and digits[2] in "6789")
        if account:
            id_type, identifier = "account", account.group(1)
        elif "@" in ident:
            id_type = "email" if "." in ident.split("@", 1)[1] else "upi_id"
            identifier = ident.lower()
        elif _SMS_HEADER_RE.fullmatch(ident):
            id_type = "sms_sender_id"
        elif _PHONE_RE.match(ident) and len(digits) >= 10 and (mobile or ident.startswith("+")):
            # Other bare digit strings (e.g. an 11-digit account number) are not phones.
            id_type = "phone"
            identifier = "+91" + digits[-10:] if mobile else "+" + digits
        elif _ACCOUNT_RE.match(ident):
            id_type = "account"
        else:
            # Free text like "John" or "Amazon Pay" is a display name, not an identifier.
            name, identifier = name or ident, None

    return {"name": name, "identifier": identifier, "identifier_type": id_type, "raw": raw_text or name}


def _transaction_fields(record: dict[str, Any]) -> dict[str, Any]:
    return {k: record.get(k) for k in _TXN_FIELDS}


class InformationExtractor:
    """Convert Module 1 :class:`Evidence` (or its dict form) into key-field records."""

    def __init__(self, reputation_scorer: URLReputationScorer | None = None):
        self.reputation = reputation_scorer or URLReputationScorer()

    def extract(self, evidence: Evidence | dict[str, Any]) -> dict[str, Any]:
        ev = evidence.to_dict() if isinstance(evidence, Evidence) else evidence
        kind = ev["evidence_type"]
        structured = ev.get("structured") or {}
        metadata = ev.get("metadata") or {}
        entities = ev.get("entities") or {}

        out: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "evidence_id": ev.get("evidence_id"),
            "evidence_type": kind,
            "source": ev.get("source"),
            "content_hash": ev.get("content_hash"),
            "sender": None,
            "receiver": None,
            "timestamp": None,
            "transaction": None,
            "transactions": [],
            "urls": [],
            "message": None,
            "contacts": {
                "phone_numbers": entities.get("phone_numbers", []),
                "emails": entities.get("emails", []),
                "upi_ids": entities.get("upi_ids", []),
                "reference_numbers": entities.get("reference_numbers", []),
            },
            "field_sources": {},
            "warnings": list(ev.get("warnings", [])),
        }

        if kind == "transaction":
            self._from_transactions(out, structured.get("records", []))
        elif kind == "url":
            out["urls"] = [self.reputation.score(structured or ev["normalized_text"]).to_dict()]
            out["field_sources"]["urls"] = "evidence_url"
        else:  # message or screenshot
            self._from_message(out, ev.get("normalized_text", ""), entities)
            if kind == "screenshot" and structured.get("transaction"):
                self._from_transactions(out, [structured["transaction"]], overwrite=False)
            if kind == "screenshot":
                out["message"]["ocr_confidence"] = structured.get("ocr_confidence")

        if kind != "url":
            out["urls"] = [self.reputation.score(u).to_dict() for u in entities.get("urls", [])]
            if out["urls"]:
                out["field_sources"]["urls"] = "text"

        self._apply_metadata(out, metadata)
        return out

    def extract_many(self, items) -> list[dict[str, Any]]:
        return [self.extract(item) for item in items]

    # ----------------------------------------------------------------- helpers

    def _set(self, out, field, value, source, overwrite=True):
        if value in (None, "", []) or (out[field] is not None and not overwrite):
            return
        out[field] = value
        out["field_sources"][field] = source

    def _from_transactions(self, out, records, overwrite=True):
        txns = []
        for rec in records:
            sender, receiver = rec.get("sender"), rec.get("receiver")
            # Bank statements often carry the counterparty only in the narration
            # ("UPI/abc@ybl/..."), so fall back to a UPI ID found there.
            if rec.get("description"):
                upi = extract_entities(str(rec["description"])).upi_ids
                if upi and rec.get("direction") == "credit" and not sender:
                    sender = upi[0]
                elif upi and rec.get("direction") != "credit" and not receiver:
                    receiver = upi[0]
            txns.append({
                **_transaction_fields(rec),
                "sender": make_party(sender),
                "receiver": make_party(receiver),
                "timestamp": parse_datetime(rec.get("timestamp")) or rec.get("timestamp"),
                "description": rec.get("description"),
            })
        if not txns:
            return
        out["transactions"] = txns
        first = txns[0]
        self._set(out, "sender", first["sender"], "transaction", overwrite)
        self._set(out, "receiver", first["receiver"], "transaction", overwrite)
        self._set(out, "timestamp", first["timestamp"], "transaction", overwrite)
        self._set(out, "transaction", _transaction_fields(first), "transaction", overwrite)
        if len(txns) > 1:
            amounts = [t["amount"] for t in txns if isinstance(t["amount"], (int, float))]
            out["transaction"] = {
                **out["transaction"],
                "record_count": len(txns),
                "total_debit": round(sum(t["amount"] for t in txns
                                         if t["direction"] == "debit" and t["amount"]), 2),
                "total_credit": round(sum(t["amount"] for t in txns
                                          if t["direction"] == "credit" and t["amount"]), 2),
                "max_amount": max(amounts) if amounts else None,
            }

    def _from_message(self, out, text: str, entities: dict):
        headers = {k.lower(): v.strip() for k, v in _HEADER_RE.findall(text)}
        body = text
        platform = None
        participants: list[str] = []

        if "from" in headers:
            platform = "email" if "subject" in headers or "@" in headers["from"] else "sms"
            self._set(out, "sender", make_party(headers["from"]), "header")
            self._set(out, "receiver", make_party(headers.get("to")), "header")
            self._set(out, "timestamp", parse_datetime(headers.get("date") or headers.get("sent")),
                      "header")
            body = _HEADER_RE.sub("", text).strip()

        chat_lines = [m for line in body.splitlines() if (m := _CHAT_LINE_RE.match(line))]
        if chat_lines:
            platform = platform or "chat"
            participants = list(dict.fromkeys(m.group("name").strip() for m in chat_lines))
            first = chat_lines[0]
            self._set(out, "sender", make_party(None, name=participants[0]), "chat_export")
            if len(participants) > 1:
                self._set(out, "receiver", make_party(None, name=participants[1]), "chat_export")
            self._set(out, "timestamp",
                      parse_datetime(f"{first.group('date')} {first.group('time')}"), "chat_export")
            body = "\n".join(f"{m.group('name').strip()}: {m.group('text')}" for m in chat_lines)

        if platform is None and (sms := _SMS_HEADER_RE.match(body)):
            platform = "sms"
            self._set(out, "sender", {"name": None, "identifier": sms.group("id"),
                                      "identifier_type": "sms_sender_id", "raw": sms.group("id")},
                      "sms_header")
            body = body[sms.end():].strip()

        if out["timestamp"] is None and (m := _TEXT_DATETIME_RE.search(body)):
            self._set(out, "timestamp", parse_datetime(m.group(1)), "text")

        out["message"] = {
            "content": body,
            "subject": headers.get("subject"),
            "platform": platform,
            "participants": participants,
            "char_count": len(body),
            "amounts_mentioned": entities.get("amounts", []),
        }

    def _apply_metadata(self, out, metadata: dict):
        """Values supplied by the reporter at submission time override inferred ones."""
        for key in ("sender", "receiver"):
            if metadata.get(key):
                self._set(out, key, make_party(metadata[key]), "metadata")
        if metadata.get("timestamp"):
            ts = parse_datetime(metadata["timestamp"])
            if ts:
                self._set(out, "timestamp", ts, "metadata")
            else:
                out["warnings"].append(f"unparseable metadata timestamp: {metadata['timestamp']!r}")
