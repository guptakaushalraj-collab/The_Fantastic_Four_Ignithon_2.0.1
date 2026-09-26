"""Text normalization and indicator extraction."""

from __future__ import annotations

import re
import unicodedata

from .models import Entities

# Zero-width and bidi control characters are a common trick for hiding
# keywords from filters, so they are stripped before any analysis.
_INVISIBLE = dict.fromkeys(
    map(ord, "​‌‍‎‏‪‫‬‭‮⁠﻿­")
)

_URL_RE = re.compile(
    r"""(?ix)
    (?<![@\w.-])(
        (?:https?://|www\.)[^\s<>"'()]+
      | (?:[a-z0-9-]+\.)+(?:com|in|net|org|info|xyz|top|online|site|club|co|io|ly|me|app|link|live|shop|biz)
        (?:/[^\s<>"'()]*)?
    )
    """
)
_EMAIL_RE = re.compile(r"\b[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b", re.I)
# UPI VPAs look like email addresses without a dotted domain (e.g. ``name@okaxis``).
_UPI_RE = re.compile(r"\b[\w.-]{1,256}@[a-z]{2,64}(?![\w.-])", re.I)
_PHONE_RE = re.compile(r"(?<![\d\w])(?:\+?91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")
_AMOUNT_RE = re.compile(
    r"""(?ix)
    (?P<cur>₹|rs\.?|inr|\$|usd|€|eur)\s*(?P<num>\d{1,3}(?:,\d{2,3})+(?:\.\d{1,2})?|\d+(?:\.\d{1,2})?)
  | (?P<num2>\d{1,3}(?:,\d{2,3})+(?:\.\d{1,2})?|\d+(?:\.\d{1,2})?)\s*(?P<cur2>rs\.?|inr|rupees|usd|dollars)\b
    """
)
_REF_RE = re.compile(
    r"(?i)\b(?:utr|rrn|ref(?:erence)?|txn|transaction)\s*(?:no\.?|id|number|#)?\s*[:\-]?\s*([A-Z0-9]{8,22})\b"
)

_CURRENCY_CODES = {
    "₹": "INR", "rs": "INR", "rs.": "INR", "inr": "INR", "rupees": "INR",
    "$": "USD", "usd": "USD", "dollars": "USD",
    "€": "EUR", "eur": "EUR",
}


def normalize_text(text: str) -> str:
    """Canonicalize unicode, drop invisible characters and collapse whitespace."""
    text = unicodedata.normalize("NFKC", text).translate(_INVISIBLE)
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = [re.sub(r"[ \t\f\v]+", " ", line).strip() for line in text.split("\n")]
    return re.sub(r"\n{3,}", "\n\n", "\n".join(lines)).strip()


def refang(text: str) -> str:
    """Undo common URL defanging (``hxxp``, ``[.]``, ``(dot)``) used when sharing IOCs."""
    text = re.sub(r"(?i)\bhxxp(s?)", r"http\1", text)
    text = re.sub(r"(?i)\[(?:\.|dot)\]|\((?:\.|dot)\)|\{\.\}", ".", text)
    return re.sub(r"(?i)\[:\]|\[://\]", lambda m: m.group(0)[1:-1], text)


def parse_amount(value: str) -> float | None:
    try:
        return float(value.replace(",", ""))
    except ValueError:
        return None


def _dedupe(items):
    return list(dict.fromkeys(items))


def extract_entities(text: str) -> Entities:
    """Pull URLs, contacts, payment handles, amounts and reference numbers from text."""
    text = refang(text)

    urls = _dedupe(m.rstrip(".,;:!?") for m in _URL_RE.findall(text))
    emails = _dedupe(m.lower() for m in _EMAIL_RE.findall(text))
    upi_ids = _dedupe(
        m.lower() for m in _UPI_RE.findall(text) if m.lower() not in emails
    )

    phones = []
    for match in _PHONE_RE.findall(text):
        digits = re.sub(r"\D", "", match)[-10:]
        phones.append("+91" + digits)

    amounts = []
    for m in _AMOUNT_RE.finditer(text):
        raw_cur = (m.group("cur") or m.group("cur2")).lower()
        value = parse_amount(m.group("num") or m.group("num2"))
        if value is not None:
            amounts.append(
                {"value": value, "currency": _CURRENCY_CODES.get(raw_cur, raw_cur.upper()),
                 "raw": m.group(0).strip()}
            )

    refs = [r for r in _REF_RE.findall(text) if any(ch.isdigit() for ch in r)]

    return Entities(
        urls=urls,
        emails=emails,
        phone_numbers=_dedupe(phones),
        upi_ids=upi_ids,
        amounts=amounts,
        reference_numbers=_dedupe(refs),
    )
