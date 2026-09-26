"""Module 5 core: replace personal and financial identifiers with ``[REDACTED]``.

Works on any structured evidence: Module 2 records or case files, a Module 3
timeline or a Module 4 report. Sensitive values are found two ways:

* Structured fields: a party whose ``identifier_type`` is sensitive (phone,
  email, UPI ID, account) and the ``contacts`` lists. Every value found there
  is also removed wherever it appears in free text (message bodies, titles,
  statement narrations), even in forms the patterns below would miss.
* Patterns over every string: emails, UPI IDs, Indian phone numbers, card
  numbers (Luhn-checked), masked accounts (``XX1234``) and numbers after
  "A/c" or "account".

Transaction references (UTR/RRN) are kept: investigators and banks need them
to trace the money, and they identify a payment rather than a person.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from typing import Any, Callable

PLACEHOLDER = "[REDACTED]"
SENSITIVE_TYPES = ("account", "card", "phone", "email", "upi_id")

# Keys whose values are ids, hashes or times, never personal data.
_SKIP_KEYS = {
    "evidence_id", "content_hash", "schema_version", "transaction_id", "reference_numbers",
    "field_sources", "timestamp", "generated_at", "issue_id", "linked_evidence", "evidence_ids",
    "case_id", "time_precision",
}
_CONTACT_LISTS = {"phone_numbers": "phone", "emails": "email", "upi_ids": "upi_id"}

_EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]+@[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b", re.I)
# A trailing "." may end the sentence; "@ybl.com" would be an email instead.
_UPI_RE = re.compile(r"(?<![\w.-])[\w.-]{1,256}@[a-z]{2,64}(?![\w-]|\.\w)", re.I)
_PHONE_RE = re.compile(r"(?<![\d\w+])(?:\+?91[\s-]?|0)?[6-9]\d{4}[\s-]?\d{5}(?!\d)")
_CARD_RE = re.compile(r"(?<![\d\w])\d(?:[ -]?\d){12,18}(?![\d\w])")
_MASKED_ACCOUNT_RE = re.compile(r"(?<![\w*])[xX*]{2,}\d{2,6}(?!\w)")
_ACCOUNT_CONTEXT_RE = re.compile(
    r"(?i)\b(?:a/?c|acct|account)(?:\s*(?:no|number|num))?\.?\s*[:#-]?\s*"
    r"(?:ending(?:\s+(?:with|in))?\s*)?"
    r"(?P<number>[xX*]*\d(?:[\d\s-]{0,20}\d)?)"
)


def _luhn(digits: str) -> bool:
    total = 0
    for i, ch in enumerate(reversed(digits)):
        n = int(ch)
        if i % 2:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
    return total % 10 == 0


@dataclass
class RedactionResult:
    document: Any
    counts: dict[str, int] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return sum(self.counts.values())

    def summary(self) -> dict[str, Any]:
        return {"total": self.total, "by_type": dict(self.counts)}


class Redactor:
    """Replace sensitive identifiers in a JSON-like document.

    ``types`` limits what is redacted (default: all of ``SENSITIVE_TYPES``).
    The input is never modified; :meth:`redact` returns a redacted copy and
    how many values of each type were replaced.
    """

    def __init__(self, types: tuple[str, ...] | list[str] | set[str] = SENSITIVE_TYPES,
                 placeholder: str = PLACEHOLDER):
        unknown = set(types) - set(SENSITIVE_TYPES)
        if unknown:
            raise ValueError(f"unknown redaction type(s): {', '.join(sorted(unknown))}")
        self.types = set(types)
        self.placeholder = placeholder

    def redact(self, document: Any) -> RedactionResult:
        known: dict[str, str] = {}      # sensitive value -> type
        protected: set[str] = set()     # digits of transaction references
        self._collect(document, known, protected)

        counts = {t: 0 for t in SENSITIVE_TYPES if t in self.types}
        literal = self._literal_pattern(known)

        def text(value: str) -> str:
            return self._redact_text(value, literal, known, protected, counts)

        redacted = self._walk(copy.deepcopy(document), text, counts)
        return RedactionResult(redacted, {t: n for t, n in counts.items() if n})

    def redact_text(self, value: str) -> str:
        """Redact one free-text string using the patterns only."""
        return self._redact_text(value, None, {}, set(), {t: 0 for t in self.types})

    # ------------------------------------------------------------ collection

    def _collect(self, node: Any, known: dict[str, str], protected: set[str]) -> None:
        if isinstance(node, dict):
            if self._sensitive_party(node):
                known.setdefault(node["identifier"], node["identifier_type"])
                if isinstance(node.get("raw"), str) and node["raw"] != node.get("name"):
                    known.setdefault(self._raw_identifier(node["raw"]), node["identifier_type"])
            for key, value in node.items():
                if key in _CONTACT_LISTS and _CONTACT_LISTS[key] in self.types \
                        and isinstance(value, list):
                    for item in value:
                        if isinstance(item, str) and item:
                            known.setdefault(item, _CONTACT_LISTS[key])
                elif key in ("transaction_id", "reference_numbers"):
                    for ref in value if isinstance(value, list) else [value]:
                        digits = re.sub(r"\D", "", str(ref or ""))
                        if len(digits) >= 6:
                            protected.add(digits)
                else:
                    self._collect(value, known, protected)
        elif isinstance(node, list):
            for item in node:
                self._collect(item, known, protected)

    def _sensitive_party(self, node: dict) -> bool:
        return (node.get("identifier_type") in self.types and isinstance(node.get("identifier"), str)
                and bool(node["identifier"]))

    @staticmethod
    def _raw_identifier(raw: str) -> str:
        """The identifier as written in ``raw`` ("Name <id>" keeps only the id)."""
        m = re.match(r'^\s*"?[^"<]*?"?\s*<([^>]+)>\s*$', raw)
        return (m.group(1) if m else raw).strip()

    @staticmethod
    def _literal_pattern(known: dict[str, str]) -> re.Pattern | None:
        values = sorted((v for v in known if len(v) >= 4), key=len, reverse=True)
        if not values:
            return None
        return re.compile(r"(?<![\w@.+-])(?:" + "|".join(map(re.escape, values)) + r")(?![\w@-])",
                          re.I)

    # --------------------------------------------------------------- walking

    def _walk(self, node: Any, text: Callable[[str], str], counts: dict[str, int]) -> Any:
        if isinstance(node, dict):
            party = self._sensitive_party(node)
            for key, value in node.items():
                if key in _SKIP_KEYS:
                    continue
                if key in _CONTACT_LISTS and isinstance(value, list):
                    kind = _CONTACT_LISTS[key]
                    if kind in self.types:
                        counts[kind] += sum(bool(v) for v in value)
                        node[key] = [self.placeholder if v else v for v in value]
                    continue
                if party and key == "identifier":
                    counts[node["identifier_type"]] += 1
                    node[key] = self.placeholder
                elif party and key == "raw" and isinstance(value, str) and value != node.get("name"):
                    node[key] = text(value)
                    if node[key] == value:  # an identifier no pattern recognizes
                        counts[node["identifier_type"]] += 1
                        node[key] = self.placeholder
                else:
                    node[key] = self._walk(value, text, counts)
            return node
        if isinstance(node, list):
            return [self._walk(item, text, counts) for item in node]
        if isinstance(node, str):
            return text(node)
        return node

    def _redact_text(self, value: str, literal: re.Pattern | None, known: dict[str, str],
                     protected: set[str], counts: dict[str, int]) -> str:
        if not value:
            return value
        lowered = {k.lower(): t for k, t in known.items()}

        def sub(kind: str, check: Callable[[re.Match], bool] | None = None):
            def repl(m: re.Match) -> str:
                if check and not check(m):
                    return m.group(0)
                counts[kind] += 1
                return self.placeholder
            return repl

        def not_reference(m: re.Match) -> bool:
            digits = re.sub(r"\D", "", m.group(0))
            return not any(digits in ref for ref in protected)

        def card(m: re.Match) -> bool:
            digits = re.sub(r"\D", "", m.group(0))
            return 13 <= len(digits) <= 19 and _luhn(digits) and not_reference(m)

        if literal is not None:
            def known_repl(m: re.Match) -> str:
                counts[lowered[m.group(0).lower()]] += 1
                return self.placeholder
            value = literal.sub(known_repl, value)
        if "email" in self.types:
            value = _EMAIL_RE.sub(sub("email"), value)
        if "upi_id" in self.types:
            value = _UPI_RE.sub(sub("upi_id"), value)
        if "card" in self.types:
            value = _CARD_RE.sub(sub("card", card), value)
        if "account" in self.types:
            def account(m: re.Match) -> str:
                number = m.group("number")
                digits = re.sub(r"\D", "", number)
                if len(digits) < 3 or any(digits in ref for ref in protected):
                    return m.group(0)
                counts["account"] += 1
                return m.group(0)[: m.start("number") - m.start()] + self.placeholder
            value = _ACCOUNT_CONTEXT_RE.sub(account, value)
            value = _MASKED_ACCOUNT_RE.sub(sub("account"), value)
        if "phone" in self.types:
            value = _PHONE_RE.sub(sub("phone", not_reference), value)
        return value


def redact(document: Any, types=SENSITIVE_TYPES, placeholder: str = PLACEHOLDER) -> Any:
    """Return a redacted copy of ``document``."""
    return Redactor(types, placeholder).redact(document).document
