"""Module 5 — Redaction.

Finds sensitive data in structured evidence (account and card numbers, phone
numbers, email addresses, UPI IDs) and replaces it with ``[REDACTED]``, so a
case can be shared without exposing the victim's or anyone else's details.
Transaction references are kept for tracing the money.
"""

from .redactor import PLACEHOLDER, SENSITIVE_TYPES, RedactionResult, Redactor, redact

__all__ = ["PLACEHOLDER", "SENSITIVE_TYPES", "RedactionResult", "Redactor", "redact"]
