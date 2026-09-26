"""Data models shared by the evidence ingestion stage."""

from __future__ import annotations

import hashlib
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class EvidenceType(str, Enum):
    """The kind of evidence a submitted item represents."""

    MESSAGE = "message"
    URL = "url"
    TRANSACTION = "transaction"
    SCREENSHOT = "screenshot"


@dataclass
class Entities:
    """Structured indicators pulled out of an item's normalized text."""

    urls: list[str] = field(default_factory=list)
    emails: list[str] = field(default_factory=list)
    phone_numbers: list[str] = field(default_factory=list)
    upi_ids: list[str] = field(default_factory=list)
    amounts: list[dict[str, Any]] = field(default_factory=list)
    reference_numbers: list[str] = field(default_factory=list)

    def is_empty(self) -> bool:
        return not any(asdict(self).values())


@dataclass
class Evidence:
    """A single piece of fraud evidence in a normalized, tagged form.

    ``normalized_text`` is always populated (possibly empty) so that
    downstream modules can treat every evidence type uniformly, while
    ``structured`` carries type-specific fields (parsed URL parts,
    canonical transaction records, OCR details, ...).
    """

    evidence_type: EvidenceType
    normalized_text: str
    source: str
    content_hash: str
    structured: dict[str, Any] = field(default_factory=dict)
    entities: Entities = field(default_factory=Entities)
    metadata: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    evidence_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    ingested_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["evidence_type"] = self.evidence_type.value
        return data


def content_hash(raw: bytes | str) -> str:
    """SHA-256 of the raw submission, used for de-duplication and chain of custody."""
    if isinstance(raw, str):
        raw = raw.encode("utf-8")
    return hashlib.sha256(raw).hexdigest()
