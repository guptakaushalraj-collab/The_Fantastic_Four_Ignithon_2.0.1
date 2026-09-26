"""Entry point for Module 1: turn raw fraud evidence into tagged, normalized records."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Iterable

from .models import Evidence, EvidenceType, content_hash
from .ocr import OCREngine, OCRUnavailableError, default_engine, sniff_image_mime
from .text import extract_entities, normalize_text, refang
from .transactions import (
    looks_like_transaction_text,
    normalize_record,
    parse_structured,
    parse_transaction_text,
)
from .urls import normalize_url

_LONE_URL_RE = re.compile(
    r"(?i)^(?:(?:https?|hxxps?)(?:://|\[://\])|www\.)\S+$"
    r"|^(?:[a-z0-9-]+(?:\.|\[\.\]))+[a-z]{2,}(?:/\S*)?$"
)
_TEXT_EXTENSIONS = {".txt", ".json", ".csv", ".tsv", ".eml", ".log", ".md", ""}


class EvidenceIngestor:
    """Normalizes and tags raw evidence.

    Accepted inputs:

    * ``bytes`` — image data (screenshot) or UTF-8 text
    * :class:`pathlib.Path` — a file on disk; images are OCR'd, others read as text
    * ``dict`` / ``list[dict]`` — structured transaction records
    * ``str`` — a message, a URL, a JSON/CSV transaction export, or a bank alert SMS

    The type is auto-detected unless ``evidence_type`` is passed explicitly.
    """

    def __init__(self, ocr_engine: OCREngine | None = None):
        self.ocr_engine = ocr_engine or default_engine()

    # ------------------------------------------------------------------ public

    def ingest(
        self,
        item: Any,
        evidence_type: EvidenceType | str | None = None,
        source: str = "direct",
        metadata: dict[str, Any] | None = None,
    ) -> Evidence:
        forced = EvidenceType(evidence_type) if evidence_type else None
        metadata = dict(metadata or {})

        if isinstance(item, Path):
            return self._ingest_path(item, forced, metadata)

        if isinstance(item, (bytes, bytearray)):
            item = bytes(item)
            mime = sniff_image_mime(item)
            if mime or forced is EvidenceType.SCREENSHOT:
                metadata.setdefault("mime_type", mime)
                return self._screenshot(item, source, metadata)
            try:
                item = item.decode("utf-8")
            except UnicodeDecodeError:
                item = item.decode("latin-1")
                metadata["decoding"] = "latin-1"

        if isinstance(item, (dict, list)):
            if forced not in (None, EvidenceType.TRANSACTION):
                item = json.dumps(item, ensure_ascii=False)
            else:
                return self._transaction(item, source, metadata)

        if not isinstance(item, str):
            raise TypeError(f"unsupported evidence input: {type(item).__name__}")

        kind = forced or self.detect_text_type(item)
        if kind is EvidenceType.URL:
            return self._url(item, source, metadata)
        if kind is EvidenceType.TRANSACTION:
            return self._transaction(item, source, metadata)
        if kind is EvidenceType.SCREENSHOT:
            raise ValueError("screenshot evidence must be supplied as image bytes or a file path")
        return self._message(item, source, metadata)

    def ingest_many(self, items: Iterable[Any], **kwargs) -> list[Evidence]:
        """Ingest a batch; items that fail are returned as warnings on a message record
        rather than aborting the whole case file."""
        results = []
        for item in items:
            try:
                results.append(self.ingest(item, **kwargs))
            except (TypeError, ValueError, OSError) as exc:
                text = str(item)[:500]
                results.append(Evidence(
                    evidence_type=EvidenceType.MESSAGE,
                    normalized_text=normalize_text(text),
                    source=kwargs.get("source", "direct"),
                    content_hash=content_hash(text),
                    warnings=[f"ingestion failed: {exc}"],
                ))
        return results

    @staticmethod
    def detect_text_type(text: str) -> EvidenceType:
        stripped = normalize_text(text)
        if _LONE_URL_RE.match(stripped):
            return EvidenceType.URL
        if parse_structured(stripped) is not None or looks_like_transaction_text(stripped):
            return EvidenceType.TRANSACTION
        return EvidenceType.MESSAGE

    # ----------------------------------------------------------------- helpers

    def _ingest_path(self, path: Path, forced, metadata) -> Evidence:
        data = path.read_bytes()
        metadata.update(filename=path.name, size_bytes=len(data))
        source = f"file:{path}"
        mime = sniff_image_mime(data)
        if mime or forced is EvidenceType.SCREENSHOT:
            metadata["mime_type"] = mime
            return self._screenshot(data, source, metadata)
        if path.suffix.lower() not in _TEXT_EXTENSIONS:
            metadata["unrecognized_extension"] = path.suffix
        return self.ingest(data, evidence_type=forced, source=source, metadata=metadata)

    def _message(self, text: str, source: str, metadata: dict) -> Evidence:
        normalized = normalize_text(text)
        entities = extract_entities(normalized)
        return Evidence(
            evidence_type=EvidenceType.MESSAGE,
            normalized_text=normalized,
            source=source,
            content_hash=content_hash(text),
            structured={
                "char_count": len(normalized),
                "line_count": normalized.count("\n") + 1 if normalized else 0,
                "linked_urls": [normalize_url(u) for u in entities.urls],
            },
            entities=entities,
            metadata=metadata,
        )

    def _url(self, text: str, source: str, metadata: dict) -> Evidence:
        info = normalize_url(text)
        warnings = [] if info["host"] else ["could not determine host"]
        return Evidence(
            evidence_type=EvidenceType.URL,
            normalized_text=info["canonical"],
            source=source,
            content_hash=content_hash(text),
            structured=info,
            entities=extract_entities(info["canonical"]),
            metadata=metadata,
            warnings=warnings,
        )

    def _transaction(self, item: Any, source: str, metadata: dict) -> Evidence:
        raw = item if isinstance(item, str) else json.dumps(item, sort_keys=True, default=str)
        warnings: list[str] = []

        records = parse_structured(item)
        if records is not None:
            normalized_records = []
            for record in records:
                rec, rec_warnings = normalize_record(record)
                normalized_records.append(rec)
                warnings.extend(rec_warnings)
            metadata["format"] = "structured"
        else:
            normalized_records = [parse_transaction_text(item)]
            metadata["format"] = "text"
            if normalized_records[0]["amount"] is None:
                warnings.append("no amount found in transaction text")

        summary = "\n".join(_summarize(r) for r in normalized_records)
        entity_text = normalize_text(item) if records is None else "\n".join(
            _flatten_values(r) for r in normalized_records
        )
        return Evidence(
            evidence_type=EvidenceType.TRANSACTION,
            normalized_text=summary,
            source=source,
            content_hash=content_hash(raw),
            structured={"records": normalized_records, "record_count": len(normalized_records)},
            entities=extract_entities(entity_text),
            metadata=metadata,
            warnings=warnings,
        )

    def _screenshot(self, data: bytes, source: str, metadata: dict) -> Evidence:
        warnings: list[str] = []
        structured: dict[str, Any] = {}
        text = ""
        try:
            result = self.ocr_engine.extract_text(data)
            text = normalize_text(result.text)
            structured.update(
                ocr_engine=result.engine, ocr_confidence=result.confidence, **result.details
            )
            if not text:
                warnings.append("OCR produced no text")
            elif result.confidence is not None and result.confidence < 0.6:
                warnings.append(f"low OCR confidence ({result.confidence:.2f})")
        except OCRUnavailableError as exc:
            warnings.append(f"OCR unavailable: {exc}")

        if text:
            # Screenshots keep their tag, but we record what the captured text looks
            # like (chat vs. payment receipt) so later modules can route it.
            structured["content_type"] = self.detect_text_type(text).value
            if structured["content_type"] == EvidenceType.TRANSACTION.value:
                structured["transaction"] = parse_transaction_text(text)

        return Evidence(
            evidence_type=EvidenceType.SCREENSHOT,
            normalized_text=text,
            source=source,
            content_hash=content_hash(data),
            structured=structured,
            entities=extract_entities(text),
            metadata=metadata,
            warnings=warnings,
        )


def _flatten_values(record: dict[str, Any]) -> str:
    values = []
    for value in record.values():
        values.append(_flatten_values(value) if isinstance(value, dict) else str(value))
    return " ".join(v for v in values if v and v != "None")


def _summarize(record: dict[str, Any]) -> str:
    parts = [
        f"{key}={record[key]}"
        for key in ("transaction_id", "timestamp", "direction", "amount", "currency",
                    "payment_method", "sender", "receiver", "status")
        if record.get(key) is not None
    ]
    return "; ".join(parts) or refang(str(record.get("description") or ""))
