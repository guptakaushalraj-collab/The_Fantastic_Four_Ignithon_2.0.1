"""Persist extracted records as structured JSON."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from .extractor import SCHEMA_VERSION

SCHEMA_PATH = Path(__file__).with_name("schema.json")


class JsonEvidenceStore:
    """A case file on disk: one JSON document holding every extracted record.

    Records are keyed by ``evidence_id``, so re-saving a record replaces it
    rather than duplicating it. Writes are atomic (temp file + rename) so an
    interrupted run never leaves a half-written case file.
    """

    def __init__(self, path: str | os.PathLike, case_id: str | None = None):
        self.path = Path(path)
        self.case_id = case_id
        self._records: dict[str, dict[str, Any]] = {}
        if self.path.exists():
            doc = json.loads(self.path.read_text(encoding="utf-8"))
            self.case_id = case_id or doc.get("case_id")
            self._records = {r["evidence_id"]: r for r in doc.get("records", [])}

    def add(self, record: dict[str, Any]) -> None:
        self._records[record["evidence_id"]] = record

    def add_many(self, records: Iterable[dict[str, Any]]) -> None:
        for record in records:
            self.add(record)

    def get(self, evidence_id: str) -> dict[str, Any] | None:
        return self._records.get(evidence_id)

    @property
    def records(self) -> list[dict[str, Any]]:
        return list(self._records.values())

    def to_document(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "case_id": self.case_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "record_count": len(self._records),
            "records": self.records,
        }

    def save(self) -> Path:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(self.to_document(), fh, ensure_ascii=False, indent=2, default=str)
            os.replace(tmp, self.path)
        except BaseException:
            os.unlink(tmp)
            raise
        return self.path


def load_schema() -> dict[str, Any]:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
