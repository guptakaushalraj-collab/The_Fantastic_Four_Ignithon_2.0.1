"""Module 1 — Evidence Ingestion.

Normalizes raw fraud evidence (messages, screenshots, transactions, URLs)
and tags each item with its evidence type.

    >>> from fraud_evidence.ingestion import EvidenceIngestor
    >>> ev = EvidenceIngestor().ingest("hxxps://sbi-kyc-update[.]xyz/login")
    >>> ev.evidence_type.value, ev.normalized_text
    ('url', 'https://sbi-kyc-update.xyz/login')
"""

from .models import Entities, Evidence, EvidenceType
from .ocr import OCREngine, OCRResult, OCRUnavailableError, TesseractOCR
from .pipeline import EvidenceIngestor

__all__ = [
    "Entities",
    "Evidence",
    "EvidenceIngestor",
    "EvidenceType",
    "OCREngine",
    "OCRResult",
    "OCRUnavailableError",
    "TesseractOCR",
]
