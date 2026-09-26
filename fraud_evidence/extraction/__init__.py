"""Module 2 — Information Extraction.

Takes normalized evidence from Module 1 and extracts the key fields
(sender, receiver, timestamp, transaction amount, URL reputation, message
content) into structured JSON records described by ``schema.json``.

    >>> from fraud_evidence.ingestion import EvidenceIngestor
    >>> from fraud_evidence.extraction import InformationExtractor
    >>> ev = EvidenceIngestor().ingest("hxxps://sbi-kyc-update[.]xyz/login")
    >>> InformationExtractor().extract(ev)["urls"][0]["verdict"]
    'malicious'
"""

from .extractor import SCHEMA_VERSION, InformationExtractor, make_party, parse_datetime
from .reputation import ListProvider, ReputationProvider, Signal, URLReputation, URLReputationScorer
from .store import JsonEvidenceStore, load_schema

__all__ = [
    "SCHEMA_VERSION",
    "InformationExtractor",
    "JsonEvidenceStore",
    "ListProvider",
    "ReputationProvider",
    "Signal",
    "URLReputation",
    "URLReputationScorer",
    "load_schema",
    "make_party",
    "parse_datetime",
]
