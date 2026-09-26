"""Fraud evidence pipeline: ingestion, extraction, timeline, flags, redaction and report."""

import sys

if sys.version_info < (3, 10):
    raise SystemExit(
        f"fraud_evidence needs Python 3.10 or newer; this is Python "
        f"{sys.version_info.major}.{sys.version_info.minor}. Install a newer Python from python.org."
    )
